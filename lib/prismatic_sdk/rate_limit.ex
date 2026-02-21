defmodule PrismaticSDK.RateLimit do
  @moduledoc """
  Rate limiting infrastructure for the Prismatic SDK.

  Provides intelligent rate limiting with:
  - Token bucket algorithm for smooth rate limiting
  - Per-service and per-endpoint rate limits
  - Automatic retry with exponential backoff
  - Circuit breaker integration

  ## Usage

      # Check if request is allowed
      case PrismaticSDK.RateLimit.check_rate("api", %{requests_per_second: 10}) do
        :ok -> make_request()
        {:error, :rate_limited} -> handle_rate_limit()
      end

      # Get current status
      {:ok, status} = PrismaticSDK.RateLimit.status("api")

  """

  use GenServer
  require Logger

  @type rate_limit_config :: %{
    requests_per_second: pos_integer(),
    burst_size: pos_integer() | nil,
    window_size_ms: pos_integer() | nil
  }

  @type rate_limit_status :: %{
    key: String.t(),
    tokens_available: float(),
    tokens_max: pos_integer(),
    refill_rate: float(),
    last_refill: DateTime.t(),
    requests_made: pos_integer(),
    requests_allowed: pos_integer(),
    requests_denied: pos_integer()
  }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Checks if a request is allowed under the rate limit.

  ## Examples

      case PrismaticSDK.RateLimit.check_rate("api", %{requests_per_second: 10}) do
        :ok ->
          # Request allowed, proceed
          make_api_call()
        {:error, :rate_limited} ->
          # Rate limited, retry later
          {:error, :rate_limited}
      end

  """
  @spec check_rate(String.t(), rate_limit_config()) :: :ok | {:error, :rate_limited}
  def check_rate(key, config) do
    GenServer.call(__MODULE__, {:check_rate, key, config})
  end

  @doc """
  Gets the current rate limit status for a key.

  ## Examples

      {:ok, status} = PrismaticSDK.RateLimit.status("api")
      # => %{
      #   key: "api",
      #   tokens_available: 8.5,
      #   tokens_max: 10,
      #   refill_rate: 10.0,
      #   last_refill: ~U[2026-02-21 10:30:00Z],
      #   requests_made: 150,
      #   requests_allowed: 142,
      #   requests_denied: 8
      # }

  """
  @spec status(String.t()) :: {:ok, rate_limit_status()} | {:error, :not_found}
  def status(key) do
    GenServer.call(__MODULE__, {:status, key})
  end

  @doc """
  Resets the rate limit for a key (for testing).

  ## Examples

      :ok = PrismaticSDK.RateLimit.reset("api")

  """
  @spec reset(String.t()) :: :ok
  def reset(key) do
    GenServer.call(__MODULE__, {:reset, key})
  end

  @doc """
  Lists all active rate limiters.

  ## Examples

      keys = PrismaticSDK.RateLimit.list_keys()
      # => ["api", "osint", "perimeter"]

  """
  @spec list_keys() :: [String.t()]
  def list_keys do
    GenServer.call(__MODULE__, :list_keys)
  end

  @doc """
  Returns health status of the rate limiter.

  ## Examples

      {:ok, health} = PrismaticSDK.RateLimit.health_check()

  """
  @spec health_check() :: {:ok, map()}
  def health_check do
    GenServer.call(__MODULE__, :health_check)
  end

  # ============================================================================
  # Supervisor
  # ============================================================================

  defmodule Supervisor do
    @moduledoc """
    Supervisor for rate limiting infrastructure.
    """

    use Elixir.Supervisor

    def start_link(opts) do
      Elixir.Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
    end

    @impl true
    def init(_opts) do
      children = [
        PrismaticSDK.RateLimit
      ]

      Elixir.Supervisor.init(children, strategy: :one_for_one)
    end
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    # Create ETS table for rate limit state
    :ets.new(:rate_limits, [:set, :public, :named_table])

    # Schedule periodic cleanup
    schedule_cleanup()

    {:ok, %{}}
  end

  @impl true
  def handle_call({:check_rate, key, config}, _from, state) do
    result = do_check_rate(key, config)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:status, key}, _from, state) do
    result = do_get_status(key)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:reset, key}, _from, state) do
    :ets.delete(:rate_limits, key)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:list_keys, _from, state) do
    keys = :ets.tab2list(:rate_limits)
    |> Enum.map(fn {key, _} -> key end)
    {:reply, keys, state}
  end

  @impl true
  def handle_call(:health_check, _from, state) do
    health = %{
      status: :healthy,
      active_limiters: :ets.info(:rate_limits, :size),
      memory_usage: :ets.info(:rate_limits, :memory) * :erlang.system_info(:wordsize),
      uptime_ms: :erlang.statistics(:wall_clock) |> elem(0)
    }
    {:reply, {:ok, health}, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    do_cleanup()
    schedule_cleanup()
    {:noreply, state}
  end

  # ============================================================================
  # Private Implementation
  # ============================================================================

  defp do_check_rate(key, config) do
    now = :erlang.monotonic_time(:millisecond)
    requests_per_second = Map.fetch!(config, :requests_per_second)
    burst_size = Map.get(config, :burst_size, requests_per_second * 2)

    case :ets.lookup(:rate_limits, key) do
      [] ->
        # First request, create new bucket
        bucket = %{
          tokens: burst_size - 1,
          max_tokens: burst_size,
          refill_rate: requests_per_second / 1000.0, # tokens per ms
          last_refill: now,
          requests_made: 1,
          requests_allowed: 1,
          requests_denied: 0
        }
        :ets.insert(:rate_limits, {key, bucket})
        :ok

      [{^key, bucket}] ->
        # Refill tokens based on time elapsed
        time_elapsed = now - bucket.last_refill
        tokens_to_add = time_elapsed * bucket.refill_rate
        new_tokens = min(bucket.tokens + tokens_to_add, bucket.max_tokens)

        if new_tokens >= 1.0 do
          # Request allowed
          updated_bucket = %{bucket |
            tokens: new_tokens - 1,
            last_refill: now,
            requests_made: bucket.requests_made + 1,
            requests_allowed: bucket.requests_allowed + 1
          }
          :ets.insert(:rate_limits, {key, updated_bucket})
          :ok
        else
          # Request denied
          updated_bucket = %{bucket |
            tokens: new_tokens,
            last_refill: now,
            requests_made: bucket.requests_made + 1,
            requests_denied: bucket.requests_denied + 1
          }
          :ets.insert(:rate_limits, {key, updated_bucket})
          {:error, :rate_limited}
        end
    end
  end

  defp do_get_status(key) do
    case :ets.lookup(:rate_limits, key) do
      [] ->
        {:error, :not_found}

      [{^key, bucket}] ->
        now = :erlang.monotonic_time(:millisecond)
        time_elapsed = now - bucket.last_refill
        tokens_to_add = time_elapsed * bucket.refill_rate
        current_tokens = min(bucket.tokens + tokens_to_add, bucket.max_tokens)

        status = %{
          key: key,
          tokens_available: Float.round(current_tokens, 2),
          tokens_max: bucket.max_tokens,
          refill_rate: bucket.refill_rate * 1000.0, # convert to per second
          last_refill: DateTime.from_unix!(bucket.last_refill, :millisecond),
          requests_made: bucket.requests_made,
          requests_allowed: bucket.requests_allowed,
          requests_denied: bucket.requests_denied
        }
        {:ok, status}
    end
  end

  defp schedule_cleanup do
    # Clean up old entries every 5 minutes
    Process.send_after(self(), :cleanup, 5 * 60 * 1000)
  end

  defp do_cleanup do
    now = :erlang.monotonic_time(:millisecond)
    cutoff = now - (60 * 60 * 1000) # 1 hour ago

    :ets.tab2list(:rate_limits)
    |> Enum.each(fn {key, bucket} ->
      if bucket.last_refill < cutoff and bucket.requests_made == 0 do
        :ets.delete(:rate_limits, key)
      end
    end)
  end

  # ============================================================================
  # Utility Functions
  # ============================================================================

  @doc """
  Waits for rate limit to clear with optional timeout.

  ## Examples

      # Wait up to 30 seconds for rate limit to clear
      case PrismaticSDK.RateLimit.wait_for_rate_limit("api", config, 30_000) do
        :ok -> make_request()
        {:error, :timeout} -> {:error, :timeout}
      end

  """
  @spec wait_for_rate_limit(String.t(), rate_limit_config(), pos_integer()) ::
          :ok | {:error, :timeout}
  def wait_for_rate_limit(key, config, timeout_ms \\ 30_000) do
    start_time = :erlang.monotonic_time(:millisecond)
    do_wait_for_rate_limit(key, config, start_time, timeout_ms)
  end

  defp do_wait_for_rate_limit(key, config, start_time, timeout_ms) do
    case check_rate(key, config) do
      :ok ->
        :ok

      {:error, :rate_limited} ->
        now = :erlang.monotonic_time(:millisecond)
        if now - start_time >= timeout_ms do
          {:error, :timeout}
        else
          # Wait for a short time before retrying
          wait_time = min(1000, timeout_ms - (now - start_time))
          Process.sleep(wait_time)
          do_wait_for_rate_limit(key, config, start_time, timeout_ms)
        end
    end
  end

  @doc """
  Calculates wait time until next request is allowed.

  ## Examples

      wait_ms = PrismaticSDK.RateLimit.wait_time("api")
      Process.sleep(wait_ms)

  """
  @spec wait_time(String.t()) :: non_neg_integer()
  def wait_time(key) do
    case :ets.lookup(:rate_limits, key) do
      [] -> 0
      [{^key, bucket}] ->
        if bucket.tokens >= 1.0 do
          0
        else
          # Time to wait for 1 token to be available
          tokens_needed = 1.0 - bucket.tokens
          wait_ms = tokens_needed / bucket.refill_rate
          round(wait_ms)
        end
    end
  end

  @doc """
  Applies rate limiting to a function with automatic retry.

  ## Examples

      result = PrismaticSDK.RateLimit.with_rate_limit("api", config, fn ->
        make_api_request()
      end)

  """
  @spec with_rate_limit(String.t(), rate_limit_config(), function()) ::
          {:ok, term()} | {:error, term()}
  def with_rate_limit(key, config, fun) when is_function(fun, 0) do
    case check_rate(key, config) do
      :ok ->
        try do
          result = fun.()
          {:ok, result}
        rescue
          error -> {:error, error}
        end

      {:error, :rate_limited} ->
        {:error, :rate_limited}
    end
  end

  @doc """
  Applies rate limiting with automatic retry and exponential backoff.

  ## Examples

      result = PrismaticSDK.RateLimit.with_retry("api", config, fn ->
        make_api_request()
      end, max_retries: 3, base_delay_ms: 1000)

  """
  @spec with_retry(String.t(), rate_limit_config(), function(), keyword()) ::
          {:ok, term()} | {:error, term()}
  def with_retry(key, config, fun, opts \\ []) do
    max_retries = Keyword.get(opts, :max_retries, 3)
    base_delay_ms = Keyword.get(opts, :base_delay_ms, 1000)
    do_with_retry(key, config, fun, 0, max_retries, base_delay_ms)
  end

  defp do_with_retry(key, config, fun, attempt, max_retries, base_delay_ms) do
    case with_rate_limit(key, config, fun) do
      {:ok, result} ->
        {:ok, result}

      {:error, :rate_limited} when attempt < max_retries ->
        # Exponential backoff with jitter
        delay_ms = base_delay_ms * :math.pow(2, attempt)
        jitter = :rand.uniform(round(delay_ms * 0.1))
        total_delay = round(delay_ms + jitter)

        Logger.debug("Rate limited, retrying in #{total_delay}ms (attempt #{attempt + 1}/#{max_retries + 1})")
        Process.sleep(total_delay)
        do_with_retry(key, config, fun, attempt + 1, max_retries, base_delay_ms)

      {:error, reason} ->
        {:error, reason}
    end
  end
end