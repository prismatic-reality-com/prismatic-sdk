defmodule PrismaticSDK.CircuitBreaker do
  @moduledoc """
  Circuit breaker implementation for the Prismatic SDK.

  Provides fault tolerance by preventing calls to failing services:
  - **Closed** - Normal operation, requests pass through
  - **Open** - Service is failing, requests are blocked
  - **Half-Open** - Testing if service has recovered

  ## Usage

      # Execute with circuit breaker protection
      result = PrismaticSDK.CircuitBreaker.call("api_service", fn ->
        make_api_call()
      end)

  """

  use GenServer
  require Logger

  @type state :: :closed | :open | :half_open
  @type config :: %{
    failure_threshold: pos_integer(),
    recovery_timeout: pos_integer(),
    success_threshold: pos_integer(),
    timeout: pos_integer()
  }

  defstruct [
    :name,
    :config,
    :state,
    :failure_count,
    :success_count,
    :last_failure_time,
    :next_attempt_time
  ]

  # Default configuration
  @default_config %{
    failure_threshold: 5,
    recovery_timeout: 60_000,
    success_threshold: 3,
    timeout: 30_000
  }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Executes a function with circuit breaker protection.

  ## Examples

      result = PrismaticSDK.CircuitBreaker.call("api", fn ->
        HTTPClient.get("https://api.example.com/data")
      end)

      case result do
        {:ok, data} -> process_data(data)
        {:error, :circuit_open} -> use_cached_data()
        {:error, reason} -> handle_error(reason)
      end

  """
  @spec call(String.t(), function()) :: {:ok, term()} | {:error, term()}
  def call(name, fun) when is_function(fun, 0) do
    GenServer.call(via_tuple(name), {:call, fun})
  end

  @doc """
  Gets the current state of a circuit breaker.

  ## Examples

      state = PrismaticSDK.CircuitBreaker.status("api")
      # => :closed | :open | :half_open

  """
  @spec status(String.t()) :: state()
  def status(name) do
    GenServer.call(via_tuple(name), :status)
  end

  @doc """
  Records a successful operation (for external use).

  ## Examples

      :ok = PrismaticSDK.CircuitBreaker.record_success("api")

  """
  @spec record_success(String.t()) :: :ok
  def record_success(name) do
    GenServer.cast(via_tuple(name), :record_success)
  end

  @doc """
  Records a failed operation (for external use).

  ## Examples

      :ok = PrismaticSDK.CircuitBreaker.record_failure("api", :timeout)

  """
  @spec record_failure(String.t(), term()) :: :ok
  def record_failure(name, reason) do
    GenServer.cast(via_tuple(name), {:record_failure, reason})
  end

  @doc """
  Resets a circuit breaker to closed state.

  ## Examples

      :ok = PrismaticSDK.CircuitBreaker.reset("api")

  """
  @spec reset(String.t()) :: :ok
  def reset(name) do
    GenServer.call(via_tuple(name), :reset)
  end

  @doc """
  Gets detailed status information.

  ## Examples

      info = PrismaticSDK.CircuitBreaker.info("api")
      # => %{
      #   state: :closed,
      #   failure_count: 0,
      #   success_count: 15,
      #   last_failure_time: nil,
      #   config: %{...}
      # }

  """
  @spec info(String.t()) :: map()
  def info(name) do
    GenServer.call(via_tuple(name), :info)
  end

  @doc """
  Returns health status of all circuit breakers.

  ## Examples

      {:ok, health} = PrismaticSDK.CircuitBreaker.health_check()

  """
  @spec health_check() :: {:ok, map()}
  def health_check do
    breakers = Registry.select(PrismaticSDK.CircuitBreaker.Registry, [{{:"$1", :"$2", :"$3"}, [], [:"$1"]}])

    breaker_states = Enum.map(breakers, fn {name, _pid, _} ->
      %{name: name, state: status(name)}
    end)

    open_breakers = Enum.count(breaker_states, fn %{state: state} -> state == :open end)

    health = %{
      status: if(open_breakers == 0, do: :healthy, else: :degraded),
      total_breakers: length(breaker_states),
      open_breakers: open_breakers,
      breaker_states: breaker_states
    }

    {:ok, health}
  end

  # ============================================================================
  # Registry
  # ============================================================================

  defmodule Registry do
    @moduledoc """
    Registry for circuit breaker processes.
    """

    def start_link(_opts \\ []) do
      Registry.start_link(keys: :unique, name: __MODULE__)
    end

    def via_tuple(name) do
      {:via, Registry, {__MODULE__, name}}
    end
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  def start_link(name, config \\ %{}) do
    full_config = Map.merge(@default_config, config)

    initial_state = %__MODULE__{
      name: name,
      config: full_config,
      state: :closed,
      failure_count: 0,
      success_count: 0,
      last_failure_time: nil,
      next_attempt_time: nil
    }

    GenServer.start_link(__MODULE__, initial_state, name: via_tuple(name))
  end

  @impl true
  def init(state) do
    {:ok, state}
  end

  @impl true
  def handle_call({:call, fun}, _from, state) do
    case state.state do
      :closed ->
        execute_call(fun, state)

      :open ->
        if can_attempt_call?(state) do
          # Transition to half-open and attempt call
          new_state = %{state | state: :half_open, success_count: 0}
          execute_call(fun, new_state)
        else
          {:reply, {:error, :circuit_open}, state}
        end

      :half_open ->
        execute_call(fun, state)
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply, state.state, state}
  end

  @impl true
  def handle_call(:reset, _from, state) do
    new_state = %{state |
      state: :closed,
      failure_count: 0,
      success_count: 0,
      last_failure_time: nil,
      next_attempt_time: nil
    }
    {:reply, :ok, new_state}
  end

  @impl true
  def handle_call(:info, _from, state) do
    info = %{
      state: state.state,
      failure_count: state.failure_count,
      success_count: state.success_count,
      last_failure_time: state.last_failure_time,
      next_attempt_time: state.next_attempt_time,
      config: state.config
    }
    {:reply, info, state}
  end

  @impl true
  def handle_cast(:record_success, state) do
    new_state = handle_success(state)
    {:noreply, new_state}
  end

  @impl true
  def handle_cast({:record_failure, reason}, state) do
    new_state = handle_failure(state, reason)
    {:noreply, new_state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp execute_call(fun, state) do
    try do
      result = fun.()
      new_state = handle_success(state)
      {:reply, {:ok, result}, new_state}
    rescue
      error ->
        new_state = handle_failure(state, error)
        {:reply, {:error, error}, new_state}
    catch
      :exit, reason ->
        new_state = handle_failure(state, reason)
        {:reply, {:error, reason}, new_state}
    end
  end

  defp handle_success(state) do
    case state.state do
      :closed ->
        %{state | success_count: state.success_count + 1}

      :half_open ->
        new_success_count = state.success_count + 1
        if new_success_count >= state.config.success_threshold do
          # Transition back to closed
          Logger.info("Circuit breaker #{state.name} transitioned to CLOSED")
          %{state |
            state: :closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: nil,
            next_attempt_time: nil
          }
        else
          %{state | success_count: new_success_count}
        end

      :open ->
        # Shouldn't happen, but handle gracefully
        state
    end
  end

  defp handle_failure(state, reason) do
    now = :erlang.monotonic_time(:millisecond)
    new_failure_count = state.failure_count + 1

    Logger.warning("Circuit breaker #{state.name} recorded failure: #{inspect(reason)}")

    case state.state do
      :closed ->
        if new_failure_count >= state.config.failure_threshold do
          # Transition to open
          next_attempt = now + state.config.recovery_timeout
          Logger.warning("Circuit breaker #{state.name} transitioned to OPEN")

          %{state |
            state: :open,
            failure_count: new_failure_count,
            last_failure_time: now,
            next_attempt_time: next_attempt
          }
        else
          %{state |
            failure_count: new_failure_count,
            last_failure_time: now
          }
        end

      :half_open ->
        # Failed during half-open, go back to open
        next_attempt = now + state.config.recovery_timeout
        Logger.warning("Circuit breaker #{state.name} transitioned back to OPEN")

        %{state |
          state: :open,
          failure_count: new_failure_count,
          success_count: 0,
          last_failure_time: now,
          next_attempt_time: next_attempt
        }

      :open ->
        # Already open, just update failure info
        next_attempt = now + state.config.recovery_timeout
        %{state |
          failure_count: new_failure_count,
          last_failure_time: now,
          next_attempt_time: next_attempt
        }
    end
  end

  defp can_attempt_call?(state) do
    case state.next_attempt_time do
      nil -> true
      next_attempt -> :erlang.monotonic_time(:millisecond) >= next_attempt
    end
  end

  defp via_tuple(name) do
    Registry.via_tuple(name)
  end

  # ============================================================================
  # Utility Functions
  # ============================================================================

  @doc """
  Ensures a circuit breaker exists for the given name.

  ## Examples

      :ok = PrismaticSDK.CircuitBreaker.ensure_breaker("api")

  """
  @spec ensure_breaker(String.t(), config()) :: :ok
  def ensure_breaker(name, config \\ %{}) do
    case Elixir.Registry.lookup(PrismaticSDK.CircuitBreaker.Registry, name) do
      [] ->
        # Start new circuit breaker
        DynamicSupervisor.start_child(
          PrismaticSDK.CircuitBreaker.Supervisor,
          {__MODULE__, [name, config]}
        )
        :ok

      [{_pid, _}] ->
        # Already exists
        :ok
    end
  end

  @doc """
  Lists all active circuit breakers.

  ## Examples

      breakers = PrismaticSDK.CircuitBreaker.list_breakers()

  """
  @spec list_breakers() :: [String.t()]
  def list_breakers do
    Elixir.Registry.select(PrismaticSDK.CircuitBreaker.Registry, [{{:"$1", :"$2", :"$3"}, [], [:"$1"]}])
    |> Enum.map(fn {name, _pid, _} -> name end)
  end

  # ============================================================================
  # Circuit Breaker Supervisor
  # ============================================================================

  defmodule Supervisor do
    @moduledoc """
    Dynamic supervisor for circuit breaker processes.
    """

    use DynamicSupervisor

    def start_link(opts) do
      DynamicSupervisor.start_link(__MODULE__, opts, name: __MODULE__)
    end

    @impl true
    def init(_opts) do
      DynamicSupervisor.init(strategy: :one_for_one)
    end
  end
end