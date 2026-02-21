defmodule PrismaticSDK.Telemetry do
  @moduledoc """
  Telemetry instrumentation for the Prismatic SDK.

  Provides comprehensive metrics and monitoring for:
  - HTTP requests and responses
  - WebSocket connections and messages
  - Rate limiting events
  - Circuit breaker state changes
  - Authentication events

  ## Usage

      # Subscribe to events
      :telemetry.attach("my_handler", [:prismatic_sdk, :client, :request], fn name, measurements, metadata, config ->
        handle_request_event(name, measurements, metadata, config)
      end, nil)

      # Get current metrics
      {:ok, metrics} = PrismaticSDK.Telemetry.get_metrics()

  """

  use GenServer
  require Logger

  @events [
    # HTTP Client events
    [:prismatic_sdk, :client, :request],
    [:prismatic_sdk, :client, :request, :start],
    [:prismatic_sdk, :client, :request, :stop],
    [:prismatic_sdk, :client, :request, :exception],

    # Authentication events
    [:prismatic_sdk, :auth, :login],
    [:prismatic_sdk, :auth, :token_refresh],
    [:prismatic_sdk, :auth, :logout],

    # Rate limiting events
    [:prismatic_sdk, :rate_limit, :check],
    [:prismatic_sdk, :rate_limit, :allowed],
    [:prismatic_sdk, :rate_limit, :denied],

    # Circuit breaker events
    [:prismatic_sdk, :circuit_breaker, :call],
    [:prismatic_sdk, :circuit_breaker, :state_change],

    # WebSocket events
    [:prismatic_sdk, :websocket, :connect],
    [:prismatic_sdk, :websocket, :disconnect],
    [:prismatic_sdk, :websocket, :message_sent],
    [:prismatic_sdk, :websocket, :message_received],

    # Service-specific events
    [:prismatic_sdk, :perimeter, :discover],
    [:prismatic_sdk, :perimeter, :monitoring_start],
    [:prismatic_sdk, :osint, :investigate],
    [:prismatic_sdk, :labs, :session_create],
    [:prismatic_sdk, :labs, :execute]
  ]

  defstruct [
    :metrics_table,
    :start_time
  ]

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Starts the telemetry system.

  Automatically called by the application supervisor.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Gets current metrics summary.

  ## Examples

      {:ok, metrics} = PrismaticSDK.Telemetry.get_metrics()
      # => %{
      #   http_requests: %{
      #     total: 1247,
      #     success: 1198,
      #     errors: 49,
      #     average_duration_ms: 245.6
      #   },
      #   rate_limiting: %{
      #     checks: 1247,
      #     allowed: 1198,
      #     denied: 49
      #   },
      #   websockets: %{
      #     active_connections: 3,
      #     messages_sent: 156,
      #     messages_received: 423
      #   }
      # }

  """
  @spec get_metrics() :: {:ok, map()} | {:error, term()}
  def get_metrics do
    GenServer.call(__MODULE__, :get_metrics)
  end

  @doc """
  Resets all metrics (for testing).

  ## Examples

      :ok = PrismaticSDK.Telemetry.reset_metrics()

  """
  @spec reset_metrics() :: :ok
  def reset_metrics do
    GenServer.call(__MODULE__, :reset_metrics)
  end

  @doc """
  Returns health status of the telemetry system.

  ## Examples

      {:ok, health} = PrismaticSDK.Telemetry.health_check()

  """
  @spec health_check() :: {:ok, map()}
  def health_check do
    GenServer.call(__MODULE__, :health_check)
  end

  @doc """
  Lists all SDK telemetry events.

  ## Examples

      events = PrismaticSDK.Telemetry.list_events()

  """
  @spec list_events() :: [list(atom())]
  def list_events do
    @events
  end

  @doc """
  Executes a function with telemetry instrumentation.

  ## Examples

      result = PrismaticSDK.Telemetry.span([:my_app, :operation], %{user_id: 123}, fn ->
        do_expensive_operation()
      end)

  """
  @spec span(list(atom()), map(), function()) :: term()
  def span(event_name, metadata, fun) when is_function(fun, 0) do
    start_time = System.monotonic_time(:microsecond)
    start_metadata = Map.put(metadata, :start_time, start_time)

    :telemetry.execute(
      event_name ++ [:start],
      %{system_time: System.system_time(:microsecond)},
      start_metadata
    )

    try do
      result = fun.()
      end_time = System.monotonic_time(:microsecond)
      duration = end_time - start_time

      :telemetry.execute(
        event_name ++ [:stop],
        %{duration: duration},
        Map.merge(metadata, %{result: :ok})
      )

      result
    rescue
      error ->
        end_time = System.monotonic_time(:microsecond)
        duration = end_time - start_time

        :telemetry.execute(
          event_name ++ [:exception],
          %{duration: duration},
          Map.merge(metadata, %{error: error, kind: :error})
        )

        reraise error, __STACKTRACE__
    catch
      kind, reason ->
        end_time = System.monotonic_time(:microsecond)
        duration = end_time - start_time

        :telemetry.execute(
          event_name ++ [:exception],
          %{duration: duration},
          Map.merge(metadata, %{error: reason, kind: kind})
        )

        :erlang.raise(kind, reason, __STACKTRACE__)
    end
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS table for metrics
    metrics_table = :ets.new(:prismatic_sdk_metrics, [:set, :public, :named_table])

    # Initialize counters
    initialize_metrics(metrics_table)

    # Attach telemetry handlers
    attach_handlers()

    state = %__MODULE__{
      metrics_table: metrics_table,
      start_time: DateTime.utc_now()
    }

    {:ok, state}
  end

  @impl true
  def handle_call(:get_metrics, _from, state) do
    metrics = collect_metrics(state.metrics_table)
    {:reply, {:ok, metrics}, state}
  end

  @impl true
  def handle_call(:reset_metrics, _from, state) do
    :ets.delete_all_objects(state.metrics_table)
    initialize_metrics(state.metrics_table)
    {:reply, :ok, state}
  end

  @impl true
  def handle_call(:health_check, _from, state) do
    uptime_ms = DateTime.diff(DateTime.utc_now(), state.start_time, :millisecond)
    metrics_count = :ets.info(state.metrics_table, :size)

    health = %{
      status: :healthy,
      uptime_ms: uptime_ms,
      metrics_count: metrics_count,
      events_attached: length(@events)
    }

    {:reply, {:ok, health}, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp initialize_metrics(table) do
    counters = [
      # HTTP metrics
      {:http_requests_total, 0},
      {:http_requests_success, 0},
      {:http_requests_error, 0},
      {:http_request_duration_sum, 0},
      {:http_request_duration_count, 0},

      # Authentication metrics
      {:auth_login_total, 0},
      {:auth_login_success, 0},
      {:auth_login_error, 0},
      {:auth_token_refresh_total, 0},

      # Rate limiting metrics
      {:rate_limit_checks, 0},
      {:rate_limit_allowed, 0},
      {:rate_limit_denied, 0},

      # Circuit breaker metrics
      {:circuit_breaker_calls, 0},
      {:circuit_breaker_successes, 0},
      {:circuit_breaker_failures, 0},
      {:circuit_breaker_open_count, 0},

      # WebSocket metrics
      {:websocket_connections, 0},
      {:websocket_messages_sent, 0},
      {:websocket_messages_received, 0},

      # Service metrics
      {:perimeter_discovers, 0},
      {:osint_investigations, 0},
      {:labs_sessions, 0},
      {:labs_executions, 0}
    ]

    Enum.each(counters, fn {key, value} ->
      :ets.insert(table, {key, value})
    end)
  end

  defp collect_metrics(table) do
    metrics = :ets.tab2list(table) |> Map.new()

    # Calculate derived metrics
    http_average_duration = case {metrics[:http_request_duration_sum], metrics[:http_request_duration_count]} do
      {sum, count} when count > 0 -> sum / count / 1000 # Convert to ms
      _ -> 0.0
    end

    %{
      http_requests: %{
        total: metrics[:http_requests_total] || 0,
        success: metrics[:http_requests_success] || 0,
        errors: metrics[:http_requests_error] || 0,
        average_duration_ms: Float.round(http_average_duration, 2)
      },
      authentication: %{
        login_total: metrics[:auth_login_total] || 0,
        login_success: metrics[:auth_login_success] || 0,
        login_errors: metrics[:auth_login_error] || 0,
        token_refreshes: metrics[:auth_token_refresh_total] || 0
      },
      rate_limiting: %{
        checks: metrics[:rate_limit_checks] || 0,
        allowed: metrics[:rate_limit_allowed] || 0,
        denied: metrics[:rate_limit_denied] || 0
      },
      circuit_breakers: %{
        calls: metrics[:circuit_breaker_calls] || 0,
        successes: metrics[:circuit_breaker_successes] || 0,
        failures: metrics[:circuit_breaker_failures] || 0,
        open_count: metrics[:circuit_breaker_open_count] || 0
      },
      websockets: %{
        active_connections: metrics[:websocket_connections] || 0,
        messages_sent: metrics[:websocket_messages_sent] || 0,
        messages_received: metrics[:websocket_messages_received] || 0
      },
      services: %{
        perimeter_discovers: metrics[:perimeter_discovers] || 0,
        osint_investigations: metrics[:osint_investigations] || 0,
        labs_sessions: metrics[:labs_sessions] || 0,
        labs_executions: metrics[:labs_executions] || 0
      }
    }
  end

  defp attach_handlers do
    # HTTP request handler
    :telemetry.attach(
      "prismatic-sdk-http-requests",
      [:prismatic_sdk, :client, :request],
      &handle_http_request/4,
      nil
    )

    # Authentication handlers
    :telemetry.attach(
      "prismatic-sdk-auth-login",
      [:prismatic_sdk, :auth, :login],
      &handle_auth_event/4,
      nil
    )

    # Rate limiting handlers
    :telemetry.attach(
      "prismatic-sdk-rate-limit",
      [:prismatic_sdk, :rate_limit, :check],
      &handle_rate_limit_event/4,
      nil
    )

    # Circuit breaker handlers
    :telemetry.attach(
      "prismatic-sdk-circuit-breaker",
      [:prismatic_sdk, :circuit_breaker, :call],
      &handle_circuit_breaker_event/4,
      nil
    )

    # WebSocket handlers
    :telemetry.attach_many(
      "prismatic-sdk-websocket",
      [
        [:prismatic_sdk, :websocket, :connect],
        [:prismatic_sdk, :websocket, :disconnect],
        [:prismatic_sdk, :websocket, :message_sent],
        [:prismatic_sdk, :websocket, :message_received]
      ],
      &handle_websocket_event/4,
      nil
    )

    # Service handlers
    :telemetry.attach_many(
      "prismatic-sdk-services",
      [
        [:prismatic_sdk, :perimeter, :discover],
        [:prismatic_sdk, :osint, :investigate],
        [:prismatic_sdk, :labs, :session_create],
        [:prismatic_sdk, :labs, :execute]
      ],
      &handle_service_event/4,
      nil
    )
  end

  # Event handlers

  defp handle_http_request(_event, measurements, metadata, _config) do
    increment_counter(:http_requests_total)

    case metadata[:result] do
      :ok ->
        increment_counter(:http_requests_success)
      _ ->
        increment_counter(:http_requests_error)
    end

    if duration = measurements[:duration] do
      increment_counter(:http_request_duration_sum, duration)
      increment_counter(:http_request_duration_count, 1)
    end
  end

  defp handle_auth_event([:prismatic_sdk, :auth, :login], _measurements, metadata, _config) do
    increment_counter(:auth_login_total)

    case metadata[:result] do
      :ok -> increment_counter(:auth_login_success)
      _ -> increment_counter(:auth_login_error)
    end
  end

  defp handle_auth_event([:prismatic_sdk, :auth, :token_refresh], _measurements, _metadata, _config) do
    increment_counter(:auth_token_refresh_total)
  end

  defp handle_auth_event(_event, _measurements, _metadata, _config), do: :ok

  defp handle_rate_limit_event(_event, _measurements, metadata, _config) do
    increment_counter(:rate_limit_checks)

    case metadata[:result] do
      :allowed -> increment_counter(:rate_limit_allowed)
      :denied -> increment_counter(:rate_limit_denied)
      _ -> :ok
    end
  end

  defp handle_circuit_breaker_event(_event, _measurements, metadata, _config) do
    increment_counter(:circuit_breaker_calls)

    case metadata[:result] do
      :ok -> increment_counter(:circuit_breaker_successes)
      _ -> increment_counter(:circuit_breaker_failures)
    end

    if metadata[:state_change] == :open do
      increment_counter(:circuit_breaker_open_count)
    end
  end

  defp handle_websocket_event([:prismatic_sdk, :websocket, :connect], _measurements, _metadata, _config) do
    increment_counter(:websocket_connections)
  end

  defp handle_websocket_event([:prismatic_sdk, :websocket, :disconnect], _measurements, _metadata, _config) do
    decrement_counter(:websocket_connections)
  end

  defp handle_websocket_event([:prismatic_sdk, :websocket, :message_sent], _measurements, _metadata, _config) do
    increment_counter(:websocket_messages_sent)
  end

  defp handle_websocket_event([:prismatic_sdk, :websocket, :message_received], _measurements, _metadata, _config) do
    increment_counter(:websocket_messages_received)
  end

  defp handle_websocket_event(_event, _measurements, _metadata, _config), do: :ok

  defp handle_service_event([:prismatic_sdk, :perimeter, :discover], _measurements, _metadata, _config) do
    increment_counter(:perimeter_discovers)
  end

  defp handle_service_event([:prismatic_sdk, :osint, :investigate], _measurements, _metadata, _config) do
    increment_counter(:osint_investigations)
  end

  defp handle_service_event([:prismatic_sdk, :labs, :session_create], _measurements, _metadata, _config) do
    increment_counter(:labs_sessions)
  end

  defp handle_service_event([:prismatic_sdk, :labs, :execute], _measurements, _metadata, _config) do
    increment_counter(:labs_executions)
  end

  defp handle_service_event(_event, _measurements, _metadata, _config), do: :ok

  # Helper functions

  defp increment_counter(key, amount \\ 1) do
    :ets.update_counter(:prismatic_sdk_metrics, key, amount)
  rescue
    ArgumentError ->
      :ets.insert(:prismatic_sdk_metrics, {key, amount})
  end

  defp decrement_counter(key, amount \\ 1) do
    :ets.update_counter(:prismatic_sdk_metrics, key, -amount)
  rescue
    ArgumentError ->
      :ets.insert(:prismatic_sdk_metrics, {key, -amount})
  end
end