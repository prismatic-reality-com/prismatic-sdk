defmodule PrismaticSDK.Labs do
  @moduledoc """
  Sandboxed Labs API wrapper.

  Provides access to Prismatic Platform's secure execution environments including:

  - **Playbook Labs** - Workflow execution with template rendering
  - **Blackboard Labs** - Multi-agent coordination via shared memory
  - **Lean4 Labs** - Theorem proving and formal verification
  - **Smalltalk Labs** - Object-oriented live coding environment

  ## Usage

      client = PrismaticSDK.Client.new(api_key: "your-api-key")

      # Create a new lab session
      {:ok, session} = PrismaticSDK.Labs.create_session(client, %{
        lab_type: "lean4",
        classification_level: "public",
        config: %{}
      })

      # Execute code in the session
      {:ok, execution} = PrismaticSDK.Labs.execute_in_session(client, session.id, %{
        execution_type: "lean4_check",
        input_data: %{
          "operation" => "type_check",
          "expression" => "Nat.add 2 2"
        }
      })

      # Terminate session
      :ok = PrismaticSDK.Labs.terminate_session(client, session.id)

  """

  alias PrismaticSDK.Client

  @type client :: Client.t()
  @type session_id :: String.t()
  @type lab_type :: :playbook | :blackboard | :lean4 | :smalltalk
  @type classification_level :: :public | :internal | :confidential | :secret | :top_secret
  @type execution_status :: :pending | :running | :completed | :failed | :timeout

  @type session :: %{
    id: session_id(),
    user_id: String.t(),
    lab_type: lab_type(),
    classification_level: classification_level(),
    status: atom(),
    config: map(),
    state: map(),
    resource_usage: map(),
    started_at: DateTime.t(),
    last_activity_at: DateTime.t(),
    expires_at: DateTime.t()
  }

  @type execution :: %{
    id: String.t(),
    session_id: session_id(),
    execution_type: String.t(),
    input_data: map(),
    output_data: map() | nil,
    status: execution_status(),
    error_message: String.t() | nil,
    execution_time_ms: integer() | nil,
    resource_usage: map(),
    started_at: DateTime.t(),
    completed_at: DateTime.t() | nil
  }

  # ============================================================================
  # Session Management API
  # ============================================================================

  @doc """
  Creates a new lab session with sandbox isolation.

  ## Parameters

  - `attrs` - Session attributes map

  ## Required Attributes

  - `:lab_type` - Type of lab (`:playbook`, `:blackboard`, `:lean4`, `:smalltalk`)
  - `:classification_level` - Security level (`:public`, `:internal`, `:confidential`, `:secret`, `:top_secret`)

  ## Optional Attributes

  - `:config` - Lab-specific configuration (default: `%{}`)
  - `:expires_at` - Session expiration time (default: 1 hour from now)
  - `:user_id` - User ID for session ownership (if not provided, uses authenticated user)

  ## Examples

      # Basic session creation
      {:ok, session} = PrismaticSDK.Labs.create_session(client, %{
        lab_type: :lean4,
        classification_level: :public
      })

      # Advanced session with custom config
      {:ok, session} = PrismaticSDK.Labs.create_session(client, %{
        lab_type: :playbook,
        classification_level: :confidential,
        config: %{
          timeout_ms: 120_000,
          memory_limit_mb: 512
        },
        expires_at: DateTime.add(DateTime.utc_now(), 7200, :second)
      })

  ## Response

      {:ok, %{
        id: "sess_1234567890",
        user_id: "user_123",
        lab_type: :lean4,
        classification_level: :public,
        status: :active,
        config: %{timeout_ms: 60000},
        state: %{},
        resource_usage: %{memory_bytes: 0},
        started_at: ~U[2026-02-21 10:30:00Z],
        last_activity_at: ~U[2026-02-21 10:30:00Z],
        expires_at: ~U[2026-02-21 11:30:00Z]
      }}

  """
  @spec create_session(client(), map()) :: {:ok, session()} | {:error, term()}
  def create_session(client, attrs) do
    # Convert lab_type to string if it's an atom
    params = attrs
    |> Map.update(:lab_type, nil, fn
      type when is_atom(type) -> Atom.to_string(type)
      type -> type
    end)
    |> Map.update(:classification_level, nil, fn
      level when is_atom(level) -> Atom.to_string(level)
      level -> level
    end)

    case Client.post(client, "/api/v1/labs/sessions", params) do
      {:ok, response} -> {:ok, parse_session(response)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Gets an active session by ID.

  ## Examples

      {:ok, session} = PrismaticSDK.Labs.get_session(client, session_id)

  """
  @spec get_session(client(), session_id()) :: {:ok, session()} | {:error, term()}
  def get_session(client, session_id) do
    case Client.get(client, "/api/v1/labs/sessions/#{session_id}") do
      {:ok, response} -> {:ok, parse_session(response)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Updates a session's state or configuration.

  ## Examples

      {:ok, session} = PrismaticSDK.Labs.update_session_state(client, session_id, %{
        state: %{"current_step" => 3},
        config: %{timeout_ms: 120_000}
      })

  """
  @spec update_session_state(client(), session_id(), map()) ::
          {:ok, session()} | {:error, term()}
  def update_session_state(client, session_id, updates) do
    case Client.put(client, "/api/v1/labs/sessions/#{session_id}", updates) do
      {:ok, response} -> {:ok, parse_session(response)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Lists active sessions for the authenticated user.

  ## Options

  - `:limit` - Maximum number of sessions to return (default: 50)
  - `:status` - Filter by session status
  - `:lab_type` - Filter by lab type

  ## Examples

      {:ok, sessions} = PrismaticSDK.Labs.list_active_sessions(client)

      {:ok, lean4_sessions} = PrismaticSDK.Labs.list_active_sessions(client,
        lab_type: :lean4,
        limit: 10
      )

  """
  @spec list_active_sessions(client(), keyword()) :: {:ok, [session()]} | {:error, term()}
  def list_active_sessions(client, opts \\ []) do
    params = %{}
    |> maybe_put(:limit, opts[:limit])
    |> maybe_put(:status, opts[:status])
    |> maybe_put(:lab_type, opts[:lab_type])

    case Client.get(client, "/api/v1/labs/sessions", params) do
      {:ok, %{"sessions" => sessions}} -> {:ok, Enum.map(sessions, &parse_session/1)}
      {:ok, sessions} when is_list(sessions) -> {:ok, Enum.map(sessions, &parse_session/1)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Terminates a lab session and cleans up resources.

  ## Parameters

  - `session_id` - UUID of the session
  - `reason` - Optional termination reason (default: "manual")

  ## Examples

      :ok = PrismaticSDK.Labs.terminate_session(client, session_id)

      :ok = PrismaticSDK.Labs.terminate_session(client, session_id, "timeout")

  """
  @spec terminate_session(client(), session_id(), String.t()) :: :ok | {:error, term()}
  def terminate_session(client, session_id, reason \\ "manual") do
    params = %{reason: reason}

    case Client.delete(client, "/api/v1/labs/sessions/#{session_id}", params) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  # ============================================================================
  # Code Execution API
  # ============================================================================

  @doc """
  Executes code in a sandboxed session.

  ## Parameters

  - `session_id` - UUID of the session
  - `execution_data` - Execution parameters map

  ## Required Execution Data

  - `:execution_type` - Type of execution (varies by lab type)
  - `:input_data` - Input data for the execution

  ## Examples

      # Lean4 theorem proving
      {:ok, execution} = PrismaticSDK.Labs.execute_in_session(client, session_id, %{
        execution_type: "lean4_check",
        input_data: %{
          "operation" => "prove_theorem",
          "theorem" => "2 + 2 = 4",
          "proof" => "by norm_num"
        }
      })

      # Playbook template rendering
      {:ok, execution} = PrismaticSDK.Labs.execute_in_session(client, session_id, %{
        execution_type: "template_render",
        input_data: %{
          "type" => "template_render",
          "template" => "Hello {{name}}!",
          "variables" => %{"name" => "World"}
        }
      })

      # Blackboard operations
      {:ok, execution} = PrismaticSDK.Labs.execute_in_session(client, session_id, %{
        execution_type: "blackboard_write",
        input_data: %{
          "operation" => "write",
          "key" => "message",
          "value" => "Hello World"
        }
      })

      # Smalltalk evaluation
      {:ok, execution} = PrismaticSDK.Labs.execute_in_session(client, session_id, %{
        execution_type: "smalltalk_eval",
        input_data: %{
          "operation" => "evaluate",
          "expression" => "Array new: 5"
        }
      })

  ## Response

      {:ok, %{
        id: "exec_1234567890",
        session_id: "sess_1234567890",
        execution_type: "lean4_check",
        input_data: %{"operation" => "type_check", ...},
        output_data: %{"type_correct" => true, "inferred_type" => "Nat"},
        status: :completed,
        error_message: nil,
        execution_time_ms: 150,
        resource_usage: %{memory_bytes: 1024000},
        started_at: ~U[2026-02-21 10:30:00Z],
        completed_at: ~U[2026-02-21 10:30:01Z]
      }}

  """
  @spec execute_in_session(client(), session_id(), map()) ::
          {:ok, execution()} | {:error, term()}
  def execute_in_session(client, session_id, execution_data) do
    case Client.post(client, "/api/v1/labs/sessions/#{session_id}/execute", execution_data) do
      {:ok, response} -> {:ok, parse_execution(response)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Gets the status of a code execution.

  ## Examples

      {:ok, execution} = PrismaticSDK.Labs.get_execution(client, execution_id)

  """
  @spec get_execution(client(), String.t()) :: {:ok, execution()} | {:error, term()}
  def get_execution(client, execution_id) do
    case Client.get(client, "/api/v1/labs/executions/#{execution_id}") do
      {:ok, response} -> {:ok, parse_execution(response)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Lists executions for a session.

  ## Options

  - `:limit` - Maximum number of executions to return (default: 50)
  - `:status` - Filter by execution status

  ## Examples

      {:ok, executions} = PrismaticSDK.Labs.list_executions(client, session_id)

  """
  @spec list_executions(client(), session_id(), keyword()) ::
          {:ok, [execution()]} | {:error, term()}
  def list_executions(client, session_id, opts \\ []) do
    params = %{}
    |> maybe_put(:limit, opts[:limit])
    |> maybe_put(:status, opts[:status])

    case Client.get(client, "/api/v1/labs/sessions/#{session_id}/executions", params) do
      {:ok, %{"executions" => executions}} -> {:ok, Enum.map(executions, &parse_execution/1)}
      {:ok, executions} when is_list(executions) -> {:ok, Enum.map(executions, &parse_execution/1)}
      {:error, reason} -> {:error, reason}
    end
  end

  # ============================================================================
  # Resource Monitoring API
  # ============================================================================

  @doc """
  Gets current resource usage for a session.

  ## Examples

      {:ok, usage} = PrismaticSDK.Labs.get_resource_usage(client, session_id)

  ## Response

      {:ok, %{
        memory_bytes: 1500000,
        heap_size: 800000,
        cpu_percent: 15.5,
        execution_count: 42,
        active: true,
        last_check: ~U[2026-02-21 10:30:00Z]
      }}

  """
  @spec get_resource_usage(client(), session_id()) :: {:ok, map()} | {:error, term()}
  def get_resource_usage(client, session_id) do
    Client.get(client, "/api/v1/labs/sessions/#{session_id}/resources")
  end

  @doc """
  Gets system-wide metrics for the labs service.

  ## Examples

      {:ok, metrics} = PrismaticSDK.Labs.get_system_metrics(client)

  ## Response

      {:ok, %{
        active_sessions: 25,
        total_executions_today: 1247,
        resource_warnings: 3,
        uptime_ms: 3600000,
        memory_usage_total: 2147483648,
        cpu_usage_average: 45.2
      }}

  """
  @spec get_system_metrics(client()) :: {:ok, map()} | {:error, term()}
  def get_system_metrics(client) do
    Client.get(client, "/api/v1/labs/metrics")
  end

  # ============================================================================
  # Lab Type Information API
  # ============================================================================

  @doc """
  Gets supported lab types.

  ## Examples

      {:ok, lab_types} = PrismaticSDK.Labs.supported_lab_types(client)
      # => {:ok, [:playbook, :blackboard, :lean4, :smalltalk]}

  """
  @spec supported_lab_types(client()) :: {:ok, [lab_type()]} | {:error, term()}
  def supported_lab_types(client) do
    case Client.get(client, "/api/v1/labs/types") do
      {:ok, %{"lab_types" => types}} ->
        {:ok, Enum.map(types, &String.to_existing_atom/1)}
      {:ok, types} when is_list(types) ->
        {:ok, Enum.map(types, &String.to_existing_atom/1)}
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Gets available classification levels.

  ## Examples

      {:ok, levels} = PrismaticSDK.Labs.classification_levels(client)
      # => {:ok, [:public, :internal, :confidential, :secret, :top_secret]}

  """
  @spec classification_levels(client()) :: {:ok, [classification_level()]} | {:error, term()}
  def classification_levels(client) do
    case Client.get(client, "/api/v1/labs/classification-levels") do
      {:ok, %{"levels" => levels}} ->
        {:ok, Enum.map(levels, &String.to_existing_atom/1)}
      {:ok, levels} when is_list(levels) ->
        {:ok, Enum.map(levels, &String.to_existing_atom/1)}
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Gets information about a specific lab type.

  ## Examples

      {:ok, info} = PrismaticSDK.Labs.lab_type_info(client, :lean4)

  ## Response

      {:ok, %{
        name: "lean4",
        display_name: "Lean 4 Theorem Proving",
        description: "Formal verification and theorem proving environment",
        supported_operations: ["type_check", "prove_theorem", "evaluate"],
        resource_limits: %{
          max_memory_mb: 1024,
          max_execution_time_ms: 300000
        },
        examples: [...]
      }}

  """
  @spec lab_type_info(client(), lab_type()) :: {:ok, map()} | {:error, term()}
  def lab_type_info(client, lab_type) do
    Client.get(client, "/api/v1/labs/types/#{lab_type}")
  end

  # ============================================================================
  # Quota and Limits API
  # ============================================================================

  @doc """
  Gets current quota usage for the authenticated user.

  ## Examples

      {:ok, quota} = PrismaticSDK.Labs.get_quota(client)

  ## Response

      {:ok, %{
        user_id: "user_123",
        role: "power_user",
        limits: %{
          max_concurrent_sessions: 5,
          max_memory_mb: 1024,
          max_execution_time_ms: 300000,
          max_daily_executions: 500
        },
        current_usage: %{
          active_sessions: 2,
          memory_used_mb: 512,
          executions_today: 47
        },
        quota_reset_at: ~U[2026-02-22 00:00:00Z]
      }}

  """
  @spec get_quota(client()) :: {:ok, map()} | {:error, term()}
  def get_quota(client) do
    Client.get(client, "/api/v1/labs/quota")
  end

  # Private helper functions

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp parse_session(session_data) do
    %{
      id: session_data["id"],
      user_id: session_data["user_id"],
      lab_type: String.to_existing_atom(session_data["lab_type"]),
      classification_level: String.to_existing_atom(session_data["classification_level"]),
      status: String.to_existing_atom(session_data["status"] || "active"),
      config: session_data["config"] || %{},
      state: session_data["state"] || %{},
      resource_usage: session_data["resource_usage"] || %{},
      started_at: parse_datetime(session_data["started_at"]),
      last_activity_at: parse_datetime(session_data["last_activity_at"]),
      expires_at: parse_datetime(session_data["expires_at"])
    }
  end

  defp parse_execution(execution_data) do
    %{
      id: execution_data["id"],
      session_id: execution_data["session_id"],
      execution_type: execution_data["execution_type"],
      input_data: execution_data["input_data"] || %{},
      output_data: execution_data["output_data"],
      status: String.to_existing_atom(execution_data["status"] || "pending"),
      error_message: execution_data["error_message"],
      execution_time_ms: execution_data["execution_time_ms"],
      resource_usage: execution_data["resource_usage"] || %{},
      started_at: parse_datetime(execution_data["started_at"]),
      completed_at: parse_datetime(execution_data["completed_at"])
    }
  end

  defp parse_datetime(nil), do: DateTime.utc_now()
  defp parse_datetime(datetime_string) when is_binary(datetime_string) do
    case DateTime.from_iso8601(datetime_string) do
      {:ok, datetime, _offset} -> datetime
      {:error, _} -> DateTime.utc_now()
    end
  end
  defp parse_datetime(_), do: DateTime.utc_now()
end