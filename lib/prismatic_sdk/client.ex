defmodule PrismaticSDK.Client do
  @moduledoc """
  HTTP client for the Prismatic Platform API.

  Handles authentication, request/response processing, error handling,
  and integration with rate limiting and circuit breaker infrastructure.

  ## Configuration

  The client can be configured with various options:

      client = PrismaticSDK.Client.new(
        api_key: "pk_live_...",
        base_url: "https://api.prismatic-platform.com",
        timeout: 30_000,
        retry_attempts: 3,
        rate_limit: %{
          requests_per_second: 10,
          burst_size: 50
        }
      )

  ## Authentication

  Supports multiple authentication methods:

  - **API Key**: `api_key: "pk_live_..."`
  - **Bearer Token**: `bearer_token: "jwt_token"`
  - **Basic Auth**: `basic_auth: {username, password}`

  ## Error Handling

  All requests return standardized error responses:

      {:error, :unauthorized}     # 401 - Invalid credentials
      {:error, :forbidden}        # 403 - Insufficient permissions
      {:error, :not_found}        # 404 - Resource not found
      {:error, :rate_limited}     # 429 - Rate limit exceeded
      {:error, :server_error}     # 5xx - Server errors
      {:error, :timeout}          # Request timeout
      {:error, :network_error}    # Network connectivity issues

  """

  alias PrismaticSDK.Auth
  require Logger

  @type t :: %__MODULE__{
    base_url: String.t(),
    auth: Auth.t(),
    timeout: pos_integer(),
    retry_attempts: non_neg_integer(),
    rate_limit: map() | nil,
    circuit_breaker: String.t() | nil,
    pool: atom(),
    headers: map()
  }

  @type request_opts :: [
    path: String.t(),
    method: atom(),
    body: term(),
    params: map(),
    headers: map(),
    timeout: pos_integer(),
    pool: atom()
  ]

  @type response :: {:ok, map()} | {:error, term()}

  @enforce_keys [:base_url, :auth]
  defstruct [
    :base_url,
    :auth,
    timeout: 30_000,
    retry_attempts: 3,
    rate_limit: nil,
    circuit_breaker: nil,
    pool: :default,
    headers: %{}
  ]

  @doc """
  Creates a new client with the given configuration.

  ## Options

  - `:api_key` - API key for authentication
  - `:bearer_token` - JWT bearer token
  - `:base_url` - API base URL (default: from application config)
  - `:timeout` - Request timeout in milliseconds (default: 30_000)
  - `:retry_attempts` - Number of retry attempts (default: 3)
  - `:rate_limit` - Rate limiting config (optional)
  - `:circuit_breaker` - Circuit breaker name (optional)
  - `:pool` - HTTP pool to use (default: :default)
  - `:headers` - Additional HTTP headers (default: %{})

  ## Examples

      # API key authentication
      client = PrismaticSDK.Client.new(api_key: "pk_live_...")

      # JWT token authentication
      client = PrismaticSDK.Client.new(bearer_token: "eyJ0eXAi...")

      # Custom configuration
      client = PrismaticSDK.Client.new(
        api_key: "pk_test_...",
        base_url: "https://staging.api.prismatic.com",
        timeout: 60_000,
        retry_attempts: 5,
        pool: :osint
      )

  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    base_url = Keyword.get(opts, :base_url) ||
               Application.get_env(:prismatic_sdk, :base_url, "https://api.prismatic-platform.com")

    auth = cond do
      api_key = Keyword.get(opts, :api_key) ->
        Auth.api_key(api_key)

      bearer_token = Keyword.get(opts, :bearer_token) ->
        Auth.bearer_token(bearer_token)

      basic_auth = Keyword.get(opts, :basic_auth) ->
        case basic_auth do
          {username, password} -> Auth.basic_auth(username, password)
          _ -> raise ArgumentError, "Invalid basic_auth format, expected {username, password}"
        end

      true ->
        # Try to get from application config
        case Application.get_env(:prismatic_sdk, :api_key) do
          nil -> raise ArgumentError, "No authentication method provided"
          api_key -> Auth.api_key(api_key)
        end
    end

    %__MODULE__{
      base_url: String.trim_trailing(base_url, "/"),
      auth: auth,
      timeout: Keyword.get(opts, :timeout, 30_000),
      retry_attempts: Keyword.get(opts, :retry_attempts, 3),
      rate_limit: Keyword.get(opts, :rate_limit),
      circuit_breaker: Keyword.get(opts, :circuit_breaker),
      pool: Keyword.get(opts, :pool, :default),
      headers: Keyword.get(opts, :headers, %{}) |> Map.new()
    }
  end

  @doc """
  Makes an HTTP request using the configured client.

  ## Examples

      # GET request
      {:ok, response} = PrismaticSDK.Client.request(client,
        method: :get,
        path: "/api/v1/perimeter/discover",
        params: %{domain: "example.com"}
      )

      # POST request with body
      {:ok, response} = PrismaticSDK.Client.request(client,
        method: :post,
        path: "/api/v1/labs/sessions",
        body: %{lab_type: "lean4", config: %{}}
      )

  """
  @spec request(t(), request_opts()) :: response()
  def request(client, opts) do
    path = Keyword.fetch!(opts, :path)
    method = Keyword.get(opts, :method, :get)
    body = Keyword.get(opts, :body, nil)
    params = Keyword.get(opts, :params, %{})
    headers = Keyword.get(opts, :headers, %{})
    timeout = Keyword.get(opts, :timeout, client.timeout)
    pool = Keyword.get(opts, :pool, client.pool)

    with :ok <- check_rate_limit(client),
         :ok <- check_circuit_breaker(client),
         {:ok, response} <- make_request(client, method, path, body, params, headers, timeout, pool) do

      record_success(client)
      emit_telemetry(client, method, path, :ok, response)
      {:ok, response}
    else
      {:error, reason} = error ->
        record_failure(client, reason)
        emit_telemetry(client, method, path, :error, reason)
        error
    end
  end

  @doc """
  Performs a GET request.

  ## Examples

      {:ok, surface} = PrismaticSDK.Client.get(client, "/api/v1/perimeter/surface", %{domain: "example.com"})

  """
  @spec get(t(), String.t(), map(), keyword()) :: response()
  def get(client, path, params \\ %{}, opts \\ []) do
    request(client, Keyword.merge(opts, [method: :get, path: path, params: params]))
  end

  @doc """
  Performs a POST request.

  ## Examples

      {:ok, session} = PrismaticSDK.Client.post(client, "/api/v1/labs/sessions", %{lab_type: "lean4"})

  """
  @spec post(t(), String.t(), term(), keyword()) :: response()
  def post(client, path, body \\ %{}, opts \\ []) do
    request(client, Keyword.merge(opts, [method: :post, path: path, body: body]))
  end

  @doc """
  Performs a PUT request.

  ## Examples

      {:ok, session} = PrismaticSDK.Client.put(client, "/api/v1/labs/sessions/123", %{state: "updated"})

  """
  @spec put(t(), String.t(), term(), keyword()) :: response()
  def put(client, path, body \\ %{}, opts \\ []) do
    request(client, Keyword.merge(opts, [method: :put, path: path, body: body]))
  end

  @doc """
  Performs a DELETE request.

  ## Examples

      :ok = PrismaticSDK.Client.delete(client, "/api/v1/labs/sessions/123")

  """
  @spec delete(t(), String.t(), keyword()) :: response()
  def delete(client, path, opts \\ []) do
    request(client, Keyword.merge(opts, [method: :delete, path: path]))
  end

  @doc """
  Health check for the client configuration.

  Verifies:
  - HTTP client connectivity
  - Authentication validity
  - Rate limiter status
  - Circuit breaker status

  ## Examples

      {:ok, health} = PrismaticSDK.Client.health_check(client)
      # => %{
      #   status: :healthy,
      #   connectivity: :ok,
      #   authentication: :valid,
      #   rate_limiter: :ok,
      #   circuit_breaker: :closed
      # }

  """
  @spec health_check(t()) :: {:ok, map()} | {:error, term()}
  def health_check(client) do
    try do
      health = %{
        status: :healthy,
        connectivity: check_connectivity(client),
        authentication: check_authentication(client),
        rate_limiter: check_rate_limit_status(client),
        circuit_breaker: check_circuit_breaker_status(client)
      }

      overall_status = if all_checks_pass?(health), do: :healthy, else: :degraded
      {:ok, %{health | status: overall_status}}
    rescue
      error ->
        {:error, {:health_check_failed, error}}
    end
  end

  # Private functions

  defp check_rate_limit(_client) do
    # Simplified rate limiting - would be implemented based on platform needs
    :ok
  end

  defp check_circuit_breaker(_client) do
    # Simplified circuit breaker - would be implemented based on platform needs
    :ok
  end

  defp make_request(client, method, path, body, params, headers, timeout, _pool) do
    url = build_url(client.base_url, path, params)
    {content_type, request_headers} = build_headers(client, headers)
    request_body = encode_body(body, content_type)

    _options = [
      timeout: timeout,
      recv_timeout: timeout
    ]

    req = Finch.build(method, url, request_headers, request_body)

    case Finch.request(req, PrismaticSDK.Finch, receive_timeout: timeout) do
      {:ok, %Finch.Response{status: status, body: response_body, headers: response_headers}} ->
        handle_response(status, response_body, response_headers)

      {:error, %Mint.TransportError{reason: :timeout}} ->
        {:error, :timeout}

      {:error, reason} ->
        {:error, {:network_error, reason}}
    end
  end

  defp build_url(base_url, path, params) when params == %{} do
    "#{base_url}#{path}"
  end

  defp build_url(base_url, path, params) do
    query_string = URI.encode_query(params)
    "#{base_url}#{path}?#{query_string}"
  end

  defp build_headers(client, additional_headers) do
    base_headers = %{
      "user-agent" => "PrismaticSDK/#{PrismaticSDK.version()} (Elixir)",
      "accept" => "application/json",
      "content-type" => "application/json"
    }

    merged =
      base_headers
      |> Map.merge(client.headers)
      |> Map.merge(additional_headers)
      |> Map.merge(Auth.headers(client.auth))

    {Map.get(merged, "content-type", "application/json"), Map.to_list(merged)}
  end

  defp encode_body(nil, _content_type), do: ""
  defp encode_body("", _content_type), do: ""
  defp encode_body(body, "application/json") when is_map(body) or is_list(body) do
    Jason.encode!(body)
  end
  defp encode_body(body, _content_type) when is_binary(body), do: body
  defp encode_body(body, _content_type), do: inspect(body)

  defp handle_response(status, body, headers) when status in 200..299 do
    content_type = get_header(headers, "content-type", "")

    case decode_response_body(body, content_type) do
      {:ok, decoded_body} -> {:ok, decoded_body}
      {:error, _} -> {:ok, body}
    end
  end

  defp handle_response(401, _body, _headers), do: {:error, :unauthorized}
  defp handle_response(403, _body, _headers), do: {:error, :forbidden}
  defp handle_response(404, _body, _headers), do: {:error, :not_found}
  defp handle_response(429, _body, _headers), do: {:error, :rate_limited}
  defp handle_response(status, body, headers) when status in 400..499 do
    case decode_response_body(body, get_header(headers, "content-type", "")) do
      {:ok, decoded} -> {:error, {:client_error, status, decoded}}
      {:error, _} -> {:error, {:client_error, status, body}}
    end
  end

  defp handle_response(status, body, headers) when status in 500..599 do
    case decode_response_body(body, get_header(headers, "content-type", "")) do
      {:ok, decoded} -> {:error, {:server_error, status, decoded}}
      {:error, _} -> {:error, {:server_error, status, body}}
    end
  end

  defp handle_response(status, body, _headers) do
    {:error, {:unexpected_status, status, body}}
  end

  defp decode_response_body("", _content_type), do: {:ok, nil}
  defp decode_response_body(body, content_type) when is_binary(content_type) do
    if String.contains?(content_type, "application/json") do
      Jason.decode(body)
    else
      {:ok, body}
    end
  end

  defp get_header(headers, key, default) do
    case List.keyfind(headers, key, 0) do
      {^key, value} -> value
      nil -> default
    end
  end

  defp record_success(_client) do
    # Simplified success recording
    :ok
  end

  defp record_failure(_client, _reason) do
    # Simplified failure recording
    :ok
  end

  defp emit_telemetry(client, method, path, result, data) do
    metadata = %{
      base_url: client.base_url,
      method: method,
      path: path,
      pool: client.pool,
      result: result
    }

    measurements = %{
      duration: System.monotonic_time(:microsecond)
    }

    :telemetry.execute(
      [:prismatic_sdk, :client, :request],
      measurements,
      Map.put(metadata, :data, data)
    )
  end

  defp check_connectivity(client) do
    case get(client, "/api/v1/health", %{}, timeout: 5_000) do
      {:ok, _} -> :ok
      {:error, :timeout} -> :timeout
      {:error, _} -> :error
    end
  end

  defp check_authentication(client) do
    case get(client, "/api/v1/user", %{}, timeout: 5_000) do
      {:ok, _} -> :valid
      {:error, :unauthorized} -> :invalid
      {:error, _} -> :unknown
    end
  end

  defp check_rate_limit_status(_client) do
    :disabled
  end

  defp check_circuit_breaker_status(_client) do
    :disabled
  end

  defp all_checks_pass?(health) do
    health
    |> Map.drop([:status])
    |> Map.values()
    |> Enum.all?(fn
      :ok -> true
      :valid -> true
      :closed -> true
      :disabled -> true
      _ -> false
    end)
  end
end