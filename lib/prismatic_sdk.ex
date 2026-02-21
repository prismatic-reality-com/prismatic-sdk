defmodule PrismaticSDK do
  @moduledoc """
  Production-ready Elixir SDK for the Prismatic Platform.

  The Prismatic SDK provides type-safe access to all Prismatic Platform APIs including:

  - **External Attack Surface Management (EASM)** - Asset discovery and risk assessment
  - **OSINT Intelligence** - 120+ sources for open source intelligence
  - **Sandboxed Labs** - Secure code execution environments
  - **Threat Intelligence** - IOCs, malware analysis, breach detection
  - **Compliance Assessment** - NIS2, Czech ZKB compliance frameworks

  ## Quick Start

      # Configure your client
      client = PrismaticSDK.Client.new(
        api_key: "your-api-key",
        base_url: "https://api.prismatic-platform.com",
        timeout: 30_000
      )

      # Discover attack surface
      {:ok, surface} = PrismaticSDK.Perimeter.discover(client, "example.com")

      # Get security rating
      {:ok, rating} = PrismaticSDK.Perimeter.security_rating(client, "example.com")

      # Run OSINT investigation
      {:ok, findings} = PrismaticSDK.OSINT.investigate(client, "target.com",
        sources: [:whois, :dns, :certificates]
      )

      # Create sandboxed lab session
      {:ok, session} = PrismaticSDK.Labs.create_session(client, %{
        lab_type: "lean4",
        classification_level: "public"
      })

  ## Authentication

  The SDK supports multiple authentication methods:

  - **API Keys** - For service-to-service authentication
  - **JWT Tokens** - For user-based authentication
  - **OAuth 2.0** - For third-party integrations

      # API Key authentication
      client = PrismaticSDK.Client.new(api_key: "pk_live_...")

      # JWT token authentication
      {:ok, token} = PrismaticSDK.Auth.authenticate(client, %{
        username: "user@example.com",
        password: "secure_password"
      })

      client = PrismaticSDK.Client.new(bearer_token: token)

  ## Rate Limiting

  The SDK includes intelligent rate limiting with automatic retries:

      # Configure rate limits per service
      client = PrismaticSDK.Client.new(
        api_key: "your-key",
        rate_limit: %{
          requests_per_second: 10,
          burst_size: 50,
          retry_after: 1000
        }
      )

  ## Real-time Updates

  Subscribe to real-time updates via WebSockets:

      # Connect to monitoring updates
      {:ok, socket} = PrismaticSDK.Websocket.connect(client,
        topic: "perimeter:monitoring",
        handler: MyApp.PerimeterHandler
      )

  ## Error Handling

  All API calls return tagged tuples for predictable error handling:

      case PrismaticSDK.Perimeter.discover(client, domain) do
        {:ok, attack_surface} ->
          IO.puts("Discovered assets for domain")

        {:error, :rate_limited} ->
          IO.puts("Rate limited, retrying in 30s")
          Process.sleep(30_000)

        {:error, :unauthorized} ->
          IO.puts("Check your API key")

        {:error, error_reason} ->
          IO.puts("Discovery failed")
      end

  ## Configuration

      config :prismatic_sdk,
        # Default API endpoint
        base_url: "https://api.prismatic-platform.com",

        # Authentication
        api_key: System.get_env("PRISMATIC_API_KEY"),

        # HTTP client settings
        timeout: 30_000,
        retry_attempts: 3,

        # Rate limiting
        rate_limit_enabled: true,
        requests_per_second: 10,

        # WebSocket settings
        websocket_enabled: true,
        reconnect_interval: 5_000,

        # Telemetry
        telemetry_enabled: true

  ## Services

  The SDK provides dedicated modules for each Prismatic service:

  - `PrismaticSDK.Perimeter` - External Attack Surface Management
  - `PrismaticSDK.OSINT` - Open Source Intelligence
  - `PrismaticSDK.Labs` - Sandboxed Execution Environments
  - `PrismaticSDK.Intelligence` - Threat Intelligence
  - `PrismaticSDK.Compliance` - Regulatory Compliance
  """

  alias PrismaticSDK.Client

  @type client :: Client.t()
  @type result(data) :: {:ok, data} | {:error, term()}

  @doc """
  Creates a new SDK client with the given configuration.

  ## Options

  - `:api_key` - API key for authentication (required)
  - `:base_url` - Base URL for the API (default: from config)
  - `:timeout` - Request timeout in milliseconds (default: 30_000)
  - `:retry_attempts` - Number of retry attempts (default: 3)
  - `:rate_limit` - Rate limiting configuration (optional)

  ## Examples

      client = PrismaticSDK.new(api_key: "pk_live_...")

      client = PrismaticSDK.new(
        api_key: "pk_test_...",
        base_url: "https://staging.prismatic-platform.com",
        timeout: 60_000
      )

  """
  @spec new(keyword()) :: client()
  def new(opts \\ []) do
    Client.new(opts)
  end

  @doc """
  Returns the SDK version.
  """
  @spec version() :: String.t()
  def version do
    Application.spec(:prismatic_sdk, :vsn) |> to_string()
  end

  @doc """
  Returns the health status of the SDK and its dependencies.

  ## Examples

      {:ok, status} = PrismaticSDK.health_check(client)
      # => %{
      #   status: :healthy,
      #   version: "0.1.0",
      #   dependencies: %{
      #     http_client: :ok,
      #     rate_limiter: :ok,
      #     websocket: :ok
      #   },
      #   timestamp: ~U[2026-02-21 10:30:00Z]
      # }

  """
  @spec health_check(client()) :: result(map())
  def health_check(client) do
    case Client.get(client, "/api/v1/health", %{}, timeout: 5_000) do
      {:ok, response} ->
        {:ok, %{
          status: :healthy,
          api_response: response,
          timestamp: DateTime.utc_now()
        }}
      {:error, reason} ->
        {:error, reason}
    end
  end
end