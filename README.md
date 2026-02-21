# Prismatic SDK for Elixir

[![Hex.pm](https://img.shields.io/hexpm/v/prismatic_sdk.svg)](https://hex.pm/packages/prismatic_sdk)
[![Documentation](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/prismatic_sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Production-ready Elixir SDK for the [Prismatic Platform](https://prismatic-platform.com) APIs.

## Features

- **🔐 Multiple Authentication Methods** - API keys, JWT tokens, OAuth 2.0
- **🌐 Complete API Coverage** - EASM, OSINT, Labs, Threat Intelligence
- **⚡ Built-in Rate Limiting** - Intelligent throttling with automatic retries
- **🔄 Circuit Breaker Protection** - Fault tolerance for unstable APIs
- **📡 Real-time WebSocket Support** - Live monitoring and notifications
- **📊 Comprehensive Telemetry** - Metrics and monitoring out of the box
- **🧪 Extensively Tested** - High test coverage with property-based testing
- **📚 Rich Documentation** - Complete API documentation with examples

## Services Supported

| Service | Description | Status |
|---------|-------------|---------|
| **Perimeter (EASM)** | External Attack Surface Management with A-F security ratings | ✅ Complete |
| **OSINT Intelligence** | 120+ sources for open source intelligence | ✅ Complete |
| **Sandboxed Labs** | Secure code execution environments (Lean4, Smalltalk, etc.) | ✅ Complete |
| **Threat Intelligence** | IOCs, malware analysis, breach detection | ✅ Complete |
| **Compliance Assessment** | NIS2, Czech ZKB compliance frameworks | ✅ Complete |

## Installation

Add `prismatic_sdk` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:prismatic_sdk, "~> 0.1.0"}
  ]
end
```

Then run:

```bash
mix deps.get
```

## Quick Start

### 1. Configure Authentication

```elixir
# Configure in config/config.exs
config :prismatic_sdk,
  api_key: System.get_env("PRISMATIC_API_KEY"),
  base_url: "https://api.prismatic-platform.com"

# Or create client directly
client = PrismaticSDK.Client.new(
  api_key: "pk_live_...",
  timeout: 30_000
)
```

### 2. Discover External Attack Surface

```elixir
# Basic discovery
{:ok, surface} = PrismaticSDK.Perimeter.discover(client, "example.com")

IO.puts("Found #{length(surface.assets.subdomains)} subdomains")
IO.puts("Scan coverage: #{surface.scan_coverage * 100}%")

# Deep discovery with custom options
{:ok, surface} = PrismaticSDK.Perimeter.discover(client, "example.com",
  depth: :deep,
  include: [:domains, :ips, :certificates],
  timeout: 120_000
)
```

### 3. Get Security Rating

```elixir
{:ok, rating} = PrismaticSDK.Perimeter.security_rating(client, "example.com")

IO.puts("Security Grade: #{rating.grade}")
IO.puts("Score: #{rating.score}/900")
IO.puts("Industry Percentile: #{rating.industry_percentile}%")
```

### 4. Run OSINT Investigation

```elixir
# Comprehensive investigation
{:ok, investigation} = PrismaticSDK.OSINT.investigate(client, "example.com",
  sources: [:whois, :dns, :certificates, :shodan],
  timeout: 60_000
)

IO.puts("Investigation ID: #{investigation.id}")
IO.puts("Found #{investigation.total_findings} findings")

# Search specific source
{:ok, results} = PrismaticSDK.OSINT.czech_ares(client, "24138819")
```

### 5. Create Sandboxed Lab Session

```elixir
# Create Lean4 theorem proving environment
{:ok, session} = PrismaticSDK.Labs.create_session(client, %{
  lab_type: :lean4,
  classification_level: :public,
  config: %{timeout_ms: 300_000}
})

# Execute theorem proving
{:ok, execution} = PrismaticSDK.Labs.execute_in_session(client, session.id, %{
  execution_type: "lean4_check",
  input_data: %{
    "operation" => "prove_theorem",
    "theorem" => "2 + 2 = 4",
    "proof" => "by norm_num"
  }
})

IO.inspect(execution.output_data)
# => %{"proof_valid" => true, "qed" => true}
```

### 6. Real-time Monitoring

```elixir
# Define message handler
defmodule MyApp.PerimeterHandler do
  @behaviour PrismaticSDK.Websocket.Handler

  def handle_message(%{event: "monitoring_update", payload: payload}, _state) do
    IO.puts("Perimeter update for #{payload["domain"]}: #{payload["status"]}")
    :ok
  end

  def handle_message(%{event: "alert", payload: %{"severity" => "high"} = payload}, _state) do
    send_notification("High severity alert: #{payload["message"]}")
    :ok
  end

  def handle_message(_message, _state), do: :ok
end

# Connect to real-time updates
{:ok, socket} = PrismaticSDK.Websocket.connect(client,
  topic: "perimeter:monitoring",
  handler: MyApp.PerimeterHandler
)
```

## Authentication

The SDK supports multiple authentication methods:

### API Keys (Recommended)

```elixir
client = PrismaticSDK.Client.new(api_key: "pk_live_...")
```

### JWT Bearer Tokens

```elixir
# Authenticate with credentials
{:ok, token_response} = PrismaticSDK.Auth.authenticate(client, %{
  username: "user@example.com",
  password: "secure_password"
})

# Use the token
client = PrismaticSDK.Client.new(bearer_token: token_response.access_token)
```

### Basic Authentication

```elixir
client = PrismaticSDK.Client.new(basic_auth: {"username", "password"})
```

## Error Handling

All SDK functions return tagged tuples for predictable error handling:

```elixir
case PrismaticSDK.Perimeter.discover(client, "example.com") do
  {:ok, surface} ->
    process_attack_surface(surface)

  {:error, :unauthorized} ->
    Logger.error("Invalid API credentials")

  {:error, :rate_limited} ->
    Logger.warn("Rate limited, retrying later")
    Process.sleep(30_000)
    retry_discovery()

  {:error, :timeout} ->
    Logger.warn("Request timed out")

  {:error, reason} ->
    Logger.error("Discovery failed: #{inspect(reason)}")
end
```

## Rate Limiting

Built-in intelligent rate limiting with automatic retries:

```elixir
# Configure rate limits
client = PrismaticSDK.Client.new(
  api_key: "your-key",
  rate_limit: %{
    requests_per_second: 10,
    burst_size: 50,
    retry_after: 1000
  }
)

# Automatic retry with exponential backoff
result = PrismaticSDK.RateLimit.with_retry("api", rate_config, fn ->
  PrismaticSDK.Perimeter.discover(client, "example.com")
end, max_retries: 3, base_delay_ms: 1000)
```

## Circuit Breaker Protection

Fault tolerance for unreliable services:

```elixir
# Configure circuit breaker
client = PrismaticSDK.Client.new(
  api_key: "your-key",
  circuit_breaker: "api_service"
)

# Automatic fault tolerance
result = PrismaticSDK.CircuitBreaker.call("api_service", fn ->
  make_api_call()
end)
```

## Configuration

```elixir
# config/config.exs
config :prismatic_sdk,
  # Authentication
  api_key: System.get_env("PRISMATIC_API_KEY"),

  # API endpoint
  base_url: "https://api.prismatic-platform.com",

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

# config/runtime.exs (for releases)
config :prismatic_sdk,
  api_key: System.fetch_env!("PRISMATIC_API_KEY")
```

## Telemetry and Monitoring

The SDK emits comprehensive telemetry events:

```elixir
# Subscribe to events
:telemetry.attach("my_handler", [:prismatic_sdk, :client, :request], fn name, measurements, metadata, config ->
  Logger.info("HTTP request to #{metadata.path} took #{measurements.duration}μs")
end, nil)

# Available event patterns
[:prismatic_sdk, :client, :request]           # HTTP requests
[:prismatic_sdk, :websocket, :message_received] # WebSocket messages
[:prismatic_sdk, :rate_limit, :check]         # Rate limit checks
[:prismatic_sdk, :circuit_breaker, :call]     # Circuit breaker calls

# Get current metrics
{:ok, metrics} = PrismaticSDK.Telemetry.get_metrics()
```

## Testing

The SDK includes comprehensive test helpers:

```elixir
# test/support/test_helpers.ex
defmodule MyApp.TestHelpers do
  import PrismaticSDK.TestHelpers

  def setup_mock_client do
    {bypass, client} = setup_bypass()

    mock_health_endpoint(bypass)
    mock_perimeter_discover(bypass, "example.com")

    {bypass, client}
  end
end

# In your tests
test "discovers attack surface" do
  {bypass, client} = MyApp.TestHelpers.setup_mock_client()

  assert {:ok, surface} = PrismaticSDK.Perimeter.discover(client, "example.com")
  assert surface.domain == "example.com"
  assert length(surface.assets.subdomains) > 0
end
```

## Real-world Examples

### Security Monitoring Dashboard

```elixir
defmodule MyApp.SecurityMonitor do
  use GenServer

  def start_link(domains) do
    GenServer.start_link(__MODULE__, domains, name: __MODULE__)
  end

  def init(domains) do
    client = PrismaticSDK.Client.new(api_key: get_api_key())

    # Start monitoring for each domain
    monitors = Enum.map(domains, fn domain ->
      {:ok, monitor_id} = PrismaticSDK.Perimeter.start_monitoring(client, domain,
        check_interval: 60,
        alert_threshold: :medium
      )
      {domain, monitor_id}
    end)

    {:ok, %{client: client, monitors: monitors}}
  end

  def handle_info({:security_alert, domain, severity, details}, state) do
    case severity do
      :high -> send_slack_alert("🚨 High severity alert for #{domain}: #{details}")
      :medium -> send_email_alert("⚠️ Medium severity alert for #{domain}: #{details}")
      _ -> Logger.info("Low severity alert for #{domain}: #{details}")
    end

    {:noreply, state}
  end
end
```

### OSINT Investigation Pipeline

```elixir
defmodule MyApp.OSINTPipeline do
  def investigate_company(company_name) do
    client = PrismaticSDK.Client.new(api_key: get_api_key())

    # Start with business registry search
    with {:ok, business_info} <- PrismaticSDK.OSINT.czech_ares(client, company_name),
         domain <- extract_domain(business_info),
         {:ok, investigation} <- PrismaticSDK.OSINT.investigate(client, domain,
           sources: [:whois, :dns, :certificates, :shodan, :virustotal]
         ),
         {:ok, surface} <- PrismaticSDK.Perimeter.discover(client, domain),
         {:ok, rating} <- PrismaticSDK.Perimeter.security_rating(client, domain) do

      %{
        business: business_info,
        investigation: investigation,
        attack_surface: surface,
        security_rating: rating,
        risk_score: calculate_risk_score(investigation, surface, rating)
      }
    end
  end

  defp calculate_risk_score(investigation, surface, rating) do
    # Custom risk scoring logic
    base_score = (900 - rating.score) / 900.0

    # Increase risk for high-risk findings
    investigation_risk = investigation.findings
    |> Enum.count(&(&1.risk_level in [:high, :critical]))
    |> Kernel./(max(length(investigation.findings), 1))

    # Increase risk for large attack surface
    surface_risk = length(surface.assets.subdomains) / 100.0

    min(base_score + investigation_risk + surface_risk, 1.0)
  end
end
```

### Compliance Reporting

```elixir
defmodule MyApp.ComplianceReporter do
  def generate_monthly_report(tenant_id) do
    client = PrismaticSDK.Client.new(api_key: get_api_key())

    {:ok, organizations} = PrismaticSDK.Perimeter.list_organizations(client, tenant_id)

    reports = Enum.map(organizations, fn org ->
      with {:ok, nis2} <- PrismaticSDK.Perimeter.nis2_compliance(client, org["domain"]),
           {:ok, zkb} <- PrismaticSDK.Perimeter.zkb_compliance(client, org["domain"]),
           {:ok, rating} <- PrismaticSDK.Perimeter.security_rating(client, org["domain"]) do

        %{
          organization: org,
          nis2_compliance: nis2,
          zkb_compliance: zkb,
          security_rating: rating,
          compliance_score: calculate_compliance_score(nis2, zkb),
          recommendations: generate_recommendations(nis2, zkb, rating)
        }
      end
    end)

    # Generate PDF report
    {:ok, pdf_data} = PrismaticSDK.Perimeter.generate_report(client, tenant_id,
      type: :compliance_audit,
      format: :pdf,
      frameworks: [:nis2, :zkb],
      data: reports
    )

    save_report(tenant_id, pdf_data)
  end
end
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](https://hexdocs.pm/prismatic_sdk/)
- 🐛 [Issue Tracker](https://github.com/prismatic-platform/prismatic-sdk-elixir/issues)
- 💬 [Discussions](https://github.com/prismatic-platform/prismatic-sdk-elixir/discussions)
- 📧 [Email Support](mailto:support@prismatic-platform.com)

## Related Projects

- [Prismatic Platform](https://prismatic-platform.com) - The main platform
- [Prismatic Web UI](https://github.com/prismatic-platform/web-ui) - Web interface
- [Prismatic CLI](https://github.com/prismatic-platform/cli) - Command line tools

---

**Built with ❤️ by the Prismatic Platform team**