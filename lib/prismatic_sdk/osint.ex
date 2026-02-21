defmodule PrismaticSDK.OSINT do
  @moduledoc """
  Open Source Intelligence (OSINT) API wrapper.

  Provides access to 120+ OSINT sources including:

  - **Czech Sources** - ARES, Justice, ISIR, Commercial Register
  - **Global Sources** - Shodan, VirusTotal, Censys, Hunter.io
  - **Sanctions Lists** - EU, OFAC SDN, UN sanctions
  - **Business Registries** - EU, UK Companies House, US SEC EDGAR
  - **Social Media** - LinkedIn, Twitter, Facebook intelligence
  - **Technical Analysis** - DNS, WHOIS, certificates, infrastructure

  ## Usage

      client = PrismaticSDK.Client.new(api_key: "your-api-key")

      # Run investigation across multiple sources
      {:ok, findings} = PrismaticSDK.OSINT.investigate(client, "example.com",
        sources: [:whois, :dns, :certificates, :shodan]
      )

      # Search specific provider
      {:ok, results} = PrismaticSDK.OSINT.search(client, :czech_ares, "24138819")

      # Get available sources
      {:ok, sources} = PrismaticSDK.OSINT.list_sources(client)

  """

  alias PrismaticSDK.Client

  @type client :: Client.t()
  @type target :: String.t()
  @type source_name :: atom() | String.t()
  @type investigation_opts :: keyword()
  @type search_opts :: keyword()

  @type finding :: %{
    id: String.t(),
    title: String.t(),
    snippet: String.t() | nil,
    category: atom(),
    source_type: atom(),
    source_ref: String.t() | nil,
    risk_level: atom(),
    confidence: float(),
    metadata: map(),
    timestamp: DateTime.t()
  }

  @type investigation_result :: %{
    id: String.t(),
    target: target(),
    findings: [finding()],
    sources_used: [source_name()],
    total_findings: integer(),
    started_at: DateTime.t(),
    completed_at: DateTime.t(),
    status: atom()
  }

  # ============================================================================
  # Investigation API
  # ============================================================================

  @doc """
  Runs a comprehensive OSINT investigation against a target.

  ## Options

  - `:sources` - List of sources to query (default: automatic selection)
  - `:max_sources` - Maximum number of sources to use (default: 10)
  - `:timeout` - Investigation timeout in milliseconds (default: 300_000)
  - `:parallel` - Run sources in parallel (default: true)
  - `:categories` - Filter by finding categories
  - `:min_confidence` - Minimum confidence threshold (0.0-1.0)

  ## Examples

      # Full investigation with automatic source selection
      {:ok, results} = PrismaticSDK.OSINT.investigate(client, "example.com")

      # Targeted investigation with specific sources
      {:ok, results} = PrismaticSDK.OSINT.investigate(client, "example.com",
        sources: [:whois, :dns, :certificates, :shodan, :virustotal],
        timeout: 60_000,
        min_confidence: 0.7
      )

      # Czech business investigation
      {:ok, results} = PrismaticSDK.OSINT.investigate(client, "24138819",
        sources: [:czech_ares, :czech_justice, :czech_isir],
        categories: [:legal, :financial]
      )

  ## Response

      {:ok, %{
        id: "inv_1234567890",
        target: "example.com",
        findings: [
          %{
            id: "find_001",
            title: "Domain Registration Information",
            snippet: "Registered to Example Corp in 2020",
            category: :technical,
            source_type: :registry,
            source_ref: "https://whois.net/...",
            risk_level: :low,
            confidence: 0.95,
            metadata: %{registrar: "Namecheap", created: "2020-01-15"},
            timestamp: ~U[2026-02-21 10:30:00Z]
          }
        ],
        sources_used: [:whois, :dns, :certificates],
        total_findings: 15,
        started_at: ~U[2026-02-21 10:30:00Z],
        completed_at: ~U[2026-02-21 10:32:00Z],
        status: :completed
      }}

  """
  @spec investigate(client(), target(), investigation_opts()) ::
          {:ok, investigation_result()} | {:error, term()}
  def investigate(client, target, opts \\ []) do
    params = %{target: target}
    |> maybe_put(:sources, opts[:sources])
    |> maybe_put(:max_sources, opts[:max_sources])
    |> maybe_put(:timeout, opts[:timeout])
    |> maybe_put(:parallel, opts[:parallel])
    |> maybe_put(:categories, opts[:categories])
    |> maybe_put(:min_confidence, opts[:min_confidence])

    case Client.post(client, "/api/v1/osint/investigate", params) do
      {:ok, response} -> {:ok, parse_investigation_result(response)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Gets the status of an ongoing investigation.

  ## Examples

      {:ok, status} = PrismaticSDK.OSINT.investigation_status(client, investigation_id)

  """
  @spec investigation_status(client(), String.t()) :: {:ok, map()} | {:error, term()}
  def investigation_status(client, investigation_id) do
    Client.get(client, "/api/v1/osint/investigations/#{investigation_id}")
  end

  @doc """
  Lists recent investigations.

  ## Options

  - `:limit` - Maximum number of investigations to return (default: 50)
  - `:status` - Filter by status (`:pending`, `:running`, `:completed`, `:failed`)
  - `:target` - Filter by target

  ## Examples

      {:ok, investigations} = PrismaticSDK.OSINT.list_investigations(client, limit: 20)

  """
  @spec list_investigations(client(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_investigations(client, opts \\ []) do
    params = %{}
    |> maybe_put(:limit, opts[:limit])
    |> maybe_put(:status, opts[:status])
    |> maybe_put(:target, opts[:target])

    case Client.get(client, "/api/v1/osint/investigations", params) do
      {:ok, %{"investigations" => investigations}} -> {:ok, investigations}
      {:ok, investigations} when is_list(investigations) -> {:ok, investigations}
      {:error, reason} -> {:error, reason}
    end
  end

  # ============================================================================
  # Source-Specific Search API
  # ============================================================================

  @doc """
  Searches a specific OSINT source.

  ## Examples

      # Czech ARES business registry
      {:ok, results} = PrismaticSDK.OSINT.search(client, :czech_ares, "24138819")

      # Shodan IP/port search
      {:ok, results} = PrismaticSDK.OSINT.search(client, :shodan, "apache",
        filters: %{country: "US", port: 80}
      )

      # VirusTotal file hash
      {:ok, results} = PrismaticSDK.OSINT.search(client, :virustotal, "sha256_hash")

  """
  @spec search(client(), source_name(), String.t(), search_opts()) ::
          {:ok, map()} | {:error, term()}
  def search(client, source, query, opts \\ []) do
    params = %{
      source: to_string(source),
      query: query
    }
    |> maybe_put_all(opts)

    Client.post(client, "/api/v1/osint/search", params)
  end

  @doc """
  Gets detailed information from a source using an ID.

  ## Examples

      {:ok, details} = PrismaticSDK.OSINT.get_details(client, :czech_ares, "24138819")

  """
  @spec get_details(client(), source_name(), String.t(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def get_details(client, source, source_id, opts \\ []) do
    params = %{
      source: to_string(source),
      source_id: source_id
    }
    |> maybe_put_all(opts)

    Client.get(client, "/api/v1/osint/details", params)
  end

  # ============================================================================
  # Sources Management API
  # ============================================================================

  @doc """
  Lists all available OSINT sources.

  ## Options

  - `:category` - Filter by category (`:czech`, `:global`, `:sanctions`, etc.)
  - `:active_only` - Only return active sources (default: true)

  ## Examples

      {:ok, sources} = PrismaticSDK.OSINT.list_sources(client)

      {:ok, czech_sources} = PrismaticSDK.OSINT.list_sources(client, category: :czech)

  ## Response

      {:ok, [
        %{
          name: "czech_ares",
          display_name: "Czech ARES Business Registry",
          category: :czech,
          description: "Official Czech business registry with company information",
          supported_queries: [:ico, :name, :address],
          rate_limit: %{requests_per_minute: 60},
          active: true
        },
        %{
          name: "shodan",
          display_name: "Shodan Internet Intelligence",
          category: :global,
          description: "Search engine for Internet-connected devices",
          supported_queries: [:ip, :hostname, :service, :product],
          rate_limit: %{requests_per_minute: 100},
          active: true
        }
      ]}

  """
  @spec list_sources(client(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_sources(client, opts \\ []) do
    params = %{}
    |> maybe_put(:category, opts[:category])
    |> maybe_put(:active_only, opts[:active_only])

    case Client.get(client, "/api/v1/osint/sources", params) do
      {:ok, %{"sources" => sources}} -> {:ok, sources}
      {:ok, sources} when is_list(sources) -> {:ok, sources}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Gets information about a specific OSINT source.

  ## Examples

      {:ok, source_info} = PrismaticSDK.OSINT.get_source_info(client, :czech_ares)

  """
  @spec get_source_info(client(), source_name()) :: {:ok, map()} | {:error, term()}
  def get_source_info(client, source) do
    Client.get(client, "/api/v1/osint/sources/#{source}")
  end

  @doc """
  Checks the health status of OSINT sources.

  ## Examples

      {:ok, health} = PrismaticSDK.OSINT.sources_health(client)

  ## Response

      {:ok, %{
        total_sources: 120,
        active_sources: 118,
        degraded_sources: 2,
        failed_sources: 0,
        source_status: [
          %{name: "czech_ares", status: :healthy, last_check: ~U[2026-02-21 10:30:00Z]},
          %{name: "shodan", status: :degraded, last_check: ~U[2026-02-21 10:29:00Z], error: "Rate limited"}
        ]
      }}

  """
  @spec sources_health(client()) :: {:ok, map()} | {:error, term()}
  def sources_health(client) do
    Client.get(client, "/api/v1/osint/sources/health")
  end

  # ============================================================================
  # Czech OSINT Sources
  # ============================================================================

  @doc """
  Searches Czech ARES business registry.

  ## Examples

      # Search by IČO (company ID)
      {:ok, company} = PrismaticSDK.OSINT.czech_ares(client, "24138819")

      # Search by company name
      {:ok, results} = PrismaticSDK.OSINT.czech_ares(client, "Example s.r.o.")

  """
  @spec czech_ares(client(), String.t()) :: {:ok, map()} | {:error, term()}
  def czech_ares(client, query) do
    search(client, :czech_ares, query)
  end

  @doc """
  Searches Czech Justice Ministry registry (commercial court records).

  ## Examples

      {:ok, court_records} = PrismaticSDK.OSINT.czech_justice(client, "Example s.r.o.")

  """
  @spec czech_justice(client(), String.t()) :: {:ok, map()} | {:error, term()}
  def czech_justice(client, query) do
    search(client, :czech_justice, query)
  end

  @doc """
  Searches Czech ISIR insolvency registry.

  ## Examples

      {:ok, insolvency_records} = PrismaticSDK.OSINT.czech_isir(client, "24138819")

  """
  @spec czech_isir(client(), String.t()) :: {:ok, map()} | {:error, term()}
  def czech_isir(client, query) do
    search(client, :czech_isir, query)
  end

  # ============================================================================
  # Global OSINT Sources
  # ============================================================================

  @doc """
  Searches Shodan for Internet-connected devices.

  ## Examples

      # Search by IP address
      {:ok, host_info} = PrismaticSDK.OSINT.shodan(client, "8.8.8.8")

      # Search by service/product
      {:ok, results} = PrismaticSDK.OSINT.shodan(client, "apache",
        filters: %{country: "CZ", port: 80}
      )

  """
  @spec shodan(client(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def shodan(client, query, opts \\ []) do
    search(client, :shodan, query, opts)
  end

  @doc """
  Searches VirusTotal for malware and URL analysis.

  ## Examples

      # File hash lookup
      {:ok, analysis} = PrismaticSDK.OSINT.virustotal(client, "sha256_hash")

      # URL analysis
      {:ok, analysis} = PrismaticSDK.OSINT.virustotal(client, "https://example.com/suspicious")

  """
  @spec virustotal(client(), String.t()) :: {:ok, map()} | {:error, term()}
  def virustotal(client, query) do
    search(client, :virustotal, query)
  end

  @doc """
  Searches Hunter.io for email addresses and domains.

  ## Examples

      # Find email addresses for a domain
      {:ok, emails} = PrismaticSDK.OSINT.hunter_io(client, "example.com")

  """
  @spec hunter_io(client(), String.t()) :: {:ok, map()} | {:error, term()}
  def hunter_io(client, domain) do
    search(client, :hunter_io, domain)
  end

  # ============================================================================
  # Utility Functions
  # ============================================================================

  @doc """
  Validates a target for OSINT investigation.

  Checks if the target format is supported and valid.

  ## Examples

      {:ok, :domain} = PrismaticSDK.OSINT.validate_target(client, "example.com")
      {:ok, :ip} = PrismaticSDK.OSINT.validate_target(client, "192.168.1.1")
      {:ok, :email} = PrismaticSDK.OSINT.validate_target(client, "user@example.com")
      {:error, :invalid_format} = PrismaticSDK.OSINT.validate_target(client, "not-valid")

  """
  @spec validate_target(client(), target()) :: {:ok, atom()} | {:error, term()}
  def validate_target(client, target) do
    params = %{target: target}

    case Client.post(client, "/api/v1/osint/validate", params) do
      {:ok, %{"valid" => true, "type" => type}} -> {:ok, String.to_existing_atom(type)}
      {:ok, %{"valid" => false, "reason" => reason}} -> {:error, String.to_existing_atom(reason)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Gets OSINT investigation statistics.

  ## Examples

      {:ok, stats} = PrismaticSDK.OSINT.get_statistics(client)

  ## Response

      {:ok, %{
        total_investigations: 1250,
        investigations_today: 45,
        total_findings: 23456,
        sources_queried: 89,
        success_rate: 0.95,
        average_investigation_time_ms: 12500,
        top_sources: [
          %{name: "whois", usage_count: 234, success_rate: 0.98},
          %{name: "dns", usage_count: 198, success_rate: 0.97}
        ]
      }}

  """
  @spec get_statistics(client()) :: {:ok, map()} | {:error, term()}
  def get_statistics(client) do
    Client.get(client, "/api/v1/osint/statistics")
  end

  # Private helper functions

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp maybe_put_all(map, opts) do
    Enum.reduce(opts, map, fn {key, value}, acc ->
      maybe_put(acc, key, value)
    end)
  end

  defp parse_investigation_result(response) do
    %{
      id: response["id"],
      target: response["target"],
      findings: Enum.map(response["findings"] || [], &parse_finding/1),
      sources_used: response["sources_used"] || [],
      total_findings: response["total_findings"] || 0,
      started_at: parse_datetime(response["started_at"]),
      completed_at: parse_datetime(response["completed_at"]),
      status: String.to_existing_atom(response["status"] || "unknown")
    }
  end

  defp parse_finding(finding_data) do
    %{
      id: finding_data["id"],
      title: finding_data["title"],
      snippet: finding_data["snippet"],
      category: String.to_existing_atom(finding_data["category"] || "unknown"),
      source_type: String.to_existing_atom(finding_data["source_type"] || "unknown"),
      source_ref: finding_data["source_ref"],
      risk_level: String.to_existing_atom(finding_data["risk_level"] || "low"),
      confidence: finding_data["confidence"] || 0.0,
      metadata: finding_data["metadata"] || %{},
      timestamp: parse_datetime(finding_data["timestamp"])
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