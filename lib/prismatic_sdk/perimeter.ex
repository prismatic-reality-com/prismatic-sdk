defmodule PrismaticSDK.Perimeter do
  @moduledoc """
  External Attack Surface Management (EASM) API wrapper.

  Provides access to Prismatic Platform's EASM capabilities including:

  - **Asset Discovery** - Domains, IPs, certificates, cloud resources
  - **Security Ratings** - A-F grades with industry benchmarking
  - **Risk Assessment** - Evidence-based risk scoring
  - **Compliance Assessment** - NIS2, Czech ZKB compliance frameworks
  - **Continuous Monitoring** - Real-time attack surface monitoring
  - **Threat Intelligence** - IOCs, malware, dark web monitoring

  ## Usage

      client = PrismaticSDK.Client.new(api_key: "your-api-key")

      # Discover attack surface
      {:ok, surface} = PrismaticSDK.Perimeter.discover(client, "example.com")

      # Get security rating
      {:ok, rating} = PrismaticSDK.Perimeter.security_rating(client, "example.com")

      # Start monitoring
      {:ok, monitor_id} = PrismaticSDK.Perimeter.start_monitoring(client, "example.com",
        check_interval: 60,
        alert_threshold: :medium
      )

  """

  alias PrismaticSDK.Client

  @type client :: Client.t()
  @type domain :: String.t()
  @type discovery_opts :: keyword()
  @type monitoring_opts :: keyword()
  @type compliance_framework :: :nis2 | :zkb
  @type security_grade :: :A | :B | :C | :D | :F
  @type risk_level :: :minimal | :low | :medium | :high | :critical

  @type attack_surface :: %{
    domain: domain(),
    assets: map(),
    scan_coverage: float(),
    discovered_at: DateTime.t()
  }

  @type security_rating :: %{
    grade: security_grade(),
    score: integer(),
    breakdown: map(),
    industry_percentile: integer(),
    timestamp: DateTime.t()
  }

  @type risk_assessment :: %{
    score: float(),
    level: risk_level(),
    factors: [map()],
    confidence: float(),
    trend: atom()
  }

  # ============================================================================
  # Discovery API
  # ============================================================================

  @doc """
  Discovers external attack surface for a domain or organization.

  ## Options

  - `:depth` - Discovery depth (`:shallow`, `:standard`, `:deep`). Default: `:standard`
  - `:include` - Asset types to include. Default: `[:domains, :ips, :certs, :cloud]`
  - `:timeout` - Discovery timeout in milliseconds. Default: 60_000
  - `:tenant_id` - Tenant context for multi-tenant isolation

  ## Examples

      {:ok, surface} = PrismaticSDK.Perimeter.discover(client, "example.com")

      {:ok, surface} = PrismaticSDK.Perimeter.discover(client, "example.com",
        depth: :deep,
        include: [:domains, :ips, :certificates],
        timeout: 120_000
      )

  ## Response

      {:ok, %{
        domain: "example.com",
        assets: %{
          domains: ["api.example.com", "cdn.example.com"],
          subdomains: ["www.example.com", "blog.example.com"],
          ip_addresses: ["203.0.113.1", "203.0.113.2"],
          certificates: [%{...}],
          services: [%{...}]
        },
        scan_coverage: 0.95,
        discovered_at: ~U[2026-02-21 10:30:00Z]
      }}

  """
  @spec discover(client(), domain(), discovery_opts()) ::
          {:ok, attack_surface()} | {:error, term()}
  def discover(client, domain, opts \\ []) do
    params = %{domain: domain}
    |> maybe_put(:depth, opts[:depth])
    |> maybe_put(:include, opts[:include])
    |> maybe_put(:timeout, opts[:timeout])
    |> maybe_put(:tenant_id, opts[:tenant_id])

    case Client.post(client, "/api/v1/perimeter/discover", params) do
      {:ok, response} -> {:ok, parse_attack_surface(response)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Gets the current attack surface for a monitored domain.

  ## Examples

      {:ok, surface} = PrismaticSDK.Perimeter.get_attack_surface(client, "example.com")

  """
  @spec get_attack_surface(client(), domain()) ::
          {:ok, attack_surface()} | {:error, term()}
  def get_attack_surface(client, domain) do
    case Client.get(client, "/api/v1/perimeter/surface", %{domain: domain}) do
      {:ok, response} -> {:ok, parse_attack_surface(response)}
      {:error, reason} -> {:error, reason}
    end
  end

  # ============================================================================
  # Certificate Discovery API
  # ============================================================================

  @doc """
  Discovers certificates for a domain using Certificate Transparency logs.

  ## Options

  - `:depth` - Discovery depth (`:basic`, `:standard`, `:deep`)
  - `:include_expired` - Include expired certificates (default: false)
  - `:include_subdomains` - Include subdomain certificates (default: true)
  - `:max_age_days` - Maximum certificate age in days (default: 365)

  ## Examples

      {:ok, certificates} = PrismaticSDK.Perimeter.discover_certificates(client, "example.com")

      {:ok, certificates} = PrismaticSDK.Perimeter.discover_certificates(client, "example.com",
        depth: :deep,
        include_expired: true,
        max_age_days: 90
      )

  """
  @spec discover_certificates(client(), domain(), keyword()) ::
          {:ok, [map()]} | {:error, term()}
  def discover_certificates(client, domain, opts \\ []) do
    params = %{domain: domain}
    |> maybe_put(:depth, opts[:depth])
    |> maybe_put(:include_expired, opts[:include_expired])
    |> maybe_put(:include_subdomains, opts[:include_subdomains])
    |> maybe_put(:max_age_days, opts[:max_age_days])

    case Client.post(client, "/api/v1/perimeter/certificates/discover", params) do
      {:ok, %{"certificates" => certificates}} -> {:ok, certificates}
      {:ok, certificates} when is_list(certificates) -> {:ok, certificates}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Analyzes a certificate for security and compliance issues.

  ## Examples

      {:ok, analysis} = PrismaticSDK.Perimeter.analyze_certificate(client, certificate)

  """
  @spec analyze_certificate(client(), map()) :: {:ok, map()} | {:error, term()}
  def analyze_certificate(client, certificate) do
    Client.post(client, "/api/v1/perimeter/certificates/analyze", %{certificate: certificate})
  end

  # ============================================================================
  # Monitoring API
  # ============================================================================

  @doc """
  Starts continuous monitoring for a domain's attack surface.

  ## Options

  - `:check_interval` - Minutes between checks. Default: 60
  - `:alert_threshold` - Minimum risk level for alerts. Default: `:medium`
  - `:webhook_url` - URL for alert webhooks
  - `:email_alerts` - List of email addresses for alerts
  - `:tenant_id` - Tenant context

  ## Examples

      {:ok, monitor_id} = PrismaticSDK.Perimeter.start_monitoring(client, "example.com",
        check_interval: 30,
        alert_threshold: :high,
        webhook_url: "https://hooks.example.com/perimeter"
      )

  """
  @spec start_monitoring(client(), domain(), monitoring_opts()) ::
          {:ok, String.t()} | {:error, term()}
  def start_monitoring(client, domain, opts \\ []) do
    params = %{domain: domain}
    |> maybe_put(:check_interval, opts[:check_interval])
    |> maybe_put(:alert_threshold, opts[:alert_threshold])
    |> maybe_put(:webhook_url, opts[:webhook_url])
    |> maybe_put(:email_alerts, opts[:email_alerts])
    |> maybe_put(:tenant_id, opts[:tenant_id])

    case Client.post(client, "/api/v1/perimeter/monitoring/start", params) do
      {:ok, %{"monitor_id" => monitor_id}} -> {:ok, monitor_id}
      {:ok, %{"id" => monitor_id}} -> {:ok, monitor_id}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Stops monitoring for a given monitor ID.

  ## Examples

      :ok = PrismaticSDK.Perimeter.stop_monitoring(client, monitor_id)

  """
  @spec stop_monitoring(client(), String.t()) :: :ok | {:error, term()}
  def stop_monitoring(client, monitor_id) do
    case Client.delete(client, "/api/v1/perimeter/monitoring/#{monitor_id}") do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Gets monitoring status for a monitor ID.

  ## Examples

      {:ok, status} = PrismaticSDK.Perimeter.get_monitoring_status(client, monitor_id)

  """
  @spec get_monitoring_status(client(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_monitoring_status(client, monitor_id) do
    Client.get(client, "/api/v1/perimeter/monitoring/#{monitor_id}/status")
  end

  # ============================================================================
  # Risk Scoring API
  # ============================================================================

  @doc """
  Calculates unified risk score for a domain.

  Aggregates evidence from:
  - Attack surface findings
  - Threat intelligence matches
  - Vulnerability data
  - Compliance gaps
  - Historical trends

  ## Options

  - `:frameworks` - Compliance frameworks to include. Default: `[:nis2, :zkb]`
  - `:include_trends` - Include temporal trend analysis. Default: true

  ## Examples

      {:ok, risk} = PrismaticSDK.Perimeter.assess_risk(client, "example.com")

      {:ok, risk} = PrismaticSDK.Perimeter.assess_risk(client, "example.com",
        frameworks: [:nis2],
        include_trends: false
      )

  ## Response

      {:ok, %{
        score: 0.42,
        level: :medium,
        factors: [
          %{type: "exposed_service", severity: :high, weight: 0.3},
          %{type: "certificate_issue", severity: :medium, weight: 0.1}
        ],
        confidence: 0.87,
        trend: :improving
      }}

  """
  @spec assess_risk(client(), domain(), keyword()) ::
          {:ok, risk_assessment()} | {:error, term()}
  def assess_risk(client, domain, opts \\ []) do
    params = %{domain: domain}
    |> maybe_put(:frameworks, opts[:frameworks])
    |> maybe_put(:include_trends, opts[:include_trends])

    case Client.post(client, "/api/v1/perimeter/risk/assess", params) do
      {:ok, response} -> {:ok, parse_risk_assessment(response)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Returns security rating (A-F grade) for a domain.

  Compatible with industry-standard security rating systems.

  ## Examples

      {:ok, rating} = PrismaticSDK.Perimeter.security_rating(client, "example.com")

  ## Response

      {:ok, %{
        grade: :B,
        score: 720,
        breakdown: %{
          network_security: 750,
          application_security: 680,
          patching_cadence: 720,
          dns_email_security: 800,
          ip_reputation: 650,
          ssl_tls: 900,
          endpoint_security: 700
        },
        industry_percentile: 68,
        timestamp: ~U[2026-02-21 10:30:00Z]
      }}

  """
  @spec security_rating(client(), domain(), keyword()) ::
          {:ok, security_rating()} | {:error, term()}
  def security_rating(client, domain, opts \\ []) do
    params = %{domain: domain}
    |> maybe_put_all(opts)

    case Client.get(client, "/api/v1/perimeter/rating", params) do
      {:ok, response} -> {:ok, parse_security_rating(response)}
      {:error, reason} -> {:error, reason}
    end
  end

  # ============================================================================
  # Compliance API
  # ============================================================================

  @doc """
  Assesses compliance against specified frameworks.

  ## Supported Frameworks

  - `:nis2` - EU NIS2 Directive (Directive 2022/2555)
  - `:zkb` - Czech ZKB 264/2025 Sb. (Cybersecurity Act)

  ## Examples

      {:ok, assessment} = PrismaticSDK.Perimeter.assess_compliance(client, "example.com", [:nis2])

      {:ok, assessment} = PrismaticSDK.Perimeter.assess_compliance(client, "example.com", [:nis2, :zkb],
        include_recommendations: true
      )

  """
  @spec assess_compliance(client(), domain(), [compliance_framework()], keyword()) ::
          {:ok, map()} | {:error, term()}
  def assess_compliance(client, domain, frameworks, opts \\ []) do
    params = %{
      domain: domain,
      frameworks: frameworks
    }
    |> maybe_put(:include_recommendations, opts[:include_recommendations])

    Client.post(client, "/api/v1/perimeter/compliance/assess", params)
  end

  @doc """
  Returns NIS2 compliance status for a domain.

  ## Examples

      {:ok, compliance} = PrismaticSDK.Perimeter.nis2_compliance(client, "example.com")

  """
  @spec nis2_compliance(client(), domain(), keyword()) :: {:ok, map()} | {:error, term()}
  def nis2_compliance(client, domain, opts \\ []) do
    assess_compliance(client, domain, [:nis2], opts)
  end

  @doc """
  Returns ZKB 264/2025 Sb. compliance status for a domain.

  ## Examples

      {:ok, compliance} = PrismaticSDK.Perimeter.zkb_compliance(client, "example.com")

  """
  @spec zkb_compliance(client(), domain(), keyword()) :: {:ok, map()} | {:error, term()}
  def zkb_compliance(client, domain, opts \\ []) do
    assess_compliance(client, domain, [:zkb], opts)
  end

  # ============================================================================
  # Threat Intelligence API
  # ============================================================================

  @doc """
  Queries threat intelligence for a domain's assets.

  ## Examples

      {:ok, threats} = PrismaticSDK.Perimeter.threat_intelligence(client, "example.com")

  ## Response

      {:ok, %{
        iocs: [
          %{type: "ip", value: "198.51.100.1", severity: :high, source: "malware_db"},
          %{type: "domain", value: "malicious.example.com", severity: :medium, source: "blocklist"}
        ],
        threat_actors: [
          %{name: "APT29", confidence: 0.8, last_seen: ~U[2026-02-20 15:30:00Z]}
        ],
        vulnerabilities: [
          %{cve: "CVE-2024-1234", severity: :critical, affected_assets: ["api.example.com"]}
        ],
        dark_web_mentions: [
          %{mention: "Database leak from example.com", confidence: 0.6, source: "forum_xyz"}
        ]
      }}

  """
  @spec threat_intelligence(client(), domain(), keyword()) :: {:ok, map()} | {:error, term()}
  def threat_intelligence(client, domain, opts \\ []) do
    params = %{domain: domain}
    |> maybe_put_all(opts)

    Client.get(client, "/api/v1/perimeter/threat-intelligence", params)
  end

  # ============================================================================
  # Reporting API
  # ============================================================================

  @doc """
  Generates compliance report for a domain.

  ## Report Types

  - `:executive_summary` - High-level overview for leadership
  - `:technical_detail` - Detailed findings for security teams
  - `:compliance_audit` - Regulatory compliance documentation
  - `:third_party_risk` - Third-party risk assessment

  ## Formats

  - `:html` - HTML report
  - `:pdf` - PDF document
  - `:json` - JSON data

  ## Examples

      {:ok, report} = PrismaticSDK.Perimeter.generate_report(client, "example.com",
        type: :compliance_audit,
        format: :pdf,
        frameworks: [:nis2, :zkb]
      )

  """
  @spec generate_report(client(), domain(), keyword()) :: {:ok, map()} | {:error, term()}
  def generate_report(client, domain, opts \\ []) do
    params = %{domain: domain}
    |> maybe_put(:type, opts[:type])
    |> maybe_put(:format, opts[:format])
    |> maybe_put(:frameworks, opts[:frameworks])

    Client.post(client, "/api/v1/perimeter/reports/generate", params)
  end

  # ============================================================================
  # Tenant API
  # ============================================================================

  @doc """
  Creates a new tenant for multi-tenant isolation.

  ## Examples

      {:ok, tenant} = PrismaticSDK.Perimeter.create_tenant(client, %{
        name: "Acme Corp Security",
        settings: %{
          alert_threshold: :high,
          check_interval: 30
        }
      })

  """
  @spec create_tenant(client(), map()) :: {:ok, map()} | {:error, term()}
  def create_tenant(client, attrs) do
    Client.post(client, "/api/v1/perimeter/tenants", attrs)
  end

  @doc """
  Lists organizations for a tenant.

  ## Examples

      {:ok, organizations} = PrismaticSDK.Perimeter.list_organizations(client, tenant_id)

  """
  @spec list_organizations(client(), String.t()) :: {:ok, [map()]} | {:error, term()}
  def list_organizations(client, tenant_id) do
    case Client.get(client, "/api/v1/perimeter/tenants/#{tenant_id}/organizations") do
      {:ok, %{"organizations" => orgs}} when is_list(orgs) -> {:ok, orgs}
      {:ok, orgs} when is_list(orgs) -> {:ok, orgs}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Adds an organization to a tenant.

  ## Examples

      {:ok, organization} = PrismaticSDK.Perimeter.add_organization(client, tenant_id, %{
        domain: "example.com",
        name: "Example Corp"
      })

  """
  @spec add_organization(client(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def add_organization(client, tenant_id, attrs) do
    Client.post(client, "/api/v1/perimeter/tenants/#{tenant_id}/organizations", attrs)
  end

  # ============================================================================
  # Dashboard API
  # ============================================================================

  @doc """
  Retrieves comprehensive dashboard metrics for a tenant's security posture.

  ## Examples

      {:ok, metrics} = PrismaticSDK.Perimeter.dashboard_metrics(client, tenant_id)

  ## Response

      {:ok, %{
        summary: %{
          total_domains: 15,
          monitored_domains: 12,
          average_security_score: 725,
          overall_grade: :B,
          risk_level: :medium
        },
        security_ratings: %{A: 2, B: 5, C: 4, D: 1, F: 0},
        risk_metrics: %{
          average_score: 0.42,
          trend: :improving,
          high_risk_domains: 3,
          critical_findings: 7
        },
        monitoring: %{
          active_monitors: 12,
          last_scan: ~U[2026-02-21 10:30:00Z],
          alerts_24h: 3,
          changes_detected: 5
        },
        compliance: %{
          nis2_compliant: 8,
          nis2_non_compliant: 4,
          zkb_compliant: 7,
          zkb_non_compliant: 5
        },
        threat_intel: %{
          active_iocs: 15,
          new_threats_7d: 3,
          resolved_threats_7d: 5
        },
        timestamp: ~U[2026-02-21 12:00:00Z]
      }}

  """
  @spec dashboard_metrics(client(), String.t()) :: {:ok, map()} | {:error, term()}
  def dashboard_metrics(client, tenant_id) do
    Client.get(client, "/api/v1/perimeter/tenants/#{tenant_id}/dashboard")
  end

  # Private helper functions

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp maybe_put_all(map, opts) do
    Enum.reduce(opts, map, fn {key, value}, acc ->
      maybe_put(acc, key, value)
    end)
  end

  defp parse_attack_surface(response) do
    %{
      domain: response["domain"],
      assets: response["assets"] || %{},
      scan_coverage: response["scan_coverage"] || 0.0,
      discovered_at: parse_datetime(response["discovered_at"])
    }
  end

  defp parse_security_rating(response) do
    %{
      grade: String.to_existing_atom(response["grade"]),
      score: response["score"],
      breakdown: response["breakdown"] || %{},
      industry_percentile: response["industry_percentile"] || 0,
      timestamp: parse_datetime(response["timestamp"])
    }
  end

  defp parse_risk_assessment(response) do
    %{
      score: response["score"],
      level: String.to_existing_atom(response["level"]),
      factors: response["factors"] || [],
      confidence: response["confidence"] || 0.0,
      trend: if(response["trend"], do: String.to_existing_atom(response["trend"]), else: :unknown)
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