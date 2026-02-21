defmodule PrismaticSDK.TestHelpers do
  @moduledoc """
  Helper functions for SDK tests.
  """

  import ExUnit.Assertions

  alias PrismaticSDK.Client

  @doc """
  Creates a test client with default configuration.
  """
  def test_client(opts \\ []) do
    default_opts = [
      api_key: "test_key_123",
      base_url: "http://localhost:#{bypass_port(opts)}"
    ]

    opts = Keyword.merge(default_opts, opts)
    Client.new(opts)
  end

  @doc """
  Sets up a Bypass server for HTTP mocking.
  """
  def setup_bypass do
    bypass = Bypass.open()
    client = test_client(bypass_port: bypass.port)
    {bypass, client}
  end

  @doc """
  Creates mock HTTP responses for common endpoints.
  """
  def mock_health_endpoint(bypass) do
    Bypass.expect(bypass, "GET", "/api/v1/health", fn conn ->
      response = %{
        status: "healthy",
        version: "0.1.0",
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
      }
      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)
  end

  def mock_auth_endpoint(bypass, opts \\ []) do
    status = Keyword.get(opts, :status, 200)
    response = Keyword.get(opts, :response, %{id: "user_123", email: "test@example.com"})

    Bypass.expect(bypass, "GET", "/api/v1/auth/user", fn conn ->
      Plug.Conn.resp(conn, status, Jason.encode!(response))
    end)
  end

  def mock_perimeter_discover(bypass, domain \\ "example.com") do
    Bypass.expect(bypass, "POST", "/api/v1/perimeter/discover", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      body_data = Jason.decode!(body)

      assert body_data["domain"] == domain

      response = %{
        domain: domain,
        assets: %{
          domains: ["www.#{domain}", "api.#{domain}"],
          subdomains: ["blog.#{domain}", "cdn.#{domain}"],
          ip_addresses: ["203.0.113.1", "203.0.113.2"],
          certificates: [],
          services: []
        },
        scan_coverage: 0.95,
        discovered_at: DateTime.utc_now() |> DateTime.to_iso8601()
      }

      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)
  end

  def mock_osint_investigate(bypass, target \\ "example.com") do
    Bypass.expect(bypass, "POST", "/api/v1/osint/investigate", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      body_data = Jason.decode!(body)

      assert body_data["target"] == target

      response = %{
        id: "inv_#{:rand.uniform(1000000)}",
        target: target,
        findings: [
          %{
            id: "find_001",
            title: "Domain Registration Information",
            snippet: "Registered to Example Corp in 2020",
            category: "technical",
            source_type: "registry",
            source_ref: "https://whois.net/#{target}",
            risk_level: "low",
            confidence: 0.95,
            metadata: %{registrar: "Namecheap", created: "2020-01-15"},
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
          }
        ],
        sources_used: ["whois", "dns"],
        total_findings: 1,
        started_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        completed_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        status: "completed"
      }

      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)
  end

  def mock_labs_create_session(bypass) do
    Bypass.expect(bypass, "POST", "/api/v1/labs/sessions", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      body_data = Jason.decode!(body)

      response = %{
        id: "sess_#{:rand.uniform(1000000)}",
        user_id: "user_123",
        lab_type: body_data["lab_type"],
        classification_level: body_data["classification_level"],
        status: "active",
        config: body_data["config"] || %{},
        state: %{},
        resource_usage: %{memory_bytes: 0},
        started_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        last_activity_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        expires_at: DateTime.add(DateTime.utc_now(), 3600, :second) |> DateTime.to_iso8601()
      }

      Plug.Conn.resp(conn, 201, Jason.encode!(response))
    end)
  end

  @doc """
  Waits for an async operation to complete.
  """
  def wait_until(fun, timeout \\ 5000) when is_function(fun, 0) do
    wait_until(fun, timeout, 100)
  end

  defp wait_until(fun, timeout, interval) when timeout > 0 do
    if fun.() do
      :ok
    else
      Process.sleep(interval)
      wait_until(fun, timeout - interval, interval)
    end
  end

  defp wait_until(_fun, _timeout, _interval) do
    :timeout
  end

  @doc """
  Captures telemetry events for testing.
  """
  def capture_telemetry_events(event_names, fun) when is_list(event_names) and is_function(fun, 0) do
    test_pid = self()
    ref = make_ref()
    events = []

    handler_id = "test-handler-#{:rand.uniform(1000000)}"

    :telemetry.attach_many(
      handler_id,
      event_names,
      fn name, measurements, metadata, _config ->
        send(test_pid, {ref, {name, measurements, metadata}})
      end,
      nil
    )

    result = fun.()

    # Collect events
    collected_events = collect_events(ref, events, 100)

    :telemetry.detach(handler_id)

    {result, collected_events}
  end

  defp collect_events(ref, events, timeout) do
    receive do
      {^ref, event} ->
        collect_events(ref, [event | events], timeout)
    after
      timeout ->
        Enum.reverse(events)
    end
  end

  @doc """
  Generates test data for various SDK responses.
  """
  def sample_attack_surface(domain \\ "example.com") do
    %{
      domain: domain,
      assets: %{
        domains: ["www.#{domain}", "api.#{domain}"],
        subdomains: ["blog.#{domain}", "cdn.#{domain}"],
        ip_addresses: ["203.0.113.1", "203.0.113.2"],
        certificates: [
          %{
            subject: "CN=#{domain}",
            issuer: "Let's Encrypt",
            valid_from: "2023-01-01T00:00:00Z",
            valid_to: "2024-01-01T00:00:00Z"
          }
        ],
        services: [
          %{
            ip: "203.0.113.1",
            port: 443,
            protocol: "https",
            service: "nginx"
          }
        ]
      },
      scan_coverage: 0.95,
      discovered_at: DateTime.utc_now()
    }
  end

  def sample_security_rating(grade \\ :B) do
    score = case grade do
      :A -> 850 + :rand.uniform(50)
      :B -> 750 + :rand.uniform(99)
      :C -> 600 + :rand.uniform(149)
      :D -> 450 + :rand.uniform(149)
      :F -> 300 + :rand.uniform(149)
    end

    %{
      grade: grade,
      score: score,
      breakdown: %{
        network_security: score + :rand.uniform(50) - 25,
        application_security: score + :rand.uniform(50) - 25,
        patching_cadence: score + :rand.uniform(50) - 25,
        dns_email_security: score + :rand.uniform(50) - 25,
        ip_reputation: score + :rand.uniform(50) - 25,
        ssl_tls: score + :rand.uniform(50) - 25,
        endpoint_security: score + :rand.uniform(50) - 25
      },
      industry_percentile: :rand.uniform(100),
      timestamp: DateTime.utc_now()
    }
  end

  def sample_investigation_result(target \\ "example.com") do
    %{
      id: "inv_#{:rand.uniform(1000000)}",
      target: target,
      findings: [
        %{
          id: "find_001",
          title: "Domain Registration Information",
          snippet: "Registered to Example Corp in 2020",
          category: :technical,
          source_type: :registry,
          source_ref: "https://whois.net/#{target}",
          risk_level: :low,
          confidence: 0.95,
          metadata: %{registrar: "Namecheap", created: "2020-01-15"},
          timestamp: DateTime.utc_now()
        }
      ],
      sources_used: ["whois", "dns", "certificates"],
      total_findings: 1,
      started_at: DateTime.utc_now(),
      completed_at: DateTime.utc_now(),
      status: :completed
    }
  end

  def sample_lab_session(lab_type \\ :lean4) do
    %{
      id: "sess_#{:rand.uniform(1000000)}",
      user_id: "user_123",
      lab_type: lab_type,
      classification_level: :public,
      status: :active,
      config: %{timeout_ms: 60_000},
      state: %{},
      resource_usage: %{memory_bytes: 1_048_576},
      started_at: DateTime.utc_now(),
      last_activity_at: DateTime.utc_now(),
      expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
    }
  end

  # Private helpers

  defp bypass_port(opts) do
    Keyword.get(opts, :bypass_port, 4000)
  end
end