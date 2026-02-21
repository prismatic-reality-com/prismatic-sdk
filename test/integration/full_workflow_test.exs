defmodule PrismaticSDK.Integration.FullWorkflowTest do
  use ExUnit.Case, async: true

  alias PrismaticSDK.{Client, Perimeter, OSINT, Labs, Websocket}
  import PrismaticSDK.TestHelpers

  @moduletag :integration

  describe "complete SDK workflow" do
    setup do
      {bypass, client} = setup_bypass()

      # Set up all required test endpoints
      mock_health_endpoint(bypass)
      mock_auth_endpoint(bypass)
      mock_perimeter_endpoints(bypass)
      mock_osint_endpoints(bypass)
      mock_labs_endpoints(bypass)

      {:ok, bypass: bypass, client: client}
    end

    test "performs comprehensive security assessment", %{client: client} do
      target_domain = "example.com"

      # 1. Start with health check
      assert {:ok, health} = Client.health_check(client)
      assert health.status == :healthy

      # 2. Discover external attack surface
      assert {:ok, surface} = Perimeter.discover(client, target_domain,
        depth: :standard,
        include: [:domains, :ips, :certificates]
      )

      assert surface.domain == target_domain
      assert is_float(surface.scan_coverage)
      assert length(surface.assets.subdomains) > 0

      # 3. Get security rating
      assert {:ok, rating} = Perimeter.security_rating(client, target_domain)
      assert rating.grade in [:A, :B, :C, :D, :F]
      assert is_integer(rating.score)
      assert rating.score >= 300 and rating.score <= 900

      # 4. Assess compliance
      assert {:ok, nis2_compliance} = Perimeter.nis2_compliance(client, target_domain)
      assert {:ok, zkb_compliance} = Perimeter.zkb_compliance(client, target_domain)

      # 5. Run OSINT investigation
      assert {:ok, investigation} = OSINT.investigate(client, target_domain,
        sources: [:whois, :dns, :certificates],
        max_sources: 5,
        timeout: 30_000
      )

      assert investigation.target == target_domain
      assert investigation.status == :completed
      assert length(investigation.findings) > 0

      # 6. Check specific OSINT sources
      assert {:ok, whois_results} = OSINT.search(client, :whois, target_domain)
      assert {:ok, dns_results} = OSINT.search(client, :dns, target_domain)

      # 7. Start monitoring
      assert {:ok, monitor_id} = Perimeter.start_monitoring(client, target_domain,
        check_interval: 60,
        alert_threshold: :medium
      )

      # 8. Get monitoring status
      assert {:ok, monitor_status} = Perimeter.get_monitoring_status(client, monitor_id)
      assert is_map(monitor_status)

      # 9. Create analysis summary
      summary = %{
        domain: target_domain,
        security_rating: rating,
        attack_surface: %{
          subdomains: length(surface.assets.subdomains),
          ip_addresses: length(surface.assets.ip_addresses),
          certificates: length(surface.assets.certificates),
          scan_coverage: surface.scan_coverage
        },
        osint_findings: %{
          total: investigation.total_findings,
          high_risk: count_high_risk_findings(investigation.findings),
          sources_used: investigation.sources_used
        },
        compliance: %{
          nis2: extract_compliance_status(nis2_compliance),
          zkb: extract_compliance_status(zkb_compliance)
        },
        monitoring: %{
          active: true,
          monitor_id: monitor_id
        },
        assessed_at: DateTime.utc_now()
      }

      # Verify the summary contains expected data
      assert summary.security_rating.grade in [:A, :B, :C, :D, :F]
      assert summary.attack_surface.subdomains >= 0
      assert summary.osint_findings.total >= 0
      assert is_boolean(summary.monitoring.active)

      # 10. Stop monitoring (cleanup)
      assert :ok = Perimeter.stop_monitoring(client, monitor_id)
    end

    test "creates and manages lab sessions", %{client: client} do
      # 1. Check supported lab types
      assert {:ok, lab_types} = Labs.supported_lab_types(client)
      assert :lean4 in lab_types
      assert :playbook in lab_types

      # 2. Create Lean4 session
      assert {:ok, lean4_session} = Labs.create_session(client, %{
        lab_type: :lean4,
        classification_level: :public,
        config: %{timeout_ms: 60_000}
      })

      assert lean4_session.lab_type == :lean4
      assert lean4_session.status == :active

      # 3. Execute theorem proving
      assert {:ok, execution} = Labs.execute_in_session(client, lean4_session.id, %{
        execution_type: "lean4_check",
        input_data: %{
          "operation" => "type_check",
          "expression" => "Nat.add 2 2",
          "expected_type" => "Nat"
        }
      })

      assert execution.status == :completed
      assert is_map(execution.output_data)

      # 4. Create Playbook session
      assert {:ok, playbook_session} = Labs.create_session(client, %{
        lab_type: :playbook,
        classification_level: :internal,
        config: %{timeout_ms: 30_000}
      })

      # 5. Execute template rendering
      assert {:ok, template_execution} = Labs.execute_in_session(client, playbook_session.id, %{
        execution_type: "template_render",
        input_data: %{
          "type" => "template_render",
          "template" => "Hello {{name}}! Status: {{status}}",
          "variables" => %{"name" => "World", "status" => "OK"}
        }
      })

      assert template_execution.status == :completed
      assert template_execution.output_data["rendered"] == "Hello World! Status: OK"

      # 6. Get resource usage
      assert {:ok, lean4_usage} = Labs.get_resource_usage(client, lean4_session.id)
      assert {:ok, playbook_usage} = Labs.get_resource_usage(client, playbook_session.id)

      # 7. List active sessions
      assert {:ok, active_sessions} = Labs.list_active_sessions(client)
      assert length(active_sessions) >= 2

      session_ids = Enum.map(active_sessions, & &1.id)
      assert lean4_session.id in session_ids
      assert playbook_session.id in session_ids

      # 8. Terminate sessions
      assert :ok = Labs.terminate_session(client, lean4_session.id, "test_complete")
      assert :ok = Labs.terminate_session(client, playbook_session.id, "test_complete")
    end

    test "handles real-time WebSocket connections", %{client: client} do
      # Note: This test would require additional WebSocket mocking infrastructure
      # For now, we test the API surface

      # 1. Test topic generation
      monitoring_topic = Websocket.topic(:perimeter_monitoring)
      assert monitoring_topic == "perimeter:monitoring"

      investigation_topic = Websocket.topic(:osint_investigation, "inv_123")
      assert investigation_topic == "osint:investigation:inv_123"

      # 2. Test connection would be handled by WebSocket infrastructure
      # In a real integration test, we would:
      # {:ok, socket} = Websocket.connect(client, topic: monitoring_topic, handler: TestHandler)
      # assert is_pid(socket)

      # 3. Test health check of WebSocket infrastructure
      assert {:ok, health} = Websocket.health_check()
      assert health.status in [:healthy, :idle]
    end
  end

  # Helper functions for mocking

  defp mock_perimeter_endpoints(bypass) do
    # Discovery endpoint
    Bypass.expect(bypass, "POST", "/api/v1/perimeter/discover", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      body_data = Jason.decode!(body)

      response = sample_attack_surface(body_data["domain"])
      |> Map.update!(:discovered_at, &DateTime.to_iso8601/1)

      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    # Security rating endpoint
    Bypass.expect(bypass, "GET", "/api/v1/perimeter/rating", fn conn ->
      conn = Plug.Conn.fetch_query_params(conn)
      domain = conn.params["domain"]

      response = sample_security_rating()
      |> Map.update!(:timestamp, &DateTime.to_iso8601/1)

      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    # Compliance endpoints
    Bypass.expect(bypass, "POST", "/api/v1/perimeter/compliance/assess", fn conn ->
      response = %{
        compliance: %{
          overall_score: 0.85,
          frameworks: %{
            nis2: %{compliant: true, score: 0.9},
            zkb: %{compliant: false, score: 0.8}
          }
        }
      }
      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    # Monitoring endpoints
    Bypass.expect(bypass, "POST", "/api/v1/perimeter/monitoring/start", fn conn ->
      response = %{monitor_id: "mon_#{:rand.uniform(1000000)}"}
      Plug.Conn.resp(conn, 201, Jason.encode!(response))
    end)

    Bypass.expect(bypass, "GET", ~r{/api/v1/perimeter/monitoring/.+/status}, fn conn ->
      response = %{status: "active", last_check: DateTime.utc_now() |> DateTime.to_iso8601()}
      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    Bypass.expect(bypass, "DELETE", ~r{/api/v1/perimeter/monitoring/.+}, fn conn ->
      Plug.Conn.resp(conn, 204, "")
    end)
  end

  defp mock_osint_endpoints(bypass) do
    # Investigation endpoint
    Bypass.expect(bypass, "POST", "/api/v1/osint/investigate", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      body_data = Jason.decode!(body)

      response = sample_investigation_result(body_data["target"])
      |> update_timestamps()

      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    # Search endpoint
    Bypass.expect(bypass, "POST", "/api/v1/osint/search", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      body_data = Jason.decode!(body)

      response = %{
        source: body_data["source"],
        query: body_data["query"],
        results: [
          %{
            title: "Sample Result",
            snippet: "Sample data for #{body_data["query"]}",
            confidence: 0.9,
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
          }
        ]
      }

      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    # Sources endpoint
    Bypass.expect(bypass, "GET", "/api/v1/osint/sources", fn conn ->
      response = %{
        sources: [
          %{name: "whois", display_name: "WHOIS", category: "global", active: true},
          %{name: "dns", display_name: "DNS", category: "global", active: true},
          %{name: "certificates", display_name: "Certificates", category: "global", active: true}
        ]
      }
      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)
  end

  defp mock_labs_endpoints(bypass) do
    # Session creation
    Bypass.expect(bypass, "POST", "/api/v1/labs/sessions", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      body_data = Jason.decode!(body)

      lab_type = String.to_existing_atom(body_data["lab_type"])
      classification_level = String.to_existing_atom(body_data["classification_level"])

      response = sample_lab_session(lab_type)
      |> Map.put(:classification_level, classification_level)
      |> update_timestamps()

      Plug.Conn.resp(conn, 201, Jason.encode!(response))
    end)

    # Execution
    Bypass.expect(bypass, "POST", ~r{/api/v1/labs/sessions/.+/execute}, fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      body_data = Jason.decode!(body)

      output_data = case body_data["execution_type"] do
        "lean4_check" ->
          %{"type_correct" => true, "inferred_type" => "Nat", "qed" => true}
        "template_render" ->
          %{"rendered" => "Hello World! Status: OK"}
        _ ->
          %{"result" => "success"}
      end

      response = %{
        id: "exec_#{:rand.uniform(1000000)}",
        session_id: extract_session_id(conn.request_path),
        execution_type: body_data["execution_type"],
        input_data: body_data["input_data"],
        output_data: output_data,
        status: "completed",
        error_message: nil,
        execution_time_ms: :rand.uniform(1000),
        resource_usage: %{memory_bytes: :rand.uniform(10_000_000)},
        started_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        completed_at: DateTime.utc_now() |> DateTime.to_iso8601()
      }

      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    # Resource usage
    Bypass.expect(bypass, "GET", ~r{/api/v1/labs/sessions/.+/resources}, fn conn ->
      response = %{
        memory_bytes: :rand.uniform(10_000_000),
        heap_size: :rand.uniform(5_000_000),
        cpu_percent: :rand.uniform(100) / 1.0,
        execution_count: :rand.uniform(50),
        active: true,
        last_check: DateTime.utc_now() |> DateTime.to_iso8601()
      }

      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    # List sessions
    Bypass.expect(bypass, "GET", "/api/v1/labs/sessions", fn conn ->
      sessions = [
        sample_lab_session(:lean4) |> update_timestamps(),
        sample_lab_session(:playbook) |> update_timestamps()
      ]

      response = %{sessions: sessions}
      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    # Supported lab types
    Bypass.expect(bypass, "GET", "/api/v1/labs/types", fn conn ->
      response = %{lab_types: ["playbook", "blackboard", "lean4", "smalltalk"]}
      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    # Terminate session
    Bypass.expect(bypass, "DELETE", ~r{/api/v1/labs/sessions/.+}, fn conn ->
      Plug.Conn.resp(conn, 204, "")
    end)
  end

  # Helper functions

  defp count_high_risk_findings(findings) do
    Enum.count(findings, fn finding ->
      finding.risk_level in [:high, :critical]
    end)
  end

  defp extract_compliance_status(compliance_result) do
    compliance_result["compliance"]["overall_score"] > 0.8
  end

  defp update_timestamps(data) when is_map(data) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    data
    |> Map.update(:started_at, now, fn _ -> now end)
    |> Map.update(:completed_at, now, fn _ -> now end)
    |> Map.update(:last_activity_at, now, fn _ -> now end)
    |> Map.update(:expires_at, DateTime.add(DateTime.utc_now(), 3600, :second) |> DateTime.to_iso8601(), fn _ ->
      DateTime.add(DateTime.utc_now(), 3600, :second) |> DateTime.to_iso8601()
    end)
  end

  defp extract_session_id(path) do
    path
    |> String.split("/")
    |> Enum.at(4) # /api/v1/labs/sessions/{session_id}/execute
  end
end