defmodule PrismaticSDK.ClientTest do
  use ExUnit.Case, async: true

  alias PrismaticSDK.Client

  describe "new/1" do
    test "creates client with API key" do
      client = Client.new(api_key: "pk_test_123")

      assert client.base_url == "https://api.prismatic-platform.com"
      assert client.auth.type == :api_key
      assert client.auth.credentials == "pk_test_123"
      assert client.timeout == 30_000
      assert client.retry_attempts == 3
    end

    test "creates client with custom base URL" do
      client = Client.new(
        api_key: "pk_test_123",
        base_url: "https://staging.prismatic.com"
      )

      assert client.base_url == "https://staging.prismatic.com"
    end

    test "creates client with custom configuration" do
      client = Client.new(
        api_key: "pk_test_123",
        timeout: 60_000,
        retry_attempts: 5,
        pool: :osint
      )

      assert client.timeout == 60_000
      assert client.retry_attempts == 5
      assert client.pool == :osint
    end

    test "raises error without authentication" do
      assert_raise ArgumentError, ~r/No authentication method provided/, fn ->
        Client.new([])
      end
    end
  end

  describe "HTTP requests" do
    setup do
      bypass = Bypass.open()
      client = Client.new(
        api_key: "test_key",
        base_url: "http://localhost:#{bypass.port}"
      )
      {:ok, bypass: bypass, client: client}
    end

    test "makes GET request", %{bypass: bypass, client: client} do
      Bypass.expect_once(bypass, "GET", "/api/v1/test", fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)
        assert conn.params["param1"] == "value1"
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer test_key"]

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{success: true}))
      end)

      assert {:ok, response} = Client.get(client, "/api/v1/test", %{param1: "value1"})
      assert response["success"] == true
    end

    test "makes POST request", %{bypass: bypass, client: client} do
      Bypass.expect_once(bypass, "POST", "/api/v1/create", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        body_data = Jason.decode!(body)
        assert body_data["name"] == "test"

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(201, Jason.encode!(%{id: "123", name: "test"}))
      end)

      assert {:ok, response} = Client.post(client, "/api/v1/create", %{name: "test"})
      assert response["id"] == "123"
    end

    test "handles authentication errors", %{bypass: bypass, client: client} do
      Bypass.expect_once(bypass, "GET", "/api/v1/protected", fn conn ->
        Plug.Conn.resp(conn, 401, "Unauthorized")
      end)

      assert {:error, :unauthorized} = Client.get(client, "/api/v1/protected")
    end

    test "handles rate limiting", %{bypass: bypass, client: client} do
      Bypass.expect_once(bypass, "GET", "/api/v1/rate-limited", fn conn ->
        Plug.Conn.resp(conn, 429, "Too Many Requests")
      end)

      assert {:error, :rate_limited} = Client.get(client, "/api/v1/rate-limited")
    end

    test "handles server errors", %{bypass: bypass, client: client} do
      Bypass.expect_once(bypass, "GET", "/api/v1/error", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(500, Jason.encode!(%{error: "Internal Server Error"}))
      end)

      assert {:error, {:server_error, 500, %{"error" => "Internal Server Error"}}} =
               Client.get(client, "/api/v1/error")
    end

    @tag :skip_ci
    test "handles network timeouts", %{bypass: bypass, client: client} do
      Bypass.stub(bypass, "GET", "/api/v1/slow", fn conn ->
        Process.sleep(200)
        Plug.Conn.resp(conn, 200, "OK")
      end)

      client_with_short_timeout = %{client | timeout: 10}

      result = Client.get(client_with_short_timeout, "/api/v1/slow")
      assert match?({:error, :timeout}, result) or match?({:error, {:network_error, _}}, result)
    end
  end

  describe "health_check/1" do
    setup do
      bypass = Bypass.open()
      client = Client.new(
        api_key: "test_key",
        base_url: "http://localhost:#{bypass.port}"
      )
      {:ok, bypass: bypass, client: client}
    end

    test "returns healthy status", %{bypass: bypass, client: client} do
      Bypass.expect(bypass, "GET", "/api/v1/health", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{status: "ok"}))
      end)

      Bypass.expect(bypass, "GET", "/api/v1/user", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{id: "user_123"}))
      end)

      assert {:ok, health} = Client.health_check(client)
      assert health.status == :healthy
      assert health.connectivity == :ok
      assert health.authentication == :valid
    end

    test "detects authentication issues", %{bypass: bypass, client: client} do
      Bypass.expect(bypass, "GET", "/api/v1/health", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{status: "ok"}))
      end)

      Bypass.expect(bypass, "GET", "/api/v1/user", fn conn ->
        Plug.Conn.resp(conn, 401, "Unauthorized")
      end)

      assert {:ok, health} = Client.health_check(client)
      assert health.status == :degraded
      assert health.connectivity == :ok
      assert health.authentication == :invalid
    end
  end
end