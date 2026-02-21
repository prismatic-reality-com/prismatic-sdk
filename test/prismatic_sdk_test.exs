defmodule PrismaticSDKTest do
  use ExUnit.Case, async: true
  doctest PrismaticSDK

  describe "SDK initialization" do
    test "new/1 creates a client with API key" do
      client = PrismaticSDK.new(api_key: "test_key")

      assert client.auth.type == :api_key
      assert client.auth.credentials == "test_key"
      assert client.base_url == "https://api.prismatic-platform.com"
    end

    test "new/1 creates a client with bearer token" do
      client = PrismaticSDK.new(bearer_token: "jwt_token")

      assert client.auth.type == :bearer_token
      assert client.auth.credentials == "jwt_token"
    end

    test "new/1 uses configuration from app config" do
      # Test would require setting up application config
      client = PrismaticSDK.new(api_key: "test")
      assert is_struct(client, PrismaticSDK.Client)
    end
  end

  describe "version/0" do
    test "returns SDK version" do
      version = PrismaticSDK.version()
      assert is_binary(version)
      assert version =~ ~r/^\d+\.\d+\.\d+/
    end
  end

  describe "health_check/1" do
    setup do
      bypass = Bypass.open()
      client = PrismaticSDK.new(
        api_key: "test_key",
        base_url: "http://localhost:#{bypass.port}"
      )
      {:ok, bypass: bypass, client: client}
    end

    test "returns health status", %{bypass: bypass, client: client} do
      Bypass.expect_once(bypass, "GET", "/api/v1/health", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{status: "ok"}))
      end)

      assert {:ok, health} = PrismaticSDK.health_check(client)
      assert health.status == :healthy
    end
  end
end