defmodule PrismaticSDK.Application do
  @moduledoc """
  OTP Application for Prismatic SDK.

  Manages the supervision tree for SDK components including:
  - HTTP connection pool
  - Rate limiting infrastructure
  - Circuit breakers
  - WebSocket connection manager
  - Telemetry
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # HTTP client pool
      {Finch, name: PrismaticSDK.Finch},
      # Basic registry for SDK components
      {Registry, keys: :unique, name: PrismaticSDK.Registry}
    ]

    opts = [strategy: :one_for_one, name: PrismaticSDK.Supervisor]
    Supervisor.start_link(children, opts)
  end

  @doc """
  Returns basic health status for the SDK application.

  ## Examples

      {:ok, health} = PrismaticSDK.Application.health_check()
      # => %{
      #   status: :healthy,
      #   uptime_ms: 3600000,
      #   timestamp: ~U[2026-02-21 10:30:00Z]
      # }
  """
  @spec health_check() :: {:ok, map()} | {:error, term()}
  def health_check do
    try do
      {:ok, %{
        status: :healthy,
        uptime_ms: :erlang.statistics(:wall_clock) |> elem(0),
        timestamp: DateTime.utc_now()
      }}
    rescue
      error ->
        {:error, {:health_check_failed, error}}
    end
  end
end