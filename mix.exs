defmodule PrismaticSDK.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/korczis/prismatic-sdk"
  @description "Production-ready Elixir SDK for Prismatic Platform APIs"

  def project do
    [
      app: :prismatic_sdk,
      version: @version,
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Documentation
      name: "Prismatic SDK",
      source_url: @source_url,
      docs: docs(),
      description: @description,
      package: package(),

      # Testing
      test_coverage: [tool: ExCoveralls],

      # Dialyzer
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit],
        plt_core_path: "priv/plts",
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
        flags: [:error_handling, :race_conditions, :underspecs]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :ssl, :inets],
      mod: {PrismaticSDK.Application, []}
    ]
  end

  def cli do
    [
      preferred_envs: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Standard dependencies
      {:jason, "~> 1.4"},
      {:finch, "~> 0.16"},
      {:telemetry, "~> 1.2"},

      # Development and testing
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:bypass, "~> 2.1", only: :test},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        "CHANGELOG.md": [title: "Changelog"],
        "guides/getting-started.md": [title: "Getting Started"],
        "guides/authentication.md": [title: "Authentication"],
        "guides/rate-limiting.md": [title: "Rate Limiting"],
        "guides/websockets.md": [title: "Real-time Updates"]
      ],
      groups_for_modules: [
        "Client API": [
          PrismaticSDK.Client,
          PrismaticSDK.Auth,
          PrismaticSDK.Config
        ],
        "Services": [
          PrismaticSDK.Perimeter,
          PrismaticSDK.OSINT,
          PrismaticSDK.Labs,
          PrismaticSDK.Intelligence
        ],
        "Infrastructure": [
          PrismaticSDK.HTTP,
          PrismaticSDK.RateLimit,
          PrismaticSDK.CircuitBreaker
        ]
      ],
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end

  defp package do
    [
      name: "prismatic_sdk",
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Documentation" => "https://hexdocs.pm/prismatic_sdk"
      },
      files: ~w[
        lib
        guides
        .formatter.exs
        mix.exs
        README.md
        CHANGELOG.md
      ]
    ]
  end
end