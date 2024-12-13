defmodule BacnetClient.MixProject do
  use Mix.Project

  def project do
    [
      app: :bacnet_client,
      version: "0.1.0",
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      config_path: "config/config.exs",
      deps: deps(),
      default_release: :bacnet_client,
      releases: [
        # 普通节点
        bacnet_client: [
          include_erts: false
        ]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {BacnetClient.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
      {:bacstack, git: "https://github.com/bacnet-ex/bacstack", tag: "master"}
    ]
  end
end
