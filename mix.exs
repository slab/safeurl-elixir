defmodule SafeURL.MixProject do
  use Mix.Project


  @app     :safeurl
  @name    "SafeURL"
  @version "0.3.0"
  @github  "https://github.com/slab/safeurl-elixir"


  def project do
    [
      # Project
      app:            @app,
      version:        @version,
      elixir:         "~> 1.10",
      description:    description(),
      package:        package(),
      deps:           deps(),
      elixirc_paths:  elixirc_paths(Mix.env()),

      # ExDoc
      name:           @name,
      docs: [
        main:         @name,
        source_url:   @github,
        homepage_url: @github,
        canonical:    "https://hexdocs.pm/#{@app}",
        extras:       ["README.md"]
      ]
    ]
  end


  defp description do
    "SSRF Protection in Elixir 🛡️"
  end


  # BEAM Application
  def application do
    [env: default_configs()]
  end


  defp default_configs do
    [
      schemes: ~w[http https],
      block_reserved: true,
      blocklist: [],
      allowlist: [],
      dns_module: DNS,
    ]
  end


  # Dependencies
  defp deps do
    [
      {:httpoison, "~> 1.0 or ~> 2.0", optional: true},
      {:inet_cidr, "~> 1.0"},
      {:dns, "~> 2.2"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
    ]
  end


  # Compilation Paths
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_),     do: ["lib"]


  # Package Information
  defp package do
    [
      name: @app,
      maintainers: ["Slab"],
      licenses: ["BSD-3-Clause"],
      files: ~w(mix.exs lib README.md),
      links: %{
        "Github" => @github,
        "Slab" => "https://slab.com/",
      }
    ]
  end
end
