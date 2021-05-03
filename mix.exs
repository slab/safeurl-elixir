defmodule SafeURL.MixProject do
  use Mix.Project

  def project do
    [
      app: :safeurl,
      version: "0.1.0",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
    ]
  end

  def application do
    [env: default_configs()]
  end

  defp default_configs do
    [
      schemes: ~w[http https],
      blacklist_reserved: true,
      blacklist: [],
      whitelist: [],
    ]
  end

  defp deps do
    [
      {:httpoison, "~> 1.8"},
      {:inet_cidr, "~> 1.0"},
      {:dns, "~> 2.2"},
    ]
  end
end
