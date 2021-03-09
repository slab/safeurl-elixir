defmodule SafeURL.MixProject do
  use Mix.Project

  def project do
    [
      app: :safeurl,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    []
  end

  defp deps do
    [
      {:httpoison, "~> 1.8"},
      {:inet_cidr, "~> 1.0"},
      {:dns, "~> 2.2"}
    ]
  end
end
