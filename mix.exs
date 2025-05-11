defmodule WasmerEx.MixProject do
  use Mix.Project

  def project do
    [
      app: :wasmer_ex,
      version: "0.1.0",
      elixir: "~> 1.18",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: "WASMER Runtime in RUST for Elixir",
      deps: deps(),
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler, ">= 0.36.1", runtime: false, optional: true},
    ]
  end
end

