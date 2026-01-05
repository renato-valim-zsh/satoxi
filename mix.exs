defmodule Satoxi.MixProject do
  use Mix.Project

  def project do
    [
      app: :satoxi,
      version: "1.0.1",
      elixir: "~> 1.18",
      name: "Satoxi",
      description: "Toolbox for building bitcoin applications",
      source_url: "https://github.com/renato-valim-zsh/satoxi",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: docs(),
      package: package()
    ]
  end

  defp docs do
    [
      main: "Satoxi",
      extras: extras(),
      groups_for_modules: [
        Encoding: [
          Satoxi.Encoding.Base58Check,
          Satoxi.Encoding.Bech32,
          Satoxi.Encoding.VarInt
        ],
        Keys: [
          Satoxi.Keys.PrivKey,
          Satoxi.Keys.PubKey,
          Satoxi.Keys.ExtKey,
          Satoxi.Keys.KeyPair
        ],
        Addresses: [
          Satoxi.Address.P2SH,
          Satoxi.Address.Legacy,
          Satoxi.Address.SegWit,
          Satoxi.Address.Nested
        ],
        Script: [
          Satoxi.Script.OpCode,
          Satoxi.Script.ScriptNum
        ],
        Transaction: [
          Satoxi.Transaction.Output,
          Satoxi.Transaction.Input,
          Satoxi.Transaction.OutPoint,
          Satoxi.Transaction.Witness,
          Satoxi.Transaction.UTXO,
          Satoxi.Transaction.Builder,
          Satoxi.Transaction.Sig,
          Satoxi.Transaction.PreImage
        ],
        Contracts: [
          Satoxi.Contract.P2PKH,
          Satoxi.Contract.P2WPKH,
          Satoxi.Contract.P2SH_P2WPKH
        ],
        Helpers: [
          Satoxi.Binary,
          Satoxi.Contract.Helpers,
          Satoxi.Contract.OpCodeHelpers
        ],
        Protocols: [
          Satoxi.Serializable,
          Satoxi.Address.Encoding
        ]
      ]
    ]
  end

  defp extras do
    []
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_bech32, "~> 0.6.3"},
      {:ex_base58, "~> 0.6.5"},
      {:curvy, "~> 0.3"},
      {:ex_doc, "~> 0.25", only: :dev, runtime: false},
      {:jason, "~> 1.4.4", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      name: "satoxi",
      files: ~w(lib .formatter.exs mix.exs README.md),
      licenses: ["MIT"],
      maintainers: ["Renato Valim"],
      links: %{"GitHub" => "https://github.com/renato-valim-zsh/satoxi"}
    ]
  end
end
