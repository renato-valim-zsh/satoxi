# Satoxi

![Hex.pm](https://img.shields.io/hexpm/v/satoxi?color=informational)

Satoxi is a general purpose library for building Bitcoin applications in Elixir.

## Features

Currently supported features:

- Keypair generation with address encoding and decoding (Legacy, SegWit, Nested SegWit)
- BIP-39 mnemonic phrase generation and BIP-32 hierarchical deterministic keys
- Script and smart contract builder for defining locking/unlocking scripts
- Transaction builder with signing for both legacy and SegWit transactions
- Full SegWit support including `P2WPKH`, `P2WSH`, and `P2SH-P2WPKH` (nested SegWit)

## Installation

The package can be installed by adding `satoxi` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:satoxi, "~> 1.0.0"}
  ]
end
```

## Configuration

Optionally, Satoxi can be configured for testnet network by editing your application's configuration:

```elixir
config :satoxi,
  network: :test  # defaults to :main
```

## Usage

Satoxi is a comprehensive Bitcoin library. Many examples can be found through [the documentation](https://hexdocs.pm/satoxi). See the following for some quick-start examples:

### Keypairs, Addresses, BIP-32

Generate a new random keypair and derive its address.

```elixir
iex> keypair = Satoxi.Keys.new_keypair()
%Satoxi.Keys.KeyPair{
  privkey: %Satoxi.Keys.PrivKey{
    d: <<119, 134, 104, 227, 196, 255, 3, 163, 39, 9, 0, 43, ...>>
  },
  pubkey: %Satoxi.Keys.PubKey{
    point: %Curvy.Point{
      x: 80675204119348790085831157628459085855227400073327708725575496785606354176436,
      y: 9270420727654506759611377999115473532064051910093243567168505762017618809348
    }
  }
}

iex> address = Satoxi.Address.from_pubkey(keypair.pubkey)
iex> Satoxi.Address.to_string(address)
"19D5DoRKchdZbsP3fXYhopbFDdCJCPaLjr"

# Generate a SegWit address
iex> segwit_address = Satoxi.Address.from_pubkey(keypair.pubkey, type: :p2wpkh)
iex> Satoxi.Address.to_string(segwit_address)
"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
```

Generate a BIP-32 HD wallet, derive a child and its address.

```elixir
iex> mnemonic = Satoxi.Mnemonic.new()
"taste canvas eternal brain rent cement fat dilemma duty fame floor defy"

iex> seed = Satoxi.Mnemonic.to_seed(mnemonic)
iex> extkey = Satoxi.Keys.extkey_from_seed!(seed)
%Satoxi.Keys.ExtKey{
  chain_code: <<110, 26, 215, 117, 61, 123, 141, 33, ...>>,
  child_index: 0,
  depth: 0,
  fingerprint: <<0, 0, 0, 0>>,
  privkey: %Satoxi.Keys.PrivKey{...},
  pubkey: %Satoxi.Keys.PubKey{...},
  version: <<4, 136, 173, 228>>
}

# Derive child key and address
iex> child = Satoxi.Keys.extkey_derive(extkey, "m/0/1")
iex> address = Satoxi.Address.from_pubkey(child.pubkey)
iex> Satoxi.Address.to_string(address)
"1Cax2dCtapJZtwzYXCdLuTkZ1egG8JSugA"
```

### Building transactions

The `Builder` module provides a simple declarative way to build any type of transaction.

```elixir
iex> alias Satoxi.Contract.P2PKH

iex> utxo = Satoxi.Transaction.utxo_from_params!(utxo_params)
iex> builder = %Satoxi.Transaction.Builder{
...>   inputs: [
...>     P2PKH.unlock(utxo, %{keypair: keypair})
...>   ],
...>   outputs: [
...>     P2PKH.lock(10000, %{address: address})
...>   ]
...> }

iex> tx = Satoxi.Transaction.builder_to_tx(builder)
iex> rawtx = Satoxi.Transaction.to_binary(tx, encoding: :hex)
"0100000001121a9ac1e0..."
```

For SegWit transactions, use the `P2WPKH` or `P2SH_P2WPKH` contracts:

```elixir
iex> alias Satoxi.Contract.P2WPKH

iex> builder = %Satoxi.Transaction.Builder{
...>   inputs: [
...>     P2WPKH.unlock(utxo, %{keypair: keypair})
...>   ],
...>   outputs: [
...>     P2WPKH.lock(10000, %{address: segwit_address})
...>   ]
...> }
```

### Creating custom contracts

The `Satoxi.Contract` module provides a way to define locking and unlocking scripts in pure Elixir.

```elixir
# Define a module that implements the `Contract` behaviour
defmodule P2PKH do
  use Satoxi.Contract

  def locking_script(ctx, %{address: address}) do
    ctx
    |> op_dup
    |> op_hash160
    |> push(address.pubkey_hash)
    |> op_equalverify
    |> op_checksig
  end

  def unlocking_script(ctx, %{keypair: keypair}) do
    ctx
    |> sig(keypair.privkey)
    |> push(Satoxi.Keys.PubKey.to_binary(keypair.pubkey))
  end
end
```

## License

Satoxi is open source and released under the [MIT License](https://github.com/renato-valim-zsh/satoxi/blob/main/LICENSE).
