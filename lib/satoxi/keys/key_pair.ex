defmodule Satoxi.Keys.KeyPair do
  @moduledoc """
  A keypair is a data structure consisting of both a `t:Satoxi.Keys.PrivKey.t/0` and its corresponding `t:Satoxi.Keys.PubKey.t/0`.
  """
  alias Satoxi.Keys.{PrivKey, PubKey}

  defstruct privkey: nil, pubkey: nil

  @typedoc "KeyPair struct"
  @type t() :: %__MODULE__{
          privkey: PrivKey.t(),
          pubkey: PubKey.t()
        }

  @doc """
  Generates and returns a new `t:Satoxi.Keys.KeyPair.t/0`.
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    {_pubkey, privkey} = :crypto.generate_key(:ecdh, :secp256k1)

    privkey
    |> PrivKey.from_binary!(opts)
    |> from_privkey()
  end

  @doc """
  Returns a `t:Satoxi.Keys.KeyPair.t/0` from the given `t:Satoxi.Keys.PrivKey.t/0`.
  """
  @spec from_privkey(PrivKey.t()) :: t()
  def from_privkey(%PrivKey{} = privkey) do
    %__MODULE__{
      privkey: privkey,
      pubkey: PubKey.from_privkey(privkey)
    }
  end
end
