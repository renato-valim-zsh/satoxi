defmodule Satoxi.Address.Nested do
  @moduledoc """
  Nested SegWit (`P2SH-P2WPKH`) Bitcoin addresses.

  These addresses wrap a SegWit script inside a `P2SH` address for compatibility
  with wallets that don't support native SegWit. They start with `3` on mainnet
  or `2` on testnet (same as regular `P2SH`).

  Also known as "wrapped SegWit" or BIP-49 addresses.

  ## How it works

  The redeem script for `P2SH-P2WPKH` is:
  ```
  OP_0 <20-byte pubkey hash>
  ```
  Which is then hashed to create the `P2SH` address.

  ## Examples

      iex> pubkey = <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232,
      ...>            175, 144, 63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
      iex> address = Satoxi.Address.Nested.from_pubkey(pubkey)
      iex> Satoxi.Address.Encoding.to_string(address)
      "3CzveZV418mVv88DVvFikrapHSV2QaY7pt"
  """
  alias Satoxi.{Hash, Keys.PubKey}

  defstruct [:script_hash, :pubkey_hash]

  @typedoc "Nested SegWit (`P2SH-P2WPKH`) address"
  @type t() :: %__MODULE__{
          script_hash: binary(),
          pubkey_hash: binary()
        }

  @version_bytes %{
    main: <<0x05>>,
    test: <<0xC4>>
  }

  @doc """
  Creates a Nested SegWit address from a public key.

  This creates a `P2SH-P2WPKH` address where the redeem script is:
  `OP_0 <20-byte pubkey hash>`

  ## Examples

      iex> pubkey = <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232,
      ...>            175, 144, 63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
      iex> address = Satoxi.Address.Nested.from_pubkey(pubkey)
      iex> byte_size(address.script_hash)
      20
  """
  @spec from_pubkey(PubKey.t() | binary()) :: t()
  def from_pubkey(%PubKey{} = pubkey) do
    pubkey
    |> PubKey.to_binary()
    |> from_pubkey()
  end

  def from_pubkey(pubkey) when is_binary(pubkey) and byte_size(pubkey) in [33, 65] do
    pubkey_hash = Hash.sha256_ripemd160(pubkey)

    from_pubkey_hash(pubkey_hash)
  end

  @doc """
  Creates a Nested SegWit address from a pubkey hash.

  ## Examples

      iex> hash = <<83, 143, 209, 121, 200, 190, 15, 40, 156, 115, 14, 51, 181, 246, 163, 84, 27, 233, 102, 143>>
      iex> address = Satoxi.Address.Nested.from_pubkey_hash(hash)
      iex> address.pubkey_hash == hash
      true
  """
  @spec from_pubkey_hash(binary()) :: t()
  def from_pubkey_hash(pubkey_hash) when byte_size(pubkey_hash) == 20 do
    # Redeem script: OP_0 (0x00) + PUSH_20 (0x14) + pubkey_hash
    redeem_script = <<0x00, 0x14>> <> pubkey_hash
    script_hash = Hash.sha256_ripemd160(redeem_script)

    %__MODULE__{
      script_hash: script_hash,
      pubkey_hash: pubkey_hash
    }
  end

  @doc """
  Encodes the address to a `Base58Check` string.

  Note: The resulting address looks like a regular `P2SH` address (starts with `3`/`2`), but the spending conditions are SegWit-based.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{script_hash: script_hash}) do
    <<version_byte>> = @version_bytes[Satoxi.network()]
    ExBase58.encode_check_version!(script_hash, version_byte)
  end

  @doc """
  Returns the script hash (20 bytes) used in the `P2SH` address.
  """
  @spec get_script_hash(t()) :: binary()
  def get_script_hash(%__MODULE__{script_hash: hash}), do: hash

  @doc """
  Returns the underlying pubkey hash (20 bytes).
  """
  @spec get_pubkey_hash(t()) :: binary()
  def get_pubkey_hash(%__MODULE__{pubkey_hash: hash}), do: hash

  @doc """
  Returns the redeem script needed to spend from this address.

  This is `OP_0 <20-byte pubkey hash>`.
  """
  @spec get_redeem_script(t()) :: binary()
  def get_redeem_script(%__MODULE__{pubkey_hash: pubkey_hash}) do
    <<0x00, 0x14>> <> pubkey_hash
  end

  defimpl Satoxi.Address.Encoding do
    alias Satoxi.Address.Nested

    def to_string(address), do: Nested.to_string(address)
    def get_hash(address), do: Nested.get_script_hash(address)
  end
end
