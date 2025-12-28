defmodule Satoxi.Address.Legacy do
  @moduledoc """
  Legacy P2PKH (Pay-to-Public-Key-Hash) Bitcoin addresses.

  These addresses start with `1` on mainnet or `m`/`n` on testnet.
  They use Base58Check encoding and were the original Bitcoin address format.

  ## Examples

      iex> pubkey = <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232,
      ...>            175, 144, 63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
      iex> address = Satoxi.Address.Legacy.from_pubkey(pubkey)
      iex> Satoxi.Address.Encoding.to_string(address)
      "18cqNbEBxkAttxcZLuH9LWhZJPd1BNu1A5"
  """
  alias Satoxi.{Hash, Keys.PubKey}

  defstruct [:pubkey_hash]

  @typedoc "Legacy P2PKH address"
  @type t() :: %__MODULE__{
          pubkey_hash: binary()
        }

  @version_bytes %{
    main: <<0x00>>,
    test: <<0x6F>>
  }

  @doc """
  Creates a Legacy P2PKH address from a public key.

  ## Examples

      iex> pubkey = <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232,
      ...>            175, 144, 63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
      iex> address = Satoxi.Address.Legacy.from_pubkey(pubkey)
      iex> address.pubkey_hash
      <<83, 143, 209, 121, 200, 190, 15, 40, 156, 115, 14, 51, 181, 246, 163, 84, 27, 233, 102, 143>>
  """
  @spec from_pubkey(PubKey.t() | binary()) :: t()
  def from_pubkey(%PubKey{} = pubkey) do
    pubkey
    |> PubKey.to_binary()
    |> from_pubkey()
  end

  def from_pubkey(pubkey) when is_binary(pubkey) and byte_size(pubkey) in [33, 65] do
    pubkey_hash = Hash.sha256_ripemd160(pubkey)
    %__MODULE__{pubkey_hash: pubkey_hash}
  end

  @doc """
  Creates a Legacy P2PKH address from a pubkey hash.

  ## Examples

      iex> hash = <<83, 143, 209, 121, 200, 190, 15, 40, 156, 115, 14, 51, 181, 246, 163, 84, 27, 233, 102, 143>>
      iex> address = Satoxi.Address.Legacy.from_pubkey_hash(hash)
      iex> address.pubkey_hash == hash
      true
  """
  @spec from_pubkey_hash(binary()) :: t()
  def from_pubkey_hash(pubkey_hash) when byte_size(pubkey_hash) == 20 do
    %__MODULE__{pubkey_hash: pubkey_hash}
  end

  @doc """
  Decodes a Base58Check encoded Legacy address string.

  Returns `{:ok, address}` or `{:error, reason}`.

  ## Examples

      iex> Satoxi.Address.Legacy.from_string("18cqNbEBxkAttxcZLuH9LWhZJPd1BNu1A5")
      {:ok, %Satoxi.Address.Legacy{pubkey_hash: <<83, 143, 209, 121, 200, 190, 15, 40, 156, 115, 14, 51, 181, 246, 163, 84, 27, 233, 102, 143>>}}
  """
  @spec from_string(String.t()) :: {:ok, t()} | {:error, term()}
  def from_string(address) when is_binary(address) do
    network = Satoxi.network()
    <<expected_version>> = @version_bytes[network]

    case ExBase58.decode_check(address) do
      {:ok, <<^expected_version, pubkey_hash::binary-20>>} ->
        {:ok, %__MODULE__{pubkey_hash: pubkey_hash}}

      {:ok, <<version_byte, _::binary-20>>} ->
        {:error, {:invalid_version_byte, <<version_byte>>, network}}

      {:ok, _} ->
        {:error, :invalid_payload_length}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Decodes a Base58Check encoded Legacy address string.

  As `from_string/1` but returns the result or raises an exception.
  """
  @spec from_string!(String.t()) :: t()
  def from_string!(address) do
    case from_string(address) do
      {:ok, addr} -> addr
      {:error, error} -> raise Satoxi.Error, error
    end
  end

  @doc """
  Encodes the address to a Base58Check string.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{pubkey_hash: pubkey_hash}) do
    <<version_byte>> = @version_bytes[Satoxi.network()]
    ExBase58.encode_check_version!(pubkey_hash, version_byte)
  end

  @doc """
  Returns the pubkey hash (20 bytes).
  """
  @spec get_pubkey_hash(t()) :: binary()
  def get_pubkey_hash(%__MODULE__{pubkey_hash: hash}), do: hash

  defimpl Satoxi.Address.Encoding do
    def to_string(address), do: Satoxi.Address.Legacy.to_string(address)
    def get_hash(address), do: Satoxi.Address.Legacy.get_pubkey_hash(address)
  end
end
