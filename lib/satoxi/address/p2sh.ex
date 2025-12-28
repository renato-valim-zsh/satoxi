defmodule Satoxi.Address.P2SH do
  @moduledoc """
  P2SH (Pay-to-Script-Hash) Bitcoin addresses.

  These addresses start with `3` on mainnet or `2` on testnet.
  They use Base58Check encoding and allow spending to the hash of a script,
  enabling complex spending conditions like multisig.

  ## Examples

      iex> script_hash = Satoxi.Hash.sha256_ripemd160(<<1, 2, 3>>)
      iex> address = Satoxi.Address.P2SH.from_script_hash(script_hash)
      iex> Satoxi.Address.Encoding.to_string(address)
      "3Fte5yfJErKGBSVMHpf93sdF6RmtSbTmL1"
  """
  alias Satoxi.Hash

  defstruct [:script_hash]

  @typedoc "P2SH address"
  @type t() :: %__MODULE__{
          script_hash: binary()
        }

  @version_bytes %{
    main: <<0x05>>,
    test: <<0xC4>>
  }

  @doc """
  Creates a P2SH address from a script hash.

  The script_hash should be the HASH160 (SHA256 + RIPEMD160) of the redeem script.

  ## Examples

      iex> script_hash = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20>>
      iex> address = Satoxi.Address.P2SH.from_script_hash(script_hash)
      iex> address.script_hash == script_hash
      true
  """
  @spec from_script_hash(binary()) :: t()
  def from_script_hash(script_hash) when byte_size(script_hash) == 20 do
    %__MODULE__{script_hash: script_hash}
  end

  @doc """
  Creates a P2SH address from a redeem script.

  Computes the HASH160 of the script and creates the address.

  ## Examples

      iex> redeem_script = <<0x51, 0x21>> <> <<1::256>> <> <<0x51, 0xAE>>
      iex> address = Satoxi.Address.P2SH.from_script(redeem_script)
      iex> byte_size(address.script_hash)
      20
  """
  @spec from_script(binary()) :: t()
  def from_script(redeem_script) when is_binary(redeem_script) do
    script_hash = Hash.sha256_ripemd160(redeem_script)
    %__MODULE__{script_hash: script_hash}
  end

  @doc """
  Decodes a Base58Check encoded P2SH address string.

  Returns `{:ok, address}` or `{:error, reason}`.

  ## Examples

      iex> {:ok, address} = Satoxi.Address.P2SH.from_string("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
      iex> byte_size(address.script_hash)
      20
  """
  @spec from_string(String.t()) :: {:ok, t()} | {:error, term()}
  def from_string(address) when is_binary(address) do
    network = Satoxi.network()
    <<expected_version>> = @version_bytes[network]

    case ExBase58.decode_check(address) do
      {:ok, <<^expected_version, script_hash::binary-20>>} ->
        {:ok, %__MODULE__{script_hash: script_hash}}

      {:ok, <<version_byte, _::binary-20>>} ->
        {:error, {:invalid_version_byte, <<version_byte>>, network}}

      {:ok, _} ->
        {:error, :invalid_payload_length}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Decodes a Base58Check encoded P2SH address string.

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
  def to_string(%__MODULE__{script_hash: script_hash}) do
    <<version_byte>> = @version_bytes[Satoxi.network()]
    ExBase58.encode_check_version!(script_hash, version_byte)
  end

  @doc """
  Returns the script hash (20 bytes).
  """
  @spec get_script_hash(t()) :: binary()
  def get_script_hash(%__MODULE__{script_hash: hash}), do: hash

  defimpl Satoxi.Address.Encoding do
    def to_string(address), do: Satoxi.Address.P2SH.to_string(address)
    def get_hash(address), do: Satoxi.Address.P2SH.get_script_hash(address)
  end
end
