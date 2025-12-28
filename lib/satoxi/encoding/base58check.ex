defmodule Satoxi.Encoding.Base58Check do
  @moduledoc """
  `Base58Check` encoding and decoding for legacy Bitcoin addresses.

  ## What is Base58Check?

  Base58Check is a binary-to-text encoding scheme used in Bitcoin for legacy
  addresses and private key exports (WIF format). It includes a 4-byte checksum
  derived from double SHA-256 hashing, allowing detection of transcription errors.

  The Base58 alphabet was designed for human readability, excluding characters
  that could be easily confused:
  * `0` (zero), `O` (uppercase o) - easily confused
  * `I` (uppercase i), `l` (lowercase L) - easily confused
  * `+` and `/` - non-alphanumeric characters used in Base64

  Bitcoin's Base58 alphabet: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`

  ## Version Bytes

  Bitcoin uses version bytes to identify address and key types:

  * `0x00` - Mainnet P2PKH (Pay-to-Public-Key-Hash) addresses (start with `1`)
  * `0x05` - Mainnet P2SH (Pay-to-Script-Hash) addresses (start with `3`)
  * `0x6F` - Testnet P2PKH addresses (start with `m` or `n`)
  * `0xC4` - Testnet P2SH addresses (start with `2`)
  * `0x80` - Mainnet WIF private keys (start with `5`, `K`, or `L`)
  * `0xEF` - Testnet WIF private keys (start with `9` or `c`)

  ## Legacy vs SegWit

  Base58Check is used for legacy Bitcoin addresses. For SegWit addresses
  (starting with `bc1` or `tb1`), see `Satoxi.Encoding.Bech32`.
  """

  @alphabet :bitcoin

  @doc """
  Encodes binary data into a Base58Check string with checksum.

  The checksum is calculated by taking the first 4 bytes of a double SHA-256
  hash of the data, which is then appended before encoding.

  ## Parameters

  * `data` - The binary data to encode (including version byte if needed)

  ## Examples

      iex> Base58Check.encode(<<0x00>> <> pubkey_hash)
      {:ok, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"}
  """
  @spec encode(binary()) :: {:ok, String.t()} | {:error, term()}
  def encode(data) when is_binary(data) do
    ExBase58.encode_check(data, @alphabet)
  end

  @doc """
  Encodes binary data into a Base58Check string with checksum.

  As `encode/1` but returns the result or raises an exception.
  """
  @spec encode!(binary()) :: String.t()
  def encode!(data) do
    case encode(data) do
      {:ok, encoded} -> encoded
      {:error, error} -> raise ArgumentError, "Base58Check encoding failed: #{inspect(error)}"
    end
  end

  @doc """
  Decodes a Base58Check string and verifies the checksum.

  Returns an error if the checksum is invalid.

  ## Parameters

  * `encoded` - The Base58Check encoded string

  ## Examples

      iex> Base58Check.decode("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
      {:ok, <<0x00, pubkey_hash::binary>>}
  """
  @spec decode(String.t()) :: {:ok, binary()} | {:error, term()}
  def decode(encoded) when is_binary(encoded) do
    ExBase58.decode_check(encoded, @alphabet)
  end

  @doc """
  Decodes a Base58Check string and verifies the checksum.

  As `decode/1` but returns the result or raises an exception.
  """
  @spec decode!(String.t()) :: binary()
  def decode!(encoded) do
    case decode(encoded) do
      {:ok, decoded} -> decoded
      {:error, error} -> raise ArgumentError, "Base58Check decoding failed: #{inspect(error)}"
    end
  end

  @doc """
  Encodes binary data with a version byte into a Base58Check string.

  The version byte is prepended to the data before encoding. This is the
  standard format for Bitcoin addresses where the version byte identifies
  the address type.

  ## Parameters

  * `data` - The binary data to encode (e.g., public key hash)
  * `version` - The version byte (e.g., `0x00` for mainnet P2PKH)

  ## Examples

      iex> Base58Check.encode_version(pubkey_hash, 0x00)
      {:ok, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"}

      iex> Base58Check.encode_version(script_hash, 0x05)
      {:ok, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"}
  """
  @spec encode_version(binary(), non_neg_integer()) :: {:ok, String.t()} | {:error, term()}
  def encode_version(data, version)
      when is_binary(data) and is_integer(version) and version >= 0 do
    ExBase58.encode_check_version(data, version, @alphabet)
  end

  @doc """
  Encodes binary data with a version byte into a Base58Check string.

  As `encode_version/2` but returns the result or raises an exception.
  """
  @spec encode_version!(binary(), non_neg_integer()) :: String.t()
  def encode_version!(data, version) do
    case encode_version(data, version) do
      {:ok, encoded} -> encoded
      {:error, error} -> raise ArgumentError, "Base58Check encoding failed: #{inspect(error)}"
    end
  end

  @doc """
  Decodes a Base58Check string and verifies both checksum and version byte.

  Returns `{:ok, data}` on success, where `data` is the decoded payload
  without the version byte. Returns an error if the version byte doesn't
  match the expected version.

  ## Parameters

  * `encoded` - The Base58Check encoded string
  * `expected_version` - The expected version byte for verification

  ## Examples

      iex> Base58Check.decode_version("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 0x00)
      {:ok, <<pubkey_hash::binary>>}
  """
  @spec decode_version(String.t(), non_neg_integer()) :: {:ok, binary()} | {:error, term()}
  def decode_version(encoded, expected_version)
      when is_binary(encoded) and is_integer(expected_version) and expected_version >= 0 do
    ExBase58.decode_check_version(encoded, expected_version, @alphabet)
  end

  @doc """
  Decodes a Base58Check string and verifies both checksum and version byte.

  As `decode_version/2` but returns the result or raises an exception.
  """
  @spec decode_version!(String.t(), non_neg_integer()) :: binary()
  def decode_version!(encoded, expected_version) do
    case decode_version(encoded, expected_version) do
      {:ok, result} -> result
      {:error, error} -> raise ArgumentError, "Base58Check decoding failed: #{inspect(error)}"
    end
  end
end
