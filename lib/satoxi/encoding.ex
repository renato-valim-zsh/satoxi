defmodule Satoxi.Encoding do
  @moduledoc """
  Encoding and decoding utilities for various Bitcoin data formats.

  Supports [Bech32](https://hexdocs.pm/satoxi/Satoxi.Encoding.Bech32.html),
  [Base58Check](https://hexdocs.pm/satoxi/Satoxi.Encoding.Base58Check.html),
  [VarInt](https://hexdocs.pm/satoxi/Satoxi.Encoding.VarInt.html),
  and other encodings commonly used in Bitcoin applications.
  """

  @typedoc "Binary encoding format"
  @type encoding() :: :base64 | :hex | :var_int

  # ============================================================================
  # Bech32
  # ============================================================================

  @doc """
  Encodes a witness program into a `Bech32` address.

  See `Satoxi.Encoding.Bech32.encode/2` for details.
  """
  defdelegate encode_bech32(hrp, witness_program),
    to: Satoxi.Encoding.Bech32,
    as: :encode

  @doc """
  Encodes a witness program into a `Bech32` address.

  As `encode_bech32/2` but returns the result or raises an exception.
  """
  defdelegate encode_bech32!(hrp, witness_program),
    to: Satoxi.Encoding.Bech32,
    as: :encode!

  @doc """
  Encodes a witness program into a `Bech32m` address.

  See `Satoxi.Encoding.Bech32.encode_m/2` for details.
  """
  defdelegate encode_bech32m(hrp, witness_program),
    to: Satoxi.Encoding.Bech32,
    as: :encode_m

  @doc """
  Encodes a witness program into a `Bech32m` address.

  As `encode_bech32m/2` but returns the result or raises an exception.
  """
  defdelegate encode_bech32m!(hrp, witness_program),
    to: Satoxi.Encoding.Bech32,
    as: :encode_m!

  @doc """
  Decodes a `Bech32`/`Bech32m` address into its components.

  See `Satoxi.Encoding.Bech32.decode/1` for details.
  """
  defdelegate decode_bech32(data),
    to: Satoxi.Encoding.Bech32,
    as: :decode

  @doc """
  Decodes a `Bech32`/`Bech32m` address into its components.

  As `decode_bech32/1` but returns the result or raises an exception.
  """
  defdelegate decode_bech32!(data),
    to: Satoxi.Encoding.Bech32,
    as: :decode!

  # ============================================================================
  # Base58Check
  # ============================================================================

  @doc """
  Encodes binary data into a `Base58Check` string.

  See `Satoxi.Encoding.Base58Check.encode/1` for details.
  """
  defdelegate encode_base58check(data),
    to: Satoxi.Encoding.Base58Check,
    as: :encode

  @doc """
  Encodes binary data into a `Base58Check` string.

  As `encode_base58check/1` but returns the result or raises an exception.
  """
  defdelegate encode_base58check!(data),
    to: Satoxi.Encoding.Base58Check,
    as: :encode!

  @doc """
  Decodes a `Base58Check` string and verifies the checksum.

  See `Satoxi.Encoding.Base58Check.decode/1` for details.
  """
  defdelegate decode_base58check(encoded),
    to: Satoxi.Encoding.Base58Check,
    as: :decode

  @doc """
  Decodes a `Base58Check` string and verifies the checksum.

  As `decode_base58check/1` but returns the result or raises an exception.
  """
  defdelegate decode_base58check!(encoded),
    to: Satoxi.Encoding.Base58Check,
    as: :decode!

  @doc """
  Encodes binary data with a version byte into a `Base58Check` string.

  See `Satoxi.Encoding.Base58Check.encode_version/2` for details.
  """
  defdelegate encode_base58check_version(data, version),
    to: Satoxi.Encoding.Base58Check,
    as: :encode_version

  @doc """
  Encodes binary data with a version byte into a `Base58Check` string.

  As `encode_base58check_version/2` but returns the result or raises an exception.
  """
  defdelegate encode_base58check_version!(data, version),
    to: Satoxi.Encoding.Base58Check,
    as: :encode_version!

  @doc """
  Decodes a `Base58Check` string and verifies both checksum and version byte.

  Returns `{:ok, data}` on success. See `Satoxi.Encoding.Base58Check.decode_version/2` for details.
  """
  defdelegate decode_base58check_version(encoded, expected_version),
    to: Satoxi.Encoding.Base58Check,
    as: :decode_version

  @doc """
  Decodes a `Base58Check` string and verifies both checksum and version byte.

  As `decode_base58check_version/2` but returns the result or raises an exception.
  """
  defdelegate decode_base58check_version!(encoded, expected_version),
    to: Satoxi.Encoding.Base58Check,
    as: :decode_version!

  # ============================================================================
  # VarInt
  # ============================================================================

  @doc """
  Prepends the given binary with a VarInt representing the length of the binary.

  See `Satoxi.Encoding.VarInt.encode_binary/1` for details.
  """
  defdelegate encode_varint_binary(data), to: Satoxi.Encoding.VarInt, as: :encode_binary

  @doc """
  Returns a binary of the length specified by the VarInt in the first bytes of the binary.

  See `Satoxi.Encoding.VarInt.decode_binary/1` for details.
  """
  defdelegate decode_varint_binary(data), to: Satoxi.Encoding.VarInt, as: :decode_binary

  @doc """
  Parses the given binary, returning a tuple with a binary of the length
  specified by the VarInt in the first bytes, and any remaining bytes.

  See `Satoxi.Encoding.VarInt.parse_data/1` for details.
  """
  defdelegate parse_varint_data(data), to: Satoxi.Encoding.VarInt, as: :parse_data

  @doc """
  Parses the given binary, returning a tuple with an integer decoded from the
  VarInt in the first bytes, and any remaining bytes.

  See `Satoxi.Encoding.VarInt.parse_int/1` for details.
  """
  defdelegate parse_varint_int(data), to: Satoxi.Encoding.VarInt, as: :parse_int

  @doc """
  Parses the given binary into a list of items using the specified `t:Satoxi.Serializable.t/0` module.

  See `Satoxi.Encoding.VarInt.parse_items/2` for details.
  """
  defdelegate parse_varint_items(data, mod), to: Satoxi.Encoding.VarInt, as: :parse_items

  @doc """
  Encodes the given binary or integer data using the specified `t:Satoxi.Encoding.encoding/0`.
  If encoding is not supported, the data is returned as-is

  ## Examples

      iex> Satoxi.Encoding.encode("hello world", :base64)
      "aGVsbG8gd29ybGQ="

      iex> Satoxi.Encoding.encode("hello world", :hex)
      "68656c6c6f20776f726c64"

      iex> Satoxi.Encoding.encode("hello world", :not_supported)
      "hello world"

      iex> Satoxi.Encoding.encode(100_000_000, :var_int)
      <<254, 0, 225, 245, 5>>
  """
  @spec encode(binary() | integer(), encoding()) :: binary()
  def encode(data, :base64), do: Base.encode64(data)
  def encode(data, :hex), do: Base.encode16(data, case: :lower)
  def encode(data, :var_int) when is_integer(data), do: Satoxi.Encoding.VarInt.encode(data)
  def encode(data, _), do: data

  @doc """
  Decodes the given binary data using the specified `t:Satoxi.Encoding.encoding/0`.
  If encoding is not supported, the data is returned as-is

  ## Examples

      iex> Satoxi.Encoding.decode("aGVsbG8gd29ybGQ=", :base64)
      {:ok, "hello world"}

      iex> Satoxi.Encoding.decode("68656c6c6f20776f726c64", :hex)
      {:ok, "hello world"}
      
      iex> Satoxi.Encoding.decode("abcdefg", :hex)
      {:error, {:decoding_failed, :hex, "abcdefg"}}
      
      iex> Satoxi.Encoding.decode("0x00fff", :not_supported)
      {:ok, "0x00fff"}
  """
  @spec decode(binary(), encoding()) ::
          {:ok, binary()} | {:error, {:decoding_failed, encoding(), binary()}}
  def decode(data, :base64) when is_binary(data) do
    with :error <- Base.decode64(data) do
      {:error, {:decoding_failed, :base64, data}}
    end
  end

  def decode(data, :hex) when is_binary(data) do
    with :error <- Base.decode16(data, case: :mixed) do
      {:error, {:decoding_failed, :hex, data}}
    end
  end

  def decode(data, :var_int) when is_binary(data) do
    with {:error, _error} <- Satoxi.Encoding.VarInt.decode(data) do
      {:error, {:decoding_failed, :var_int, data}}
    end
  end

  def decode(data, _), do: {:ok, data}

  @doc """
  Decodes the given binary data using the specified `t:Satoxi.Encoding.encoding/0`.
  If encoding is not supported, the data is returned as-is

  As `decode/2` but returns the result or raises an exception.
  """
  @spec decode!(binary(), encoding()) :: binary()
  def decode!(data, encoding) do
    case decode(data, encoding) do
      {:ok, decoded} ->
        decoded

      {:error, error} ->
        raise Satoxi.Error, error
    end
  end
end
