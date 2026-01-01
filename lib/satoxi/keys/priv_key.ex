defmodule Satoxi.Keys.PrivKey do
  @moduledoc """
  Functions for generating, parsing, and encoding Bitcoin private keys.

  A private key is a 256-bit number used to sign transactions and derive public keys. 
  This module provides a struct `t:Satoxi.Keys.PrivKey.t/0` that wraps the raw private key binary along with a flag indicating whether the corresponding public key should be compressed.

  ## Wallet Import Format (WIF)

  WIF is the standard format for representing private keys in Bitcoin wallets.
  It includes a version byte (network-specific) and a checksum for error detection. 
  Use `from_wif/1` and `to_wif/1` to convert between WIF strings and private key structs.

  ## Examples

      # Generate a new random private key
      privkey = Satoxi.Keys.PrivKey.new()

      # Parse from hex-encoded string
      {:ok, privkey} = Satoxi.Keys.PrivKey.from_binary("3cff04...", encoding: :hex)

      # Parse from WIF
      {:ok, privkey} = Satoxi.Keys.PrivKey.from_wif("KyGHAK8MNohVPdeGPYXveiAbTfLARVrQuJVtd3qMqN41UEnTWDkF")

      # Export to WIF
      wif = Satoxi.Keys.PrivKey.to_wif(privkey)
  """
  import Satoxi.Encoding, only: [decode: 2, encode: 2]

  defstruct d: nil, compressed: true

  @typedoc "Private key struct"
  @type t() :: %__MODULE__{
          d: privkey_bin(),
          compressed: boolean()
        }

  @typedoc "Private key 256-bit binary"
  @type privkey_bin() :: <<_::256>>

  @typedoc """
  Wallet Import Format private key

  WIF encoded keys is a common way to represent private Keys in Bitcoin. 
  WIF encoded keys are shorter and include a built-in error checking and a type byte.
  """
  @type privkey_wif() :: String.t()

  @version_bytes %{
    main: <<0x80>>,
    test: <<0xEF>>
  }

  @doc """
  Generates and returns a new `t:Satoxi.Keys.PrivKey.t/0`.

  ## Options

  The accepted options are:

  * `:compressed` - Denotes whether the correspding `t:Satoxi.Keys.PubKey.t/0` is compressed on not. Defaults `true`.
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    {_pubkey, privkey} = :crypto.generate_key(:ecdh, :secp256k1)

    from_binary!(privkey, opts)
  end

  @doc """
  Parses the given binary into a `t:Satoxi.Keys.PrivKey.t/0`.

  ## Options

  The accepted options are:

  * `:compressed` - Denotes whether the corresponding `t:Satoxi.Keys.PubKey.t/0` is compressed on not. Defaults `true`.
  * `:encoding` - Optionally decode the binary with either the `:base64` or `:hex` encoding scheme.

  ## Examples

      iex> Satoxi.Keys.PrivKey.from_binary("3cff04633088622e4599dc2ebf843f82cef3463b910d34a752a13622abae379b", encoding: :hex)
      {:ok, %Satoxi.Keys.PrivKey{
        d: <<60, 255, 4, 99, 48, 136, 98, 46, 69, 153, 220, 46, 191, 132, 63, 130, 206, 243, 70, 59, 145, 13, 52, 167, 82, 161, 54, 34, 171, 174, 55, 155>>
      }}
  """
  @spec from_binary(binary(), keyword()) :: {:ok, t()} | {:error, term()}
  def from_binary(privkey, opts \\ []) when is_binary(privkey) do
    encoding = Keyword.get(opts, :encoding)
    compressed = Keyword.get(opts, :compressed, true)

    case decode(privkey, encoding) do
      {:ok, <<d::binary-32>>} ->
        {:ok, %__MODULE__{d: d, compressed: compressed}}

      {:ok, d} ->
        {:error, {:invalid_privkey, byte_size(d)}}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Parses the given binary into a `t:Satoxi.Keys.PrivKey.t/0`.

  As `from_binary/2` but returns the result or raises an exception.
  """
  @spec from_binary!(binary(), keyword()) :: t()
  def from_binary!(privkey, opts \\ []) when is_binary(privkey) do
    case from_binary(privkey, opts) do
      {:ok, privkey} ->
        privkey

      {:error, error} ->
        raise Satoxi.Error, error
    end
  end

  @doc """
  Serialises the given `t:Satoxi.Keys.PrivKey.t/0` into a binary.

  ## Options

  The accepted options are:

  * `:encoding` - Optionally encode the binary with either the `:base64` or `:hex` encoding scheme.

  ## Examples

      iex> privkey = Satoxi.Keys.PrivKey.from_binary!(<<176, 14, 133, 141, 225, 114,
      ...> 232, 148, 86, 86, 29, 196, 85, 236, 98, 215, 206, 45, 206, 36, 163, 
      ...> 130, 35, 122, 74, 68, 137, 95, 245, 11, 53, 133>>)
      %Satoxi.Keys.PrivKey{
        d: <<176, 14, 133, 141, 225, 114, 232, 148, 86, 86, 29,
          196, 85, 236, 98, 215, 206, 45, 206, 36, 163, 130, 35,
          122, 74, 68, 137, 95, 245, 11, 53, 133>>,
        compressed: true
      }
      iex> Satoxi.Keys.PrivKey.to_binary(privkey, encoding: :hex)
      "b00e858de172e89456561dc455ec62d7ce2dce24a382237a4a44895ff50b3585"
  """
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{d: d}, opts \\ []) do
    encoding = Keyword.get(opts, :encoding)

    encode(d, encoding)
  end

  @doc """
  Decodes the given `t:Satoxi.Keys.PrivKey.privkey_wif/0` into a `t:Satoxi.Keys.PrivKey.t/0`.

  ## Examples

      iex> Satoxi.Keys.PrivKey.from_wif("KyGHAK8MNohVPdeGPYXveiAbTfLARVrQuJVtd3qMqN41UEnTWDkF")
      {:ok, %Satoxi.Keys.PrivKey{
        d: <<60, 255, 4, 99, 48, 136, 98, 46, 69, 153, 220, 46, 191, 132, 63, 130, 206, 243, 70, 59, 145, 13, 52, 167, 82, 161, 54, 34, 171, 174, 55, 155>>
      }}
  """
  @spec from_wif(privkey_wif()) :: {:ok, t()} | {:error, term()}
  def from_wif(wif) when is_binary(wif) do
    <<expected_version>> = @version_bytes[Satoxi.network()]

    case ExBase58.decode_check(wif) do
      {:ok, <<^expected_version, d::binary-32, 1>>} ->
        {:ok, struct(__MODULE__, d: d, compressed: true)}

      {:ok, <<^expected_version, d::binary-32>>} ->
        {:ok, struct(__MODULE__, d: d, compressed: false)}

      {:ok, <<version_byte, d::binary>>} when byte_size(d) in [32, 33] ->
        {:error, {:invalid_base58_check, <<version_byte>>, Satoxi.network()}}

      _error ->
        {:error, :invalid_wif}
    end
  end

  @doc """
  Decodes the given `t:Satoxi.Keys.PrivKey.privkey_wif/0` into a `t:Satoxi.Keys.PrivKey.t/0`.

  As `from_wif/1` but returns the result or raises an exception.
  """
  @spec from_wif!(privkey_wif()) :: t()
  def from_wif!(wif) when is_binary(wif) do
    case from_wif(wif) do
      {:ok, privkey} ->
        privkey

      {:error, error} ->
        raise Satoxi.Error, error
    end
  end

  @doc """
  Encodes the given `t:Satoxi.Keys.PrivKey.t/0` as a `t:Satoxi.Keys.PrivKey.privkey_wif/0`.

  ## Examples

      iex> privkey = Satoxi.Keys.PrivKey.from_binary!(<<176, 14, 133, 141, 225, 114,
      ...> 232, 148, 86, 86, 29, 196, 85, 236, 98, 215, 206, 45, 206, 36, 163, 
      ...> 130, 35, 122, 74, 68, 137, 95, 245, 11, 53, 133>>)
      %Satoxi.Keys.PrivKey{
        d: <<176, 14, 133, 141, 225, 114, 232, 148, 86, 86, 29,
          196, 85, 236, 98, 215, 206, 45, 206, 36, 163, 130, 35,
          122, 74, 68, 137, 95, 245, 11, 53, 133>>,
        compressed: true
      }
      iex> Satoxi.Keys.PrivKey.to_wif(privkey)
      {:ok, "L37wbeJ1YGLxMnAA8yfXYNYsV5PWLQ2EG88jmb9npG4x6wpmTvpa"}
  """
  @spec to_wif(t()) :: {:ok, privkey_wif()} | {:error, atom()}
  def to_wif(%__MODULE__{d: d, compressed: compressed}) when is_binary(d) do
    <<version_byte>> = @version_bytes[Satoxi.network()]

    privkey_with_suffix =
      if compressed do
        <<d::binary, 0x01>>
      else
        d
      end

    ExBase58.encode_check_version(privkey_with_suffix, version_byte)
  end

  @doc """
  Encodes the given `t:Satoxi.Keys.PrivKey.t/0` as a `t:Satoxi.Keys.PrivKey.privkey_wif/0`.

  As `to_wif/1` but returns the result or raises an exception.
  """
  @spec to_wif!(t()) :: privkey_wif()
  def to_wif!(%__MODULE__{} = privkey) do
    case to_wif(privkey) do
      {:ok, wif} ->
        wif

      {:error, error} ->
        raise Satoxi.Error, error
    end
  end
end
