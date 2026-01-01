defmodule Satoxi.Encoding.Bech32 do
  @moduledoc """
  `Bech32`/`Bech32m` encoding and decoding for SegWit addresses.

  ## What is Bech32?

  `Bech32` is a checksummed base32 encoding format defined in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
  It was designed specifically for Bitcoin's Segregated Witness (SegWit) addresses and offers several advantages over the legacy `Base58Check` encoding used in traditional Bitcoin addresses.

  ## Why Bech32 for Bitcoin?

  `Bech32` was introduced to solve practical problems with `Base58Check` addresses:

  * **Error detection** - Uses a `BCH` code that can detect up to 4 errors and locate up to 2 errors in addresses up to 89 characters. 
    This is significantly more robust than `Base58Check`'s simple checksum.

  * **Case insensitivity** - Uses only lowercase letters (or uppercase, but not mixed), eliminating transcription errors caused by confusing similar-looking characters like `1`/`l`/`I` or `0`/`O`.

  * **QR code efficiency** - When encoded in uppercase, `Bech32` addresses use alphanumeric QR mode, resulting in ~45% smaller QR codes compared to `Base58Check` addresses.

  * **Human readable prefix** - Addresses start with a clear prefix (`bc1` for mainnet, `tb1` for testnet) making it easy to identify the network and address type.

  ## Bech32 vs Bech32m

  `Bech32m` is a modified version of Bech32 defined in [BIP-0350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).
  It fixes a weakness in Bech32 where inserting or deleting `q` characters before a final `p` could sometimes go undetected.

  * **Bech32** - Used for SegWit v0 (witness version 0)
  * **Bech32m** - Used for SegWit v1+ (Taproot and future versions)

  ## Address formats

  * `bc1q...` - Mainnet native SegWit v0 (`P2WPKH` or `P2WSH`)
  * `tb1q...` - Testnet native SegWit v0
  * `bc1p...` - Mainnet native SegWit v1 (`Taproot`) - uses `Bech32m`
  * `tb1p...` - Testnet native SegWit v1 (`Taproot`) - uses `Bech32m`
  """

  @type bech32_decoded() ::
          {hrp :: String.t(), witness_version :: non_neg_integer(), witness_program :: binary()}

  @doc """
  Encodes a witness program into a `Bech32` address.

  ## Parameters

  * `hrp` - Human readable part (`"bc"` for mainnet, `"tb"` for testnet)
  * `witness_program` - The witness program bytes (20 or 32 bytes typically)

  ## Examples

      iex> Bech32.encode("bc", <<0::160>>)
      {:ok, "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs"}

      iex> Bech32.encode("bc", pubkey_hash)
      {:ok, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}
  """
  @spec encode(String.t(), binary()) :: {:ok, String.t()} | {:error, term()}
  def encode(hrp, witness_program)
      when is_binary(hrp) and is_binary(witness_program) do
    ExBech32.encode_with_version(hrp, 0, witness_program)
  end

  @doc """
  Encodes a witness program into a `Bech32` address.

  As `encode/2` but returns the result or raises an exception.
  """
  @spec encode!(String.t(), binary()) :: String.t()
  def encode!(hrp, witness_program) do
    case encode(hrp, witness_program) do
      {:ok, address} -> address
      {:error, error} -> raise ArgumentError, "Bech32 encoding failed: #{inspect(error)}"
    end
  end

  @doc """
  Encodes a witness program into a `Bech32m` address.

  ## Parameters

  * `hrp` - Human readable part (`"bc"` for mainnet, `"tb"` for testnet)
  * `witness_program` - The witness program bytes (20 or 32 bytes typically)

  ## Examples

      iex> Bech32.encode_m("bc", <<0::160>>)
      {:ok, "bc1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqmmente"}

      iex> Bech32.encode_m("bc", pubkey_hash)
      {:ok, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"}
  """
  @spec encode_m(String.t(), binary()) :: {:ok, String.t()} | {:error, term()}
  def encode_m(hrp, witness_program)
      when is_binary(hrp) and is_binary(witness_program) do
    ExBech32.encode_with_version(hrp, 1, witness_program)
  end

  @doc """
  Encodes a witness program into a `Bech32m` address.

  As `encode_m/2` but returns the result or raises an exception.
  """
  @spec encode_m!(String.t(), binary()) :: String.t()
  def encode_m!(hrp, witness_program) do
    case encode_m(hrp, witness_program) do
      {:ok, address} -> address
      {:error, error} -> raise ArgumentError, "Bech32 encoding failed: #{inspect(error)}"
    end
  end

  @doc """
  Decodes a `Bech32`/`Bech32m` address into its components.

  ## Examples

      iex> Bech32.decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
      {:ok, {"bc", 0, <<117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214>>}}
  """
  @spec decode(String.t()) :: {:ok, bech32_decoded()} | {:error, term()}
  def decode(address) when is_binary(address) do
    ExBech32.decode_with_version(address)
  end

  @doc """
  Decodes a `Bech32`/`Bech32m` address into its components.

  As `decode/1` but returns the result or raises an exception.
  """
  @spec decode!(String.t()) :: bech32_decoded()
  def decode!(address) do
    case decode(address) do
      {:ok, result} -> result
      {:error, error} -> raise ArgumentError, "Bech32 decoding failed: #{inspect(error)}"
    end
  end
end
