defmodule Satoxi.Address do
  @moduledoc """
  Bitcoin address generation, parsing, and encoding utilities.

  This module supports multiple address formats:

  * **Legacy P2PKH** - Addresses starting with `1` (mainnet) or `m`/`n` (testnet)
  * **P2SH** - Addresses starting with `3` (mainnet) or `2` (testnet)
  * **Native SegWit P2WPKH** - `Bech32` addresses starting with `bc1q` (mainnet) or `tb1q` (testnet)
  * **Native SegWit P2WSH** - `Bech32` addresses with 32-byte program
  * **Nested SegWit** - `P2SH`-wrapped SegWit for compatibility (BIP-49)

  ## Address Types

  | Name                           | Module              | Format        | Prefix (mainnet) |
  |--------------------------------|---------------------|---------------|------------------|
  | Pay-to-Public-Key-Hash         | `Address.Legacy`    | `Base58Check` | `1`              |
  | Pay-to-Script-Hash             | `Address.P2SH`      | `Base58Check` | `3`              |
  | Pay-to-Witness-Public-Key-Hash | `Address.SegWit`    | `Bech32`      | `bc1q`           |
  | Pay-to-Witness-Script-Hash     | `Address.SegWit`    | `Bech32`      | `bc1q`           |
  | Nested SegWit (`P2SH-P2WPKH`)  | `Address.Nested`    | `Base58Check` | `3`              |

  ## Usage

  You can work directly with submodules for specific address types:

      # Create a legacy address
      legacy = Satoxi.Address.Legacy.from_pubkey(pubkey)

      # Create a native SegWit address
      segwit = Satoxi.Address.SegWit.from_pubkey(pubkey)

  Or use the unified functions in this module:

      # Parse any address format
      {:ok, address} = Satoxi.Address.from_string("bc1q...")

      # Create address from pubkey with type option
      address = Satoxi.Address.from_pubkey(pubkey, type: :p2wpkh)
  """

  alias Satoxi.Address.{Encoding, Legacy, Nested, P2SH, SegWit}
  alias Satoxi.Keys.PubKey

  @typedoc "Any supported address type"
  @type t() :: Legacy.t() | P2SH.t() | SegWit.t() | Nested.t()

  @typedoc "Address type identifier"
  @type address_type() :: :p2pkh | :p2sh | :p2wpkh | :p2wsh | :p2sh_p2wpkh

  @typedoc "Bitcoin address string (`Base58Check` or `Bech32` encoded)"
  @type address_str() :: String.t()

  # ============================================================================
  # Unified Functions
  # ============================================================================

  @doc """
  Creates an address from a public key.

  ## Options

  * `:type` - The address type to create. Defaults to `:p2pkh`.
    Supported types: `:p2pkh`, `:p2wpkh`, `:p2sh_p2wpkh`

  ## Examples

      iex> pubkey = <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232,
      ...>            175, 144, 63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
      iex> legacy_address = Satoxi.Address.from_pubkey(pubkey)
      iex> Satoxi.Address.to_string(legacy_address)
      "18cqNbEBxkAttxcZLuH9LWhZJPd1BNu1A5"
      iex> segwit_address = Satoxi.Address.from_pubkey(pubkey, type: :p2wpkh)
      iex> Satoxi.Address.to_string(segwit_address)
      "bc1q2w8az7wghc8j38rnpcemta4r2sd7je50p3spfn"
  """
  @spec from_pubkey(PubKey.t() | binary(), keyword()) :: t()
  def from_pubkey(pubkey, opts \\ []) do
    type = Keyword.get(opts, :type, :p2pkh)

    case type do
      :p2pkh -> Legacy.from_pubkey(pubkey)
      :p2wpkh -> SegWit.from_pubkey(pubkey)
      :p2sh_p2wpkh -> Nested.from_pubkey(pubkey)
    end
  end

  @doc """
  Parses an address string and returns the appropriate address struct.

  Automatically detects the address format (`Base58Check` or `Bech32`) and type.

  ## Examples

      iex> {:ok, address} = Satoxi.Address.from_string("18cqNbEBxkAttxcZLuH9LWhZJPd1BNu1A5")
      iex> match?(%Satoxi.Address.Legacy{}, address)
      true

      iex> {:ok, address} = Satoxi.Address.from_string("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
      iex> match?(%Satoxi.Address.SegWit{}, address)
      true
  """
  @spec from_string(address_str()) :: {:ok, t()} | {:error, term()}
  def from_string(address) when is_binary(address) do
    if bech32_address?(address) do
      SegWit.from_string(address)
    else
      # Try Legacy first, then P2SH
      case Legacy.from_string(address) do
        {:ok, _} = result ->
          result

        {:error, {:invalid_version_byte, _, _}} ->
          P2SH.from_string(address)

        {:error, _} = error ->
          error
      end
    end
  end

  @doc """
  Parses an address string and returns the appropriate address struct.

  As `from_string/1` but returns the result or raises an exception.
  """
  @spec from_string!(address_str()) :: t()
  def from_string!(address) do
    case from_string(address) do
      {:ok, addr} -> addr
      {:error, error} -> raise Satoxi.Error, error
    end
  end

  @doc """
  Encodes an address to its string representation.

  Uses the `Satoxi.Address.Encoding` protocol.

  ## Examples

      iex> pubkey = <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232,
      ...>            175, 144, 63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
      iex> address = Satoxi.Address.Legacy.from_pubkey(pubkey)
      iex> Satoxi.Address.to_string(address)
      "18cqNbEBxkAttxcZLuH9LWhZJPd1BNu1A5"
  """
  @spec to_string(t()) :: address_str()
  def to_string(address) do
    Encoding.to_string(address)
  end

  @doc """
  Returns the hash data from an address.

  For `P2PKH`/`P2WPKH` addresses, returns the pubkey hash.
  For `P2SH`/`Nested` addresses, returns the script hash.
  For `P2WSH` addresses, returns the witness script hash.
  """
  @spec get_hash(t()) :: binary()
  def get_hash(address) do
    Encoding.get_hash(address)
  end

  @doc """
  Returns the address type as an atom.

  ## Examples

      iex> pubkey = <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232,
      ...>            175, 144, 63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
      iex> address = Satoxi.Address.Legacy.from_pubkey(pubkey)
      iex> Satoxi.Address.type(address)
      :p2pkh

      iex> pubkey = <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232,
      ...>            175, 144, 63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
      iex> address = Satoxi.Address.SegWit.from_pubkey(pubkey)
      iex> Satoxi.Address.type(address)
      :p2wpkh
  """
  @spec type(address :: t()) :: address_type()
  def type(%Legacy{} = _address), do: :p2pkh
  def type(%P2SH{} = _address), do: :p2sh
  def type(%SegWit{type: type} = _address), do: type
  def type(%Nested{} = _address), do: :p2sh_p2wpkh

  # ============================================================================
  # Legacy Delegates
  # ============================================================================

  @doc """
  Creates a Legacy `P2PKH` address from a public key.

  See `Satoxi.Address.Legacy.from_pubkey/1` for details.
  """
  defdelegate legacy_from_pubkey(pubkey), to: Legacy, as: :from_pubkey

  @doc """
  Creates a Legacy `P2PKH` address from a pubkey hash.

  See `Satoxi.Address.Legacy.from_pubkey_hash/1` for details.
  """
  defdelegate legacy_from_pubkey_hash(hash), to: Legacy, as: :from_pubkey_hash

  # ============================================================================
  # P2SH Delegates
  # ============================================================================

  @doc """
  Creates a `P2SH` address from a script hash.

  See `Satoxi.Address.P2SH.from_script_hash/1` for details.
  """
  defdelegate p2sh_from_script_hash(hash), to: P2SH, as: :from_script_hash

  @doc """
  Creates a `P2SH` address from a redeem script.

  See `Satoxi.Address.P2SH.from_script/1` for details.
  """
  defdelegate p2sh_from_script(script), to: P2SH, as: :from_script

  # ============================================================================
  # SegWit Delegates
  # ============================================================================

  @doc """
  Creates a `P2WPKH` address from a public key.

  See `Satoxi.Address.SegWit.from_pubkey/1` for details.
  """
  defdelegate segwit_from_pubkey(pubkey), to: SegWit, as: :from_pubkey

  @doc """
  Creates a `P2WPKH` address from a pubkey hash.

  See `Satoxi.Address.SegWit.from_pubkey_hash/1` for details.
  """
  defdelegate segwit_from_pubkey_hash(hash), to: SegWit, as: :from_pubkey_hash

  @doc """
  Creates a `P2WSH` address from a witness script hash.

  See `Satoxi.Address.SegWit.from_witness_script_hash/1` for details.
  """
  defdelegate segwit_from_witness_script_hash(hash), to: SegWit, as: :from_witness_script_hash

  @doc """
  Creates a `P2WSH` address from a witness script.

  See `Satoxi.Address.SegWit.from_witness_script/1` for details.
  """
  defdelegate segwit_from_witness_script(script), to: SegWit, as: :from_witness_script

  # ============================================================================
  # Nested SegWit Delegates
  # ============================================================================

  @doc """
  Creates a Nested SegWit (`P2SH-P2WPKH`) address from a public key.

  See `Satoxi.Address.Nested.from_pubkey/1` for details.
  """
  defdelegate nested_from_pubkey(pubkey), to: Nested, as: :from_pubkey

  @doc """
  Creates a Nested SegWit (`P2SH-P2WPKH`) address from a pubkey hash.

  See `Satoxi.Address.Nested.from_pubkey_hash/1` for details.
  """
  defdelegate nested_from_pubkey_hash(hash), to: Nested, as: :from_pubkey_hash

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp bech32_address?(address) do
    lower = String.downcase(address)
    String.starts_with?(lower, "bc1") or String.starts_with?(lower, "tb1")
  end
end
