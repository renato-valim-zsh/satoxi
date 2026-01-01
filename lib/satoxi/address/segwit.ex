defmodule Satoxi.Address.SegWit do
  @moduledoc """
  Native SegWit Bitcoin addresses (`P2WPKH` and `P2WSH`).

  These addresses use `Bech32` encoding and start with:
  - `bc1q` on mainnet (witness version 0)
  - `tb1q` on testnet (witness version 0)

  ## Address Types

  | Type     | Program Size | Description                    |
  |----------|--------------|--------------------------------|
  | `P2WPKH` | 20 bytes     | Pay-to-Witness-Public-Key-Hash |
  | `P2WSH`  | 32 bytes     | Pay-to-Witness-Script-Hash     |

  ## Examples

      iex> pubkey = <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232,
      ...>            175, 144, 63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
      iex> address = Satoxi.Address.SegWit.from_pubkey(pubkey)
      iex> address.type
      :p2wpkh
  """
  alias Satoxi.{Hash, Encoding.Bech32, Keys.PubKey}

  defstruct [:witness_program, :witness_version, :type]

  @typedoc "SegWit address type"
  @type segwit_type() :: :p2wpkh | :p2wsh

  @typedoc "Native SegWit address"
  @type t() :: %__MODULE__{
          witness_program: binary(),
          witness_version: non_neg_integer(),
          type: segwit_type()
        }

  @hrp %{
    main: "bc",
    test: "tb"
  }

  @doc """
  Creates a `P2WPKH` address from a public key.

  ## Examples

      iex> pubkey = <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232,
      ...>            175, 144, 63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
      iex> address = Satoxi.Address.SegWit.from_pubkey(pubkey)
      iex> address.type
      :p2wpkh
      iex> address.witness_version
      0
  """
  @spec from_pubkey(PubKey.t() | binary()) :: t()
  def from_pubkey(%PubKey{} = pubkey) do
    pubkey
    |> PubKey.to_binary()
    |> from_pubkey()
  end

  def from_pubkey(pubkey) when is_binary(pubkey) and byte_size(pubkey) in [33, 65] do
    pubkey_hash = Hash.sha256_ripemd160(pubkey)

    %__MODULE__{
      witness_program: pubkey_hash,
      witness_version: 0,
      type: :p2wpkh
    }
  end

  @doc """
  Creates a `P2WPKH` address from a pubkey hash.

  ## Examples

      iex> hash = <<83, 143, 209, 121, 200, 190, 15, 40, 156, 115, 14, 51, 181, 246, 163, 84, 27, 233, 102, 143>>
      iex> address = Satoxi.Address.SegWit.from_pubkey_hash(hash)
      iex> address.type
      :p2wpkh
  """
  @spec from_pubkey_hash(binary()) :: t()
  def from_pubkey_hash(pubkey_hash) when byte_size(pubkey_hash) == 20 do
    %__MODULE__{
      witness_program: pubkey_hash,
      witness_version: 0,
      type: :p2wpkh
    }
  end

  @doc """
  Creates a `P2WSH` address from a witness script hash.

  The script_hash should be the `SHA256` hash of the witness script (32 bytes).

  ## Examples

      iex> script_hash = :crypto.hash(:sha256, <<1, 2, 3>>)
      iex> address = Satoxi.Address.SegWit.from_witness_script_hash(script_hash)
      iex> address.type
      :p2wsh
      iex> address.witness_version
      0
  """
  @spec from_witness_script_hash(binary()) :: t()
  def from_witness_script_hash(script_hash) when byte_size(script_hash) == 32 do
    %__MODULE__{
      witness_program: script_hash,
      witness_version: 0,
      type: :p2wsh
    }
  end

  @doc """
  Creates a `P2WSH` address from a witness script.

  Computes the `SHA256` of the script and creates the address.

  ## Examples

      iex> witness_script = <<0x51, 0x21>> <> <<1::264>> <> <<0x51, 0xAE>>
      iex> address = Satoxi.Address.SegWit.from_witness_script(witness_script)
      iex> address.type
      :p2wsh
  """
  @spec from_witness_script(binary()) :: t()
  def from_witness_script(witness_script) when is_binary(witness_script) do
    script_hash = :crypto.hash(:sha256, witness_script)

    %__MODULE__{
      witness_program: script_hash,
      witness_version: 0,
      type: :p2wsh
    }
  end

  @doc """
  Decodes a `Bech32` encoded SegWit address string.

  ## Examples

      iex> {:ok, address} = Satoxi.Address.SegWit.from_string("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
      iex> address.type
      :p2wpkh
      iex> address.witness_version
      0
  """
  @spec from_string(String.t()) :: {:ok, t()} | {:error, term()}
  def from_string(address) when is_binary(address) do
    network = Satoxi.network()
    expected_hrp = @hrp[network]

    case Bech32.decode(address) do
      {:ok, {^expected_hrp, witness_version, witness_program}} ->
        case determine_type(witness_version, witness_program) do
          {:ok, type} ->
            {:ok,
             %__MODULE__{
               witness_program: witness_program,
               witness_version: witness_version,
               type: type
             }}

          {:error, _} = error ->
            error
        end

      {:ok, {hrp, _version, _program}} ->
        {:error, {:invalid_hrp, hrp, expected_hrp}}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Decodes a `Bech32` encoded SegWit address string.

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
  Encodes the address to a `Bech32` string.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{witness_program: program, witness_version: 0}) do
    hrp = @hrp[Satoxi.network()]
    Bech32.encode!(hrp, program)
  end

  @doc """
  Returns the witness program (pubkey hash or script hash).
  """
  @spec get_witness_program(t()) :: binary()
  def get_witness_program(%__MODULE__{witness_program: program}), do: program

  @doc """
  Returns true if this is a `P2WPKH` address.
  """
  @spec p2wpkh?(t()) :: boolean()
  def p2wpkh?(%__MODULE__{type: :p2wpkh}), do: true
  def p2wpkh?(_), do: false

  @doc """
  Returns true if this is a `P2WSH` address.
  """
  @spec p2wsh?(t()) :: boolean()
  def p2wsh?(%__MODULE__{type: :p2wsh}), do: true
  def p2wsh?(_), do: false

  # Determine SegWit type from witness version and program size
  defp determine_type(0, program) when byte_size(program) == 20, do: {:ok, :p2wpkh}
  defp determine_type(0, program) when byte_size(program) == 32, do: {:ok, :p2wsh}

  defp determine_type(version, program) do
    {:error, {:invalid_witness_program, version, byte_size(program)}}
  end

  defimpl Satoxi.Address.Encoding do
    def to_string(address), do: Satoxi.Address.SegWit.to_string(address)
    def get_hash(address), do: Satoxi.Address.SegWit.get_witness_program(address)
  end
end
