defmodule Satoxi.Transaction.PreImage do
  @moduledoc """
  Module for generating Bitcoin transaction preimages for signing.

  A preimage is the data that gets hashed to produce the message that is signed by a private key. 
  Different sighash flags control which parts of the transaction are included in the preimage.

  ## Sighash Flags

  | Flag                            | Value                    | Description                         |
  | ------------------------------- | ------------------------ | ----------------------------------- |
  | `SIGHASH_ALL`                   | `0x01` / `0000 0001`     | Sign all inputs and outputs         |
  | `SIGHASH_NONE`                  | `0x02` / `0000 0010`     | Sign all inputs and no outputs      |
  | `SIGHASH_SINGLE`                | `0x03` / `0000 0011`     | Sign all inputs and single output   |
  | `SIGHASH_ALL / ANYONECANPAY`    | `0x81` / `1000 0001`     | Sign single input and all outputs   |
  | `SIGHASH_NONE / ANYONECANPAY`   | `0x82` / `1000 0010`     | Sign single input and no outputs    |
  | `SIGHASH_SINGLE / ANYONECANPAY` | `0x83` / `1000 0011`     | Sign single input and single output |

  ## Legacy vs SegWit

  - Use `legacy/4` for legacy (non-SegWit) transactions
  - Use `segwit/4` for SegWit transactions (implements [BIP-143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#user-content-Specification))

  ## Example

      # Legacy preimage
      preimage = PreImage.legacy(tx, 0, output, 0x01)
      sighash = Hash.sha256_sha256(preimage)

      # SegWit preimage (BIP-143)
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)
      preimage = PreImage.segwit(tx, 0, output, script_code)
      sighash = Hash.sha256_sha256(preimage)
  """
  alias Satoxi.Hash
  alias Satoxi.Script
  alias Satoxi.Transaction
  alias Satoxi.Transaction.Input
  alias Satoxi.Transaction.OutPoint
  alias Satoxi.Transaction.Output

  import Satoxi.Encoding, only: [encode_varint_binary: 1]
  import Bitwise

  @sighash_all 0x01
  @sighash_none 0x02
  @sighash_single 0x03
  @sighash_anyonecanpay 0x80

  defguard sighash_all?(sighash_flag)
           when (sighash_flag &&& 31) == @sighash_all

  defguard sighash_none?(sighash_flag)
           when (sighash_flag &&& 31) == @sighash_none

  defguard sighash_single?(sighash_flag)
           when (sighash_flag &&& 31) == @sighash_single

  defguard sighash_anyone_can_pay?(sighash_flag)
           when (sighash_flag &&& @sighash_anyonecanpay) != 0

  @typedoc "Sighash preimage - the data to be hashed for signing"
  @type preimage() :: binary()

  @typedoc "Sighash flag controlling which parts of tx are signed"
  @type sighash_flag() :: integer()

  # ============================================================================
  # Legacy Preimage (Original Bitcoin Signing Algorithm)
  # ============================================================================

  @doc """
  Returns the legacy preimage for the given transaction.

  This implements the original Bitcoin signing algorithm. 
  For SegWit transactions, use `segwit/4` which implements BIP-143.

  ## Parameters

  - `tx` - The transaction being signed
  - `vin` - The index of the input being signed
  - `output` - The output being spent (contains the locking script)
  - `sighash_type` - The sighash flag (default: SIGHASH_ALL = 0x01)

  ## Example

      preimage = PreImage.legacy(tx, 0, spent_output, 0x01)
      sighash = Hash.sha256_sha256(preimage)
  """
  @spec legacy(Transaction.t(), Input.vin(), Output.t(), sighash_flag()) :: preimage()
  def legacy(%Transaction{} = tx, vin, %Output{} = output, sighash_type) do
    %{script: subscript} =
      update_in(output.script.chunks, fn chunks ->
        Enum.reject(chunks, &(&1 == :OP_CODESEPARATOR))
      end)

    tx = update_in(tx.inputs, &update_tx_inputs(&1, vin, subscript, sighash_type))
    tx = update_in(tx.outputs, &update_tx_outputs(&1, vin, sighash_type))

    Transaction.to_binary(tx, segwit: false) <> <<sighash_type::little-32>>
  end

  # ============================================================================
  # SegWit Preimage (BIP-143)
  # ============================================================================

  @doc """
  Returns the SegWit preimage for the given transaction using BIP-143 algorithm.

  This is used for native SegWit (P2WPKH, P2WSH) and nested SegWit (P2SH-P2WPKH, P2SH-P2WSH) transactions.

  ## Parameters

  - `tx` - The transaction being signed
  - `vin` - The index of the input being signed
  - `output` - The output being spent (contains the value)
  - `script_code` - The script code to use in the preimage. 
    - For `P2WPKH`, use `p2wpkh_script_code/1`. 
    - For `P2WSH`, use the witness script.
  - `opts` - Options (see below)

  ## Options

  * `:sighash_type` - The sighash type (default: `SIGHASH_ALL` = `0x01`)

  ## Script Code

  For `P2WPKH` inputs, the script code is the `P2PKH`-equivalent:
  `OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG`

  For `P2WSH` inputs, the script code is the actual witness script being executed.

  ## Example

      script_code = PreImage.p2wpkh_script_code(pubkey_hash)
      preimage = PreImage.segwit(tx, 0, output, script_code)
      sighash = Hash.sha256_sha256(preimage)
  """
  @spec segwit(Transaction.t(), Input.vin(), Output.t(), Script.t(), keyword()) :: preimage()
  def segwit(%Transaction{inputs: inputs} = tx, vin, %Output{} = output, script_code, opts \\ []) do
    sighash_type = Keyword.get(opts, :sighash_type, @sighash_all)

    input = Enum.at(inputs, vin)

    # Hash of all input outpoints (or zeros if ANYONECANPAY)
    prevouts_hash = hash_prevouts(tx.inputs, sighash_type)

    # Hash of all input sequences (or zeros if ANYONECANPAY/SINGLE/NONE)
    sequence_hash = hash_sequence(tx.inputs, sighash_type)

    # Current input's outpoint
    outpoint = OutPoint.to_binary(input.outpoint)

    # Script code with length prefix
    subscript =
      script_code
      |> Script.to_binary()
      |> encode_varint_binary()

    # Hash of outputs (depends on sighash type)
    outputs_hash = hash_outputs(tx.outputs, vin, sighash_type)

    <<
      tx.version::little-32,
      prevouts_hash::binary,
      sequence_hash::binary,
      outpoint::binary,
      subscript::binary,
      output.satoshis::little-64,
      input.sequence::little-32,
      outputs_hash::binary,
      tx.lock_time::little-32,
      sighash_type::little-32
    >>
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  @doc """
  Creates the `P2PKH`-equivalent script code for a `P2WPKH` input.

  This is the script code used in the BIP-143 preimage for `P2WPKH` inputs.
  The script code is: `OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG`

  ## Parameters

  - `pubkey_hash` - The 20-byte public key hash

  ## Example

      pubkey_hash = Hash.sha256_ripemd160(pubkey_binary)
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)
  """
  @spec p2wpkh_script_code(binary()) :: Script.t()
  def p2wpkh_script_code(pubkey_hash) when byte_size(pubkey_hash) == 20 do
    %Script{chunks: [:OP_DUP, :OP_HASH160, pubkey_hash, :OP_EQUALVERIFY, :OP_CHECKSIG]}
  end

  # ============================================================================
  # Private Functions - SegWit Hash Components
  # ============================================================================

  # Double hashes the outpoints of the transaction inputs
  defp hash_prevouts(_inputs, sighash_type)
       when sighash_anyone_can_pay?(sighash_type),
       do: <<0::256>>

  defp hash_prevouts(inputs, _sighash_type) do
    inputs
    |> Enum.map(&OutPoint.to_binary(&1.outpoint))
    |> IO.iodata_to_binary()
    |> Hash.sha256_sha256()
  end

  # Double hashes the sequence values of the transaction inputs
  defp hash_sequence(_inputs, sighash_type)
       when sighash_anyone_can_pay?(sighash_type) or
              sighash_single?(sighash_type) or
              sighash_none?(sighash_type),
       do: <<0::256>>

  defp hash_sequence(inputs, _sighash_type) do
    inputs
    |> Enum.reduce(<<>>, &(&2 <> <<&1.sequence::little-32>>))
    |> Hash.sha256_sha256()
  end

  # Double hashes the transaction outputs
  # Bitcoin's quirky behavior: when SIGHASH_SINGLE and vin >= outputs count,
  # return a hash of 0x0000...0001 (32 bytes with 1 at the end)
  defp hash_outputs(outputs, vin, sighash_type)
       when sighash_single?(sighash_type) and vin >= length(outputs),
       do: <<1, 0::248>>

  defp hash_outputs(outputs, vin, sighash_type)
       when sighash_single?(sighash_type) and
              vin < length(outputs) do
    outputs
    |> Enum.at(vin)
    |> Output.to_binary()
    |> Hash.sha256_sha256()
  end

  defp hash_outputs(outputs, _vin, sighash_type)
       when not sighash_none?(sighash_type) do
    outputs
    |> Enum.reduce(<<>>, &(&2 <> Output.to_binary(&1)))
    |> Hash.sha256_sha256()
  end

  defp hash_outputs(_outputs, _vin, _sighash_type),
    do: :binary.copy(<<0>>, 32)

  # ============================================================================
  # Private Functions - Legacy Preimage Components
  # ============================================================================

  # Replaces the transaction input scripts with the subscript
  defp update_tx_inputs(inputs, vin, subscript, sighash_type)
       when sighash_anyone_can_pay?(sighash_type) do
    input =
      Enum.at(inputs, vin)
      |> Map.put(:script, subscript)

    [input]
  end

  defp update_tx_inputs(inputs, vin, subscript, sighash_type) do
    inputs
    |> Enum.with_index()
    |> Enum.map(fn
      {input, ^vin} ->
        Map.put(input, :script, subscript)

      {input, _i} ->
        if sighash_none?(sighash_type) || sighash_single?(sighash_type),
          do: Map.merge(input, %{script: %Script{}, sequence: 0}),
          else: Map.put(input, :script, %Script{})
    end)
  end

  # Prepares the transaction outputs for the legacy preimage algorithm
  defp update_tx_outputs(_outputs, _vin, sighash_type)
       when sighash_none?(sighash_type),
       do: []

  defp update_tx_outputs(outputs, vin, sighash_type)
       when sighash_single?(sighash_type) and
              length(outputs) <= vin,
       do: raise(ArgumentError, "input out of output range")

  # For SIGHASH_SINGLE, outputs before the signing input index are replaced with
  # "blank" outputs. Per the Bitcoin protocol, these blank outputs use -1 for the
  # satoshi value, which serializes as 0xFFFFFFFFFFFFFFFF (max uint64). This is
  # intentional legacy behavior from the original Bitcoin implementation - the
  # negative value produces the correct wire format when encoded as little-endian.
  defp update_tx_outputs(outputs, vin, sighash_type)
       when sighash_single?(sighash_type) do
    outputs
    |> Enum.with_index()
    |> Enum.map(fn
      {_output, i} when i < vin ->
        %Output{satoshis: -1, script: %Script{}}

      {output, _i} ->
        output
    end)
    |> Enum.slice(0..vin)
  end

  defp update_tx_outputs(outputs, _vin, _sighash_type), do: outputs
end
