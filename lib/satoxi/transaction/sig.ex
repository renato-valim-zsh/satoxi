defmodule Satoxi.Transaction.Sig do
  @moduledoc """
  Module for signing and verifying Bitcoin transactions.

  Signing a transaction in Bitcoin first involves computing a transaction
  preimage. A `t:Satoxi.Transaction.PreImage.sighash_flag/0` is used to indicate which parts of the
  transaction are included in the preimage.

  | Flag                            | Value                    | Description                         |
  | ------------------------------- | ------------------------ | ----------------------------------- |
  | `SIGHASH_ALL`                   | `0x01` / `0000 0001`     | Sign all inputs and outputs         |
  | `SIGHASH_NONE`                  | `0x02` / `0000 0010`     | Sign all inputs and no outputs      |
  | `SIGHASH_SINGLE`                | `0x03` / `0000 0011`     | Sign all inputs and single output   |
  | `SIGHASH_ALL | ANYONECANPAY`    | `0x81` / `1000 0001`     | Sign single input and all outputs   |
  | `SIGHASH_NONE | ANYONECANPAY`   | `0x82` / `1000 0010`     | Sign single input and no outputs    |
  | `SIGHASH_SINGLE | ANYONECANPAY` | `0x83` / `1000 0011`     | Sign single input and single output |

  Once the preimage is constructed, it is double hashed using the `SHA-256`
  algorithm and then used to calculate the ECDSA signature. The resulting
  DER-encoded signature is appended with the sighash flag.

  ## Legacy vs SegWit Signing

  For legacy (non-SegWit) transactions, use `sign/5` and `verify/5`.
  For SegWit transactions, use `segwit_sign/5` and `segwit_verify/6`.

  ## Preimage Generation

  For direct access to preimage generation, see `Satoxi.Transaction.PreImage`.
  """
  alias Satoxi.Script
  alias Satoxi.Hash
  alias Satoxi.Keys.{PrivKey, PubKey}
  alias Satoxi.Transaction
  alias Satoxi.Transaction.{Input, Output, PreImage}

  @typedoc "Sighash"
  @type sighash() :: <<_::256>>

  @typedoc """
  Signature

  DER-encoded signature with the sighash flag appended.
  """
  @type signature() :: binary()

  @sighash_all 0x01
  @sighash_none 0x02
  @sighash_single 0x03
  @sighash_anyonecanpay 0x80

  @default_sighash @sighash_all

  @doc """
  Returns the `t:Satoxi.Transaction.PreImage.sighash_flag/0` of the given sighash type.

  ## Examples

      iex> Sig.sighash_flag(:default)
      0x01
  """
  @spec sighash_flag(atom()) :: PreImage.sighash_flag()
  def sighash_flag(sighash_type \\ :default)
  def sighash_flag(:default), do: @default_sighash
  def sighash_flag(:sighash_all), do: @sighash_all
  def sighash_flag(:sighash_none), do: @sighash_none
  def sighash_flag(:sighash_single), do: @sighash_single
  def sighash_flag(:sighash_anyonecanpay), do: @sighash_anyonecanpay

  # ============================================================================
  # Legacy Signing Functions
  # ============================================================================

  @doc """
  Returns the legacy preimage for the given transaction.

  Delegates to `Satoxi.Transaction.PreImage.legacy/4`.
  """
  @spec preimage(Transaction.t(), Input.vin(), Output.t(), PreImage.sighash_flag()) ::
          PreImage.preimage()
  defdelegate preimage(tx, vin, output, sighash_type), to: PreImage, as: :legacy

  @doc """
  Computes a double SHA256 hash of the preimage of the given transaction. Must
  also specify the `t:Satoxi.Transaction.Input.vin/0` of the context input, the `t:Satoxi.Transaction.Output.t/0`
  that is being spent, and the `t:Satoxi.Transaction.PreImage.sighash_flag/0`.
  """
  @spec sighash(Transaction.t(), Input.vin(), Output.t(), PreImage.sighash_flag()) :: sighash()
  def sighash(%Transaction{} = tx, vin, %Output{} = output, sighash_type \\ @default_sighash) do
    tx
    |> PreImage.legacy(vin, output, sighash_type)
    |> Hash.sha256_sha256()
  end

  @doc """
  Signs the sighash of the given transaction using the given PrivKey. Must also
  specify the `t:Satoxi.Transaction.Input.vin/0` of the context input, the `t:Satoxi.Transaction.Output.t/0`
  that is being spent, and the `t:Satoxi.Transaction.PreImage.sighash_flag/0`.

  The returned DER-encoded signature is appended with the sighash flag.
  """
  @spec sign(Transaction.t(), Input.vin(), Output.t(), PrivKey.t(), keyword()) :: signature()
  def sign(%Transaction{} = tx, vin, %Output{} = output, %PrivKey{d: privkey}, opts \\ []) do
    sighash_type = Keyword.get(opts, :sighash_type, @default_sighash)

    tx
    |> sighash(vin, output, sighash_type)
    |> Curvy.sign(privkey, hash: false)
    |> Kernel.<>(<<sighash_type>>)
  end

  @doc """
  Verifies the signature against the sighash of the given transaction using the
  specified PubKey. Must also specify the `t:Satoxi.Transaction.Input.vin/0` of the context
  input, the `t:Satoxi.Transaction.Output.t/0` that is being spent.
  """
  @spec verify(signature(), Transaction.t(), Input.vin(), Output.t(), PubKey.t()) ::
          boolean() | :error
  def verify(signature, %Transaction{} = tx, vin, %Output{} = output, %PubKey{} = pubkey) do
    sig_length = byte_size(signature) - 1
    <<sig::binary-size(sig_length), sighash_type>> = signature
    message = sighash(tx, vin, output, sighash_type)
    Curvy.verify(sig, message, PubKey.to_binary(pubkey), hash: false)
  end

  # ============================================================================
  # SegWit Signing Functions (BIP-143)
  # ============================================================================

  @doc """
  Returns the SegWit preimage for the given transaction using BIP-143 algorithm.

  Delegates to `Satoxi.Transaction.PreImage.segwit/5`.
  """
  @spec segwit_preimage(Transaction.t(), Input.vin(), Output.t(), Script.t(), keyword()) ::
          PreImage.preimage()
  defdelegate segwit_preimage(tx, vin, output, script_code, opts \\ []), to: PreImage, as: :segwit

  @doc """
  Computes the SegWit sighash (double SHA-256 of the BIP-143 preimage).

  See `Satoxi.Transaction.PreImage.segwit/5` for details on options.
  """
  @spec segwit_sighash(Transaction.t(), Input.vin(), Output.t(), Script.t(), keyword()) ::
          sighash()
  def segwit_sighash(%Transaction{} = tx, vin, %Output{} = output, script_code, opts \\ []) do
    tx
    |> PreImage.segwit(vin, output, script_code, opts)
    |> Hash.sha256_sha256()
  end

  @doc """
  Signs a SegWit input using the BIP-143 sighash algorithm.

  ## Options

  * `:sighash_type` - The sighash type (default: SIGHASH_ALL = 0x01)

  ## Examples

      # For P2WPKH, create the equivalent P2PKH script code
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)
      signature = Sig.segwit_sign(tx, 0, output, privkey, script_code)
  """
  @spec segwit_sign(Transaction.t(), Input.vin(), Output.t(), Script.t(), PrivKey.t(), keyword()) ::
          signature()
  def segwit_sign(
        %Transaction{} = tx,
        vin,
        %Output{} = output,
        %Script{} = script_code,
        %PrivKey{d: privkey},
        opts \\ []
      ) do
    sighash_type = Keyword.get(opts, :sighash_type, @sighash_all)

    tx
    |> segwit_sighash(vin, output, script_code, opts)
    |> Curvy.sign(privkey, hash: false)
    |> Kernel.<>(<<sighash_type>>)
  end

  @doc """
  Verifies a SegWit signature against the BIP-143 sighash.
  """
  @spec segwit_verify(
          signature(),
          Transaction.t(),
          Input.vin(),
          Output.t(),
          Script.t(),
          PubKey.t(),
          keyword()
        ) ::
          boolean() | :error
  def segwit_verify(
        signature,
        %Transaction{} = tx,
        vin,
        %Output{} = output,
        %Script{} = script_code,
        %PubKey{} = pubkey,
        opts \\ []
      ) do
    sig_length = byte_size(signature) - 1
    <<sig::binary-size(sig_length), sighash_type>> = signature
    opts = Keyword.put(opts, :sighash_type, sighash_type)
    message = segwit_sighash(tx, vin, output, script_code, opts)
    Curvy.verify(sig, message, PubKey.to_binary(pubkey), hash: false)
  end

  @doc """
  Creates the P2PKH-equivalent script code for a P2WPKH input.

  Delegates to `Satoxi.Transaction.PreImage.p2wpkh_script_code/1`.
  """
  @spec p2wpkh_script_code(binary()) :: Satoxi.Script.t()
  defdelegate p2wpkh_script_code(pubkey_hash), to: PreImage
end
