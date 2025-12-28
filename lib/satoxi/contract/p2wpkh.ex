defmodule Satoxi.Contract.P2WPKH do
  @moduledoc """
  Pay to Witness Public Key Hash (P2WPKH) contract.

  P2WPKH is a native SegWit script type that locks Bitcoin to a public key hash.
  The witness program is a 20-byte public key hash, and the unlocking data (signature and public key) goes into the witness field rather than the scriptSig.

  Native SegWit addresses begin with "bc1q" on mainnet or "tb1q" on testnet.

  ## Locking script (scriptPubKey)

  The locking script is:

      OP_0 <20-byte-pubkey-hash>

  ## Unlocking

  For P2WPKH, the scriptSig is empty. The witness contains:

      [signature, pubkey]

  ## Lock parameters

  * `:address` - A `t:Satoxi.Address.SegWit.t/0` struct with type `:p2wpkh`.

  ## Unlock parameters

  * `:keypair` - A `t:Satoxi.Keys.KeyPair.t/0` struct.

  ## Examples

      # Create a P2WPKH output
      iex> address = Address.from_pubkey(keypair.pubkey, :p2wpkh)
      iex> contract = P2WPKH.lock(10000, %{address: address})
      iex> Contract.to_script(contract)
      %Script{chunks: [:OP_0, <<pubkey_hash::binary-20>>]}

      # Unlock a P2WPKH UTXO
      iex> contract = P2WPKH.unlock(utxo, %{keypair: keypair})
      iex> input = Contract.to_input(contract)
      iex> input.script.chunks  # Empty scriptSig
      []
      iex> input.witness  # [signature, pubkey]
      [<<signature...>>, <<pubkey...>>]
  """
  use Satoxi.Contract

  alias Satoxi.Address.SegWit
  alias Satoxi.Hash
  alias Satoxi.Keys.PubKey
  alias Satoxi.Transaction.Sig
  alias Satoxi.Transaction.UTXO

  @impl Satoxi.Contract
  def locking_script(ctx, %{address: %SegWit{} = address}) do
    ctx
    |> op_0()
    |> push(address.witness_program)
  end

  @impl Satoxi.Contract
  def unlocking_script(ctx, _params) do
    # For native SegWit, the scriptSig is empty
    ctx
  end

  @impl Satoxi.Contract
  def witness_script(
        %Contract{ctx: {tx, index}, subject: %UTXO{output: output}} = _contract,
        %{keypair: keypair}
      ) do
    # Get pubkey hash for script code
    pubkey_binary = PubKey.to_binary(keypair.pubkey)
    pubkey_hash = Hash.sha256_ripemd160(pubkey_binary)

    # Create P2PKH-equivalent script code for BIP-143 signing
    script_code = Sig.p2wpkh_script_code(pubkey_hash)

    # Sign using SegWit sighash
    signature = Sig.segwit_sign(tx, index, output, script_code, keypair.privkey)

    # Witness stack: [signature, pubkey]
    [signature, pubkey_binary]
  end

  def witness_script(%Contract{ctx: nil}, %{keypair: keypair}) do
    # Return placeholder witness for size estimation
    pubkey_binary = PubKey.to_binary(keypair.pubkey)

    [<<0::568>>, pubkey_binary]
  end
end
