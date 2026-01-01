defmodule Satoxi.Contract.P2SH_P2WPKH do
  @moduledoc """
  Pay to Script Hash - Pay to Witness Public Key Hash (`P2SH-P2WPKH`) contract.

  `P2SH-P2WPKH` is a "nested" or "wrapped" SegWit script type that provides backwards compatibility with wallets that don't support native SegWit addresses.
  The SegWit script is wrapped in a `P2SH` script.

  These addresses begin with "3" on mainnet or "2" on testnet (standard `P2SH` format).

  ## Locking script (`scriptPubKey`)

  The locking script is a standard `P2SH`:

      OP_HASH160 <20-byte-script-hash> OP_EQUAL

  Where the script hash is `HASH160` of the redeem script: `OP_0 <20-byte-pubkey-hash>`

  ## Unlocking

  The scriptSig contains the redeem script:

      <redeem-script>  (which is: OP_0 <20-byte-pubkey-hash>)

  The witness contains:

      [signature, pubkey]

  ## Lock parameters

  * `:address` - A `t:Satoxi.Address.Nested.t/0` struct.

  ## Unlock parameters

  * `:keypair` - A `t:Satoxi.Keys.KeyPair.t/0` struct.

  ## Examples

      # Create a P2SH-P2WPKH output
      iex> address = Address.from_pubkey(keypair.pubkey, type: :p2sh_p2wpkh)
      iex> contract = P2SH_P2WPKH.lock(10000, %{address: address})
      iex> Contract.to_script(contract)
      %Script{chunks: [:OP_HASH160, <<script_hash::binary-20>>, :OP_EQUAL]}

      # Unlock a P2SH-P2WPKH UTXO
      iex> contract = P2SH_P2WPKH.unlock(utxo, %{keypair: keypair})
      iex> input = Contract.to_input(contract)
      iex> input.script.chunks  # Contains redeem script
      [<<0x00, 0x14, pubkey_hash::binary-20>>]
      iex> input.witness  # [signature, pubkey]
      [<<signature...>>, <<pubkey...>>]
  """
  use Satoxi.Contract

  alias Satoxi.Address.Nested
  alias Satoxi.Keys.PubKey
  alias Satoxi.Transaction.Sig
  alias Satoxi.Transaction.UTXO

  @impl Satoxi.Contract
  def locking_script(ctx, %{address: %Nested{} = address}) do
    script_hash = Nested.get_script_hash(address)

    ctx
    |> op_hash160()
    |> push(script_hash)
    |> op_equal()
  end

  @impl Satoxi.Contract
  def unlocking_script(ctx, %{keypair: keypair}) do
    redeem_script =
      keypair.pubkey
      |> Nested.from_pubkey()
      |> Nested.get_redeem_script()

    push(ctx, redeem_script)
  end

  @impl Satoxi.Contract
  def witness_script(
        %Contract{ctx: {tx, index}, subject: %UTXO{output: output}} = _contract,
        %{keypair: keypair}
      ) do
    address = Nested.from_pubkey(keypair.pubkey)
    pubkey_binary = PubKey.to_binary(keypair.pubkey)

    # Create P2PKH-equivalent script code for BIP-143 signing
    # Same as native P2WPKH
    script_code =
      address
      |> Nested.get_pubkey_hash()
      |> Sig.p2wpkh_script_code()

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
