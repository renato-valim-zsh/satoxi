defmodule Satoxi.Contract.P2PKHTest do
  use ExUnit.Case

  alias Satoxi.Address
  alias Satoxi.Contract
  alias Satoxi.Contract.P2PKH
  alias Satoxi.Keys.KeyPair
  alias Satoxi.Keys.PrivKey
  alias Satoxi.Script
  alias Satoxi.Transaction.Output
  alias Satoxi.Transaction.UTXO

  @wif "KyGHAK8MNohVPdeGPYXveiAbTfLARVrQuJVtd3qMqN41UEnTWDkF"

  @keypair KeyPair.from_privkey(PrivKey.from_wif!(@wif))

  doctest P2PKH

  describe "lock/2" do
    test "locks satoshis to an address" do
      contract = P2PKH.lock(1000, %{address: Address.from_pubkey(@keypair.pubkey)})

      assert %Output{satoshis: 1000, script: script} = Contract.to_output(contract)

      assert %Script{
               chunks: [:OP_DUP, :OP_HASH160, <<_::binary-20>>, :OP_EQUALVERIFY, :OP_CHECKSIG]
             } = script
    end
  end

  describe "unlock/2" do
    test "unlocks UTXO with given keypair" do
      contract = P2PKH.unlock(%UTXO{}, %{keypair: @keypair})

      assert %Script{chunks: [<<_::binary-71>>, <<_::binary-33>>]} = Contract.to_script(contract)
    end
  end
end
