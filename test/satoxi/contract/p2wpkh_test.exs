defmodule Satoxi.Contract.P2WPKHTest do
  use ExUnit.Case, async: true

  alias Satoxi.Address
  alias Satoxi.Contract
  alias Satoxi.Contract.P2WPKH
  alias Satoxi.Hash
  alias Satoxi.Keys.KeyPair
  alias Satoxi.Keys.PrivKey
  alias Satoxi.Keys.PubKey
  alias Satoxi.Script
  alias Satoxi.Transaction
  alias Satoxi.Transaction.Input
  alias Satoxi.Transaction.OutPoint
  alias Satoxi.Transaction.Output
  alias Satoxi.Transaction.UTXO

  @wif "KyGHAK8MNohVPdeGPYXveiAbTfLARVrQuJVtd3qMqN41UEnTWDkF"

  @keypair KeyPair.from_privkey(PrivKey.from_wif!(@wif))

  describe "lock/2" do
    test "locks satoshis to a P2WPKH address" do
      address = Address.from_pubkey(@keypair.pubkey, type: :p2wpkh)

      contract = P2WPKH.lock(1000, %{address: address})

      assert %Output{satoshis: 1000, script: script} = Contract.to_output(contract)

      # P2WPKH locking script: OP_0 <20-byte-pubkey-hash>
      assert %Script{chunks: [:OP_0, <<_::binary-20>>]} = script
    end

    test "produces witness program matching the pubkey hash" do
      address = Address.from_pubkey(@keypair.pubkey, type: :p2wpkh)

      contract = P2WPKH.lock(1000, %{address: address})

      %Script{chunks: [:OP_0, program]} = Contract.to_script(contract)

      expected_hash = Hash.sha256_ripemd160(PubKey.to_binary(@keypair.pubkey))

      assert program == expected_hash
    end
  end

  describe "unlock/2" do
    test "unlocking script is empty for native SegWit" do
      utxo = %UTXO{}

      contract = P2WPKH.unlock(utxo, %{keypair: @keypair})

      # For native SegWit, scriptSig is empty
      assert %Script{chunks: []} = Contract.to_script(contract)
    end
  end

  describe "witness_script/2" do
    test "returns signature and pubkey when context is provided" do
      # Create a minimal UTXO with enough data for signing
      outpoint = %OutPoint{hash: :binary.copy(<<0>>, 32), vout: 0}

      utxo = %UTXO{
        outpoint: outpoint,
        output: %Output{satoshis: 1000, script: %Script{chunks: [:OP_0, <<0::160>>]}}
      }

      contract = P2WPKH.unlock(utxo, %{keypair: @keypair})

      # Create a transaction with the input for context
      input = %Input{outpoint: outpoint, script: %Script{chunks: []}, sequence: 0xFFFFFFFF}

      tx = %Transaction{
        version: 1,
        inputs: [input],
        outputs: [],
        lock_time: 0
      }

      contract = Contract.put_ctx(contract, {tx, 0})
      witness = Contract.to_witness(contract)

      # Witness should be [signature, pubkey]
      assert [signature, pubkey] = witness
      assert is_binary(signature)
      assert signature != <<0::568>>
      assert is_binary(pubkey)
      assert byte_size(pubkey) == 33
    end

    test "returns placeholder witness when no context is provided" do
      utxo = %UTXO{}
      contract = P2WPKH.unlock(utxo, %{keypair: @keypair})
      witness = Contract.to_witness(contract)

      # Should return placeholder [zeros, pubkey]
      assert [placeholder_sig, pubkey] = witness
      assert byte_size(placeholder_sig) == 71
      assert placeholder_sig == <<0::568>>
      assert byte_size(pubkey) == 33
    end
  end

  describe "Contract.segwit?/1" do
    test "returns true for P2WPKH contracts" do
      contract = P2WPKH.unlock(%UTXO{}, %{keypair: @keypair})
      assert Contract.segwit?(contract)
    end
  end
end
