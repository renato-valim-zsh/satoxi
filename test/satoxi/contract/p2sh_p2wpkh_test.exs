defmodule Satoxi.Contract.P2SH_P2WPKHTest do
  use ExUnit.Case, async: true

  alias Satoxi.Address
  alias Satoxi.Contract
  alias Satoxi.Contract.P2SH_P2WPKH
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
    test "locks satoshis to a P2SH address" do
      address = Address.from_pubkey(@keypair.pubkey, type: :p2sh_p2wpkh)
      contract = P2SH_P2WPKH.lock(1000, %{address: address})
      assert %Output{satoshis: 1000, script: script} = Contract.to_output(contract)

      # P2SH locking script: OP_HASH160 <20-byte-script-hash> OP_EQUAL
      assert %Script{chunks: [:OP_HASH160, <<_::binary-20>>, :OP_EQUAL]} = script
    end

    test "produces correct script hash from pubkey" do
      address = Address.from_pubkey(@keypair.pubkey, type: :p2sh_p2wpkh)
      contract = P2SH_P2WPKH.lock(1000, %{address: address})
      %Script{chunks: [:OP_HASH160, script_hash, :OP_EQUAL]} = Contract.to_script(contract)

      # Verify the script hash is HASH160 of the redeem script
      pubkey_binary = PubKey.to_binary(@keypair.pubkey)
      pubkey_hash = Hash.sha256_ripemd160(pubkey_binary)
      redeem_script = <<0x00, 0x14, pubkey_hash::binary-20>>
      expected_hash = Hash.sha256_ripemd160(redeem_script)

      assert script_hash == expected_hash
    end
  end

  describe "unlock/2" do
    test "unlocking script contains the redeem script" do
      utxo = %UTXO{}
      contract = P2SH_P2WPKH.unlock(utxo, %{keypair: @keypair})
      script = Contract.to_script(contract)

      # ScriptSig should contain the serialized redeem script
      # Redeem script: 0x00 0x14 <20-byte-pubkey-hash> = 22 bytes
      assert %Script{chunks: [redeem_script]} = script
      assert <<0x00, 0x14, _pubkey_hash::binary-20>> = redeem_script
    end

    test "redeem script contains correct pubkey hash" do
      utxo = %UTXO{}
      contract = P2SH_P2WPKH.unlock(utxo, %{keypair: @keypair})
      %Script{chunks: [redeem_script]} = Contract.to_script(contract)

      <<0x00, 0x14, pubkey_hash::binary-20>> = redeem_script

      expected_hash = Hash.sha256_ripemd160(PubKey.to_binary(@keypair.pubkey))
      assert pubkey_hash == expected_hash
    end
  end

  describe "witness_script/2" do
    test "returns signature and pubkey when context is provided" do
      outpoint = %OutPoint{hash: :binary.copy(<<0>>, 32), vout: 0}

      utxo = %UTXO{
        outpoint: outpoint,
        output: %Output{
          satoshis: 1000,
          script: %Script{chunks: [:OP_HASH160, <<0::160>>, :OP_EQUAL]}
        }
      }

      contract = P2SH_P2WPKH.unlock(utxo, %{keypair: @keypair})

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
      assert is_binary(pubkey)
      assert byte_size(pubkey) == 33
    end

    test "returns placeholder witness when no context is provided" do
      utxo = %UTXO{}
      contract = P2SH_P2WPKH.unlock(utxo, %{keypair: @keypair})
      witness = Contract.to_witness(contract)

      # Should return placeholder [zeros, pubkey]
      assert [placeholder_sig, pubkey] = witness
      assert byte_size(placeholder_sig) == 71
      assert byte_size(pubkey) == 33
    end
  end

  describe "Contract.segwit?/1" do
    test "returns true for P2SH_P2WPKH contracts" do
      contract = P2SH_P2WPKH.unlock(%UTXO{}, %{keypair: @keypair})
      assert Contract.segwit?(contract)
    end
  end
end
