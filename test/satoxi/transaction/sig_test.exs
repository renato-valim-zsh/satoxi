defmodule Satoxi.Transaction.SigTest do
  use ExUnit.Case, async: true

  alias Satoxi.Keys.KeyPair
  alias Satoxi.Keys.PrivKey
  alias Satoxi.Keys.PubKey
  alias Satoxi.Script
  alias Satoxi.Transaction
  alias Satoxi.Transaction.Input
  alias Satoxi.Transaction.Output
  alias Satoxi.Transaction.OutPoint
  alias Satoxi.Transaction.Sig

  @wif "KyGHAK8MNohVPdeGPYXveiAbTfLARVrQuJVtd3qMqN41UEnTWDkF"
  @keypair KeyPair.from_privkey(PrivKey.from_wif!(@wif))

  @p2pkh_script %Script{
    chunks: [
      :OP_DUP,
      :OP_HASH160,
      <<83, 143, 209, 121, 200, 190, 15, 40, 156, 115, 14, 51, 181, 246, 163, 84, 27, 233, 102,
        143>>,
      :OP_EQUALVERIFY,
      :OP_CHECKSIG
    ]
  }

  describe "sighash_flag/1" do
    test "returns correct flag for :default" do
      assert Sig.sighash_flag(:default) == 0x01
    end

    test "returns correct flag for :sighash_all" do
      assert Sig.sighash_flag(:sighash_all) == 0x01
    end

    test "returns correct flag for :sighash_none" do
      assert Sig.sighash_flag(:sighash_none) == 0x02
    end

    test "returns correct flag for :sighash_single" do
      assert Sig.sighash_flag(:sighash_single) == 0x03
    end

    test "returns correct flag for :sighash_anyonecanpay" do
      assert Sig.sighash_flag(:sighash_anyonecanpay) == 0x80
    end

    test "defaults to sighash_all when called with no arguments" do
      assert Sig.sighash_flag() == 0x01
    end
  end

  describe "preimage/4" do
    test "generates preimage for SIGHASH_ALL" do
      tx = create_test_tx()
      output = create_spent_output()

      preimage = Sig.preimage(tx, 0, output, 0x01)

      assert is_binary(preimage)

      # Preimage should end with sighash type as little-endian 32-bit
      assert binary_part(preimage, byte_size(preimage) - 4, 4) == <<0x01, 0x00, 0x00, 0x00>>
    end

    test "generates different preimages for different sighash types" do
      tx = create_test_tx()
      output = create_spent_output()

      preimage_all = Sig.preimage(tx, 0, output, 0x01)
      preimage_none = Sig.preimage(tx, 0, output, 0x02)
      preimage_single = Sig.preimage(tx, 0, output, 0x03)

      assert preimage_all != preimage_none
      assert preimage_all != preimage_single
      assert preimage_none != preimage_single
    end

    test "removes OP_CODESEPARATOR from subscript" do
      tx = create_test_tx()

      script_with_codesep = %Script{
        chunks: [
          :OP_DUP,
          :OP_CODESEPARATOR,
          :OP_HASH160,
          <<0::160>>,
          :OP_EQUALVERIFY,
          :OP_CHECKSIG
        ]
      }

      output = %Output{satoshis: 50000, script: script_with_codesep}

      # Should not raise and should produce valid preimage
      preimage = Sig.preimage(tx, 0, output, 0x01)
      assert is_binary(preimage)
    end
  end

  describe "sighash/4" do
    test "returns 32-byte hash" do
      tx = create_test_tx()
      output = create_spent_output()

      hash = Sig.sighash(tx, 0, output, 0x01)

      assert byte_size(hash) == 32
    end

    test "produces consistent hash for same inputs" do
      tx = create_test_tx()
      output = create_spent_output()

      hash1 = Sig.sighash(tx, 0, output, 0x01)
      hash2 = Sig.sighash(tx, 0, output, 0x01)

      assert hash1 == hash2
    end

    test "produces different hash for different transactions" do
      tx1 = create_test_tx(num_outputs: 1)
      tx2 = create_test_tx(num_outputs: 2)
      output = create_spent_output()

      hash1 = Sig.sighash(tx1, 0, output, 0x01)
      hash2 = Sig.sighash(tx2, 0, output, 0x01)

      assert hash1 != hash2
    end

    test "defaults to SIGHASH_ALL" do
      tx = create_test_tx()
      output = create_spent_output()

      hash_default = Sig.sighash(tx, 0, output)
      hash_explicit = Sig.sighash(tx, 0, output, 0x01)

      assert hash_default == hash_explicit
    end
  end

  describe "sign/5 and verify/5" do
    test "sign produces valid signature" do
      tx = create_test_tx()
      output = create_spent_output()

      signature = Sig.sign(tx, 0, output, @keypair.privkey)

      assert is_binary(signature)

      # Signature should be DER-encoded + sighash byte
      # DER signatures are typically 70-72 bytes + 1 byte sighash
      assert byte_size(signature) >= 70
      assert byte_size(signature) <= 73
    end

    test "signature ends with sighash type byte" do
      tx = create_test_tx()
      output = create_spent_output()

      signature = Sig.sign(tx, 0, output, @keypair.privkey, sighash_type: 0x01)

      # Last byte should be the sighash type
      assert binary_part(signature, byte_size(signature) - 1, 1) == <<0x01>>
    end

    test "verify returns true for valid signature" do
      tx = create_test_tx()
      output = create_spent_output()

      signature = Sig.sign(tx, 0, output, @keypair.privkey)

      assert Sig.verify(signature, tx, 0, output, @keypair.pubkey)
    end

    test "verify returns false for invalid signature" do
      tx = create_test_tx()
      output = create_spent_output()

      other_keypair =
        KeyPair.from_privkey(
          PrivKey.from_wif!("L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi")
        )

      signature = Sig.sign(tx, 0, output, @keypair.privkey)

      refute Sig.verify(signature, tx, 0, output, other_keypair.pubkey)
    end

    test "verify returns false for tampered transaction" do
      tx = create_test_tx()
      output = create_spent_output()

      signature = Sig.sign(tx, 0, output, @keypair.privkey)

      tampered_tx = put_in(tx.lock_time, 12345)

      refute Sig.verify(signature, tampered_tx, 0, output, @keypair.pubkey)
    end

    test "sign with different sighash types" do
      tx = create_test_tx(num_outputs: 2)
      output = create_spent_output()

      sig_all = Sig.sign(tx, 0, output, @keypair.privkey, sighash_type: 0x01)
      sig_none = Sig.sign(tx, 0, output, @keypair.privkey, sighash_type: 0x02)
      sig_single = Sig.sign(tx, 0, output, @keypair.privkey, sighash_type: 0x03)

      assert Sig.verify(sig_all, tx, 0, output, @keypair.pubkey)
      assert Sig.verify(sig_none, tx, 0, output, @keypair.pubkey)
      assert Sig.verify(sig_single, tx, 0, output, @keypair.pubkey)
    end

    test "SIGHASH_NONE allows output changes" do
      tx = create_test_tx(num_outputs: 1)
      output = create_spent_output()

      sig_none = Sig.sign(tx, 0, output, @keypair.privkey, sighash_type: 0x02)

      modified_tx = put_in(tx.outputs, [%Output{satoshis: 99999, script: @p2pkh_script}])

      # Should still verify because SIGHASH_NONE doesn't sign outputs
      assert Sig.verify(sig_none, modified_tx, 0, output, @keypair.pubkey)
    end

    test "SIGHASH_ANYONECANPAY allows input additions" do
      tx = create_test_tx(num_inputs: 1)
      output = create_spent_output()

      sig_anyonecanpay = Sig.sign(tx, 0, output, @keypair.privkey, sighash_type: 0x81)

      new_input = %Input{
        outpoint: %OutPoint{hash: :binary.copy(<<0xFF>>, 32), vout: 1},
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFF
      }

      modified_tx = update_in(tx.inputs, &(&1 ++ [new_input]))

      # Should still verify because ANYONECANPAY only signs the current input
      assert Sig.verify(sig_anyonecanpay, modified_tx, 0, output, @keypair.pubkey)
    end
  end

  describe "p2wpkh_script_code/1" do
    test "generates correct P2PKH-equivalent script" do
      pubkey_hash = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20>>

      script = Sig.p2wpkh_script_code(pubkey_hash)

      assert %Script{
               chunks: [:OP_DUP, :OP_HASH160, ^pubkey_hash, :OP_EQUALVERIFY, :OP_CHECKSIG]
             } = script
    end
  end

  describe "segwit_preimage/4 (BIP-143)" do
    test "generates preimage for SegWit transaction" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> Sig.p2wpkh_script_code()

      preimage = Sig.segwit_preimage(tx, 0, output, script_code)

      assert is_binary(preimage)

      # BIP-143 preimage has specific structure
      # Starts with version (4 bytes little-endian)
      <<version::little-32, _rest::binary>> = preimage
      assert version == 1
    end

    test "generates different preimage than legacy" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> Sig.p2wpkh_script_code()

      legacy_preimage = Sig.preimage(tx, 0, output, 0x01)

      segwit_preimage = Sig.segwit_preimage(tx, 0, output, script_code)

      assert legacy_preimage != segwit_preimage
    end
  end

  describe "segwit_sighash/4" do
    test "returns 32-byte hash" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> Sig.p2wpkh_script_code()

      hash = Sig.segwit_sighash(tx, 0, output, script_code)

      assert byte_size(hash) == 32
    end

    test "produces different hash than legacy sighash" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> Sig.p2wpkh_script_code()

      legacy_hash = Sig.sighash(tx, 0, output, 0x01)
      segwit_hash = Sig.segwit_sighash(tx, 0, output, script_code)

      assert legacy_hash != segwit_hash
    end
  end

  describe "segwit_sign/5 and segwit_verify/6" do
    test "sign produces valid SegWit signature" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> Sig.p2wpkh_script_code()

      signature = Sig.segwit_sign(tx, 0, output, script_code, @keypair.privkey)

      assert is_binary(signature)
      assert byte_size(signature) >= 70
      assert byte_size(signature) <= 73
    end

    test "verify returns true for valid SegWit signature" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> Sig.p2wpkh_script_code()

      signature = Sig.segwit_sign(tx, 0, output, script_code, @keypair.privkey)

      assert Sig.segwit_verify(signature, tx, 0, output, script_code, @keypair.pubkey)
    end

    test "verify returns false for wrong pubkey" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> Sig.p2wpkh_script_code()

      other_keypair =
        KeyPair.from_privkey(
          PrivKey.from_wif!("L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi")
        )

      signature = Sig.segwit_sign(tx, 0, output, script_code, @keypair.privkey)

      refute Sig.segwit_verify(signature, tx, 0, output, script_code, other_keypair.pubkey)
    end

    test "verify returns false for tampered amount" do
      tx = create_test_tx()
      output = create_spent_output(50000)

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> Sig.p2wpkh_script_code()

      signature = Sig.segwit_sign(tx, 0, output, script_code, @keypair.privkey)

      # SegWit commits to the amount being spent
      tampered_output = %{output | satoshis: 99999}

      refute Sig.segwit_verify(signature, tx, 0, tampered_output, script_code, @keypair.pubkey)
    end
  end

  describe "SIGHASH_SINGLE edge case" do
    test "handles vin >= outputs count correctly for SegWit" do
      # Create transaction with 1 output but we'll sign at vin=1
      tx = create_test_tx(num_inputs: 2, num_outputs: 1)
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> Sig.p2wpkh_script_code()

      preimage = Sig.segwit_preimage(tx, 1, output, script_code, sighash_type: 0x03)
      assert is_binary(preimage)

      # The signature should still work
      signature =
        Sig.segwit_sign(tx, 1, output, script_code, @keypair.privkey, sighash_type: 0x03)

      assert is_binary(signature)
    end

    test "SegWit handles vin >= outputs count" do
      tx = create_test_tx(num_inputs: 2, num_outputs: 1)
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> Sig.p2wpkh_script_code()

      # Should not raise
      preimage =
        Sig.segwit_preimage(tx, 1, output, script_code, sighash_type: 0x03)

      assert is_binary(preimage)
    end
  end

  # Helper to create a test transaction
  defp create_test_tx(opts \\ []) do
    num_inputs = Keyword.get(opts, :num_inputs, 1)
    num_outputs = Keyword.get(opts, :num_outputs, 1)

    inputs =
      for i <- 0..(num_inputs - 1) do
        %Input{
          outpoint: %OutPoint{hash: :binary.copy(<<i>>, 32), vout: 0},
          script: %Script{chunks: []},
          sequence: 0xFFFFFFFF
        }
      end

    outputs =
      for i <- 0..(num_outputs - 1) do
        %Output{satoshis: 10000 * (i + 1), script: @p2pkh_script}
      end

    %Transaction{version: 1, inputs: inputs, outputs: outputs, lock_time: 0}
  end

  # Helper to create an output being spent
  defp create_spent_output(satoshis \\ 50000) do
    %Output{satoshis: satoshis, script: @p2pkh_script}
  end

  # Helper to get the pubkey hash from a keypair
  defp get_pubkey_hash_from_keypair(keypair) do
    keypair.pubkey |> PubKey.to_binary() |> Satoxi.Hash.sha256_ripemd160()
  end
end
