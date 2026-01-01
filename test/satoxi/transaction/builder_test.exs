defmodule Satoxi.Transaction.BuilderTest do
  use ExUnit.Case, async: true

  alias Satoxi.Address
  alias Satoxi.Contract.P2PKH
  alias Satoxi.Contract.P2WPKH
  alias Satoxi.Keys.KeyPair
  alias Satoxi.Keys.PrivKey
  alias Satoxi.Script
  alias Satoxi.Transaction
  alias Satoxi.Transaction.Builder
  alias Satoxi.Transaction.OutPoint
  alias Satoxi.Transaction.Output
  alias Satoxi.Transaction.Sig
  alias Satoxi.Transaction.UTXO
  alias Satoxi.Transaction.Witness

  @wif "KyGHAK8MNohVPdeGPYXveiAbTfLARVrQuJVtd3qMqN41UEnTWDkF"
  @keypair KeyPair.from_privkey(PrivKey.from_wif!(@wif))

  @wif2 "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi"
  @keypair2 KeyPair.from_privkey(PrivKey.from_wif!(@wif2))

  describe "add_input/2" do
    test "adds unlocking contract to builder" do
      builder = %Builder{}

      utxo = create_p2pkh_utxo(0x01, 0, 10000, @keypair)
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      updated = Builder.add_input(builder, contract)

      assert length(updated.inputs) == 1
      assert hd(updated.inputs) == contract
    end

    test "appends multiple inputs" do
      utxo1 = create_p2pkh_utxo(0x01, 0, 10000, @keypair)
      utxo2 = create_p2pkh_utxo(0x02, 0, 20000, @keypair)

      builder =
        %Builder{}
        |> Builder.add_input(P2PKH.unlock(utxo1, %{keypair: @keypair}))
        |> Builder.add_input(P2PKH.unlock(utxo2, %{keypair: @keypair}))

      assert length(builder.inputs) == 2
    end
  end

  describe "add_output/2" do
    test "adds locking contract to builder" do
      builder = %Builder{}
      address = Address.from_pubkey(@keypair.pubkey)
      contract = P2PKH.lock(5000, %{address: address})

      updated = Builder.add_output(builder, contract)

      assert length(updated.outputs) == 1
      assert hd(updated.outputs) == contract
    end

    test "appends multiple outputs" do
      address1 = Address.from_pubkey(@keypair.pubkey)
      address2 = Address.from_pubkey(@keypair2.pubkey)

      builder =
        %Builder{}
        |> Builder.add_output(P2PKH.lock(5000, %{address: address1}))
        |> Builder.add_output(P2PKH.lock(3000, %{address: address2}))

      assert length(builder.outputs) == 2
    end
  end

  describe "input_sum/1" do
    test "returns sum of all input UTXO values" do
      utxo1 = create_p2pkh_utxo(0x01, 0, 10000, @keypair)
      utxo2 = create_p2pkh_utxo(0x02, 0, 25000, @keypair)
      utxo3 = create_p2pkh_utxo(0x03, 0, 15000, @keypair)

      builder =
        %Builder{}
        |> Builder.add_input(P2PKH.unlock(utxo1, %{keypair: @keypair}))
        |> Builder.add_input(P2PKH.unlock(utxo2, %{keypair: @keypair}))
        |> Builder.add_input(P2PKH.unlock(utxo3, %{keypair: @keypair}))

      assert Builder.input_sum(builder) == 50000
    end

    test "returns 0 for empty inputs" do
      assert Builder.input_sum(%Builder{}) == 0
    end
  end

  describe "output_sum/1" do
    test "returns sum of all output values" do
      address = Address.from_pubkey(@keypair.pubkey)

      builder =
        %Builder{}
        |> Builder.add_output(P2PKH.lock(5000, %{address: address}))
        |> Builder.add_output(P2PKH.lock(3000, %{address: address}))
        |> Builder.add_output(P2PKH.lock(1500, %{address: address}))

      assert Builder.output_sum(builder) == 9500
    end

    test "returns 0 for empty outputs" do
      assert Builder.output_sum(%Builder{}) == 0
    end
  end

  describe "sort/1 (BIP-69)" do
    test "sorts inputs by txid then vout" do
      # Create UTXOs with different txids (as bytes, sorted lexicographically)
      utxo_aa = create_p2pkh_utxo(0xAA, 0, 1000, @keypair)
      utxo_bb = create_p2pkh_utxo(0xBB, 0, 2000, @keypair)
      utxo_11 = create_p2pkh_utxo(0x11, 0, 3000, @keypair)

      builder =
        %Builder{}
        |> Builder.add_input(P2PKH.unlock(utxo_bb, %{keypair: @keypair}))
        |> Builder.add_input(P2PKH.unlock(utxo_aa, %{keypair: @keypair}))
        |> Builder.add_input(P2PKH.unlock(utxo_11, %{keypair: @keypair}))

      sorted = Builder.sort(builder)

      # Should be sorted by reversed hash (txid order): 0x11, 0xAA, 0xBB
      [first, second, third] = sorted.inputs

      assert first.subject.outpoint.hash == :binary.copy(<<0x11>>, 32)
      assert second.subject.outpoint.hash == :binary.copy(<<0xAA>>, 32)
      assert third.subject.outpoint.hash == :binary.copy(<<0xBB>>, 32)
    end

    test "sorts inputs by vout when txid is same" do
      utxo_v0 = create_p2pkh_utxo(0xAA, 0, 1000, @keypair)
      utxo_v2 = create_p2pkh_utxo(0xAA, 2, 2000, @keypair)
      utxo_v1 = create_p2pkh_utxo(0xAA, 1, 3000, @keypair)

      builder =
        %Builder{}
        |> Builder.add_input(P2PKH.unlock(utxo_v2, %{keypair: @keypair}))
        |> Builder.add_input(P2PKH.unlock(utxo_v0, %{keypair: @keypair}))
        |> Builder.add_input(P2PKH.unlock(utxo_v1, %{keypair: @keypair}))

      sorted = Builder.sort(builder)

      [first, second, third] = sorted.inputs

      assert first.subject.outpoint.vout == 0
      assert second.subject.outpoint.vout == 1
      assert third.subject.outpoint.vout == 2
    end

    test "sorts outputs by satoshis then script" do
      address1 = Address.from_pubkey(@keypair.pubkey)
      address2 = Address.from_pubkey(@keypair2.pubkey)

      builder =
        %Builder{}
        |> Builder.add_output(P2PKH.lock(5000, %{address: address1}))
        |> Builder.add_output(P2PKH.lock(1000, %{address: address2}))
        |> Builder.add_output(P2PKH.lock(3000, %{address: address1}))

      sorted = Builder.sort(builder)

      [first, second, third] = sorted.outputs

      assert first.subject == 1000
      assert second.subject == 3000
      assert third.subject == 5000
    end
  end

  describe "to_tx/1 with P2PKH" do
    test "builds complete signed P2PKH transaction" do
      utxo = create_p2pkh_utxo(0x01, 0, 10000, @keypair)
      address = Address.from_pubkey(@keypair2.pubkey)

      builder =
        %Builder{}
        |> Builder.add_input(P2PKH.unlock(utxo, %{keypair: @keypair}))
        |> Builder.add_output(P2PKH.lock(9000, %{address: address}))

      tx = Builder.to_tx(builder)

      assert %Transaction{} = tx
      assert tx.version == 1
      assert length(tx.inputs) == 1
      assert length(tx.outputs) == 1

      [output] = tx.outputs

      assert output.satoshis == 9000
    end

    test "built P2PKH transaction has valid signature" do
      utxo = create_p2pkh_utxo(0x01, 0, 10000, @keypair)
      address = Address.from_pubkey(@keypair2.pubkey)

      builder =
        %Builder{}
        |> Builder.add_input(P2PKH.unlock(utxo, %{keypair: @keypair}))
        |> Builder.add_output(P2PKH.lock(9000, %{address: address}))

      tx = Builder.to_tx(builder)

      [input] = tx.inputs
      [sig_chunk, pubkey_chunk] = input.script.chunks

      assert is_binary(sig_chunk)
      assert is_binary(pubkey_chunk)

      assert Sig.verify(sig_chunk, tx, 0, utxo.output, @keypair.pubkey)
    end

    test "builds transaction with multiple inputs" do
      utxo1 = create_p2pkh_utxo(0x01, 0, 10000, @keypair)
      utxo2 = create_p2pkh_utxo(0x02, 0, 15000, @keypair2)

      address = Address.from_pubkey(@keypair.pubkey)

      builder =
        %Builder{}
        |> Builder.add_input(P2PKH.unlock(utxo1, %{keypair: @keypair}))
        |> Builder.add_input(P2PKH.unlock(utxo2, %{keypair: @keypair2}))
        |> Builder.add_output(P2PKH.lock(24000, %{address: address}))

      tx = Builder.to_tx(builder)

      assert length(tx.inputs) == 2
      assert length(tx.outputs) == 1
    end

    test "builds transaction with multiple outputs" do
      utxo = create_p2pkh_utxo(0x01, 0, 20000, @keypair)

      address1 = Address.from_pubkey(@keypair.pubkey)
      address2 = Address.from_pubkey(@keypair2.pubkey)

      builder =
        %Builder{}
        |> Builder.add_input(P2PKH.unlock(utxo, %{keypair: @keypair}))
        |> Builder.add_output(P2PKH.lock(10000, %{address: address1}))
        |> Builder.add_output(P2PKH.lock(9000, %{address: address2}))

      tx = Builder.to_tx(builder)

      assert length(tx.inputs) == 1
      assert length(tx.outputs) == 2
    end
  end

  describe "to_tx/1 with P2WPKH" do
    test "builds complete signed P2WPKH transaction" do
      utxo = create_p2wpkh_utxo(0x01, 0, 10000, @keypair)

      address = Address.from_pubkey(@keypair2.pubkey, type: :p2wpkh)

      builder =
        %Builder{}
        |> Builder.add_input(P2WPKH.unlock(utxo, %{keypair: @keypair}))
        |> Builder.add_output(P2WPKH.lock(9000, %{address: address}))

      tx = Builder.to_tx(builder)

      assert %Transaction{} = tx
      assert Transaction.is_segwit?(tx)

      assert length(tx.inputs) == 1
      assert length(tx.outputs) == 1
    end

    test "P2WPKH input has empty scriptSig" do
      utxo = create_p2wpkh_utxo(0x01, 0, 10000, @keypair)
      address = Address.from_pubkey(@keypair2.pubkey, type: :p2wpkh)

      builder =
        %Builder{}
        |> Builder.add_input(P2WPKH.unlock(utxo, %{keypair: @keypair}))
        |> Builder.add_output(P2WPKH.lock(9000, %{address: address}))

      tx = Builder.to_tx(builder)

      [input] = tx.inputs

      # Native SegWit has empty scriptSig
      assert input.script.chunks == []
    end

    test "P2WPKH input has witness data" do
      utxo = create_p2wpkh_utxo(0x01, 0, 10000, @keypair)
      address = Address.from_pubkey(@keypair2.pubkey, type: :p2wpkh)

      builder =
        %Builder{}
        |> Builder.add_input(P2WPKH.unlock(utxo, %{keypair: @keypair}))
        |> Builder.add_output(P2WPKH.lock(9000, %{address: address}))

      tx = Builder.to_tx(builder)

      [input] = tx.inputs
      assert Witness.has_items?(input.witness)

      # P2WPKH witness: [signature, pubkey]
      assert length(input.witness.items) == 2

      [sig, pubkey] = input.witness.items

      assert is_binary(sig)
      assert byte_size(pubkey) == 33
    end

    test "P2WPKH signature verifies correctly" do
      utxo = create_p2wpkh_utxo(0x01, 0, 10000, @keypair)
      address = Address.from_pubkey(@keypair2.pubkey, type: :p2wpkh)

      builder =
        %Builder{}
        |> Builder.add_input(P2WPKH.unlock(utxo, %{keypair: @keypair}))
        |> Builder.add_output(P2WPKH.lock(9000, %{address: address}))

      tx = Builder.to_tx(builder)

      [input] = tx.inputs
      [signature, _pubkey] = input.witness.items

      pubkey_hash = Satoxi.Hash.sha256_ripemd160(Satoxi.Keys.PubKey.to_binary(@keypair.pubkey))
      script_code = Sig.p2wpkh_script_code(pubkey_hash)

      assert Sig.segwit_verify(signature, tx, 0, utxo.output, script_code, @keypair.pubkey)
    end
  end

  describe "to_tx/1 roundtrip" do
    test "built transaction can be serialized and parsed" do
      utxo = create_p2pkh_utxo(0x01, 0, 10000, @keypair)
      address = Address.from_pubkey(@keypair2.pubkey)

      builder =
        %Builder{}
        |> Builder.add_input(P2PKH.unlock(utxo, %{keypair: @keypair}))
        |> Builder.add_output(P2PKH.lock(9000, %{address: address}))

      tx = Builder.to_tx(builder)

      binary = Transaction.to_binary(tx)

      {:ok, parsed} = Transaction.from_binary(binary)

      assert parsed.version == tx.version
      assert parsed.lock_time == tx.lock_time

      assert length(parsed.inputs) == length(tx.inputs)
      assert length(parsed.outputs) == length(tx.outputs)
    end

    test "SegWit transaction roundtrips correctly" do
      utxo = create_p2wpkh_utxo(0x01, 0, 10000, @keypair)
      address = Address.from_pubkey(@keypair2.pubkey, type: :p2wpkh)

      builder =
        %Builder{}
        |> Builder.add_input(P2WPKH.unlock(utxo, %{keypair: @keypair}))
        |> Builder.add_output(P2WPKH.lock(9000, %{address: address}))

      tx = Builder.to_tx(builder)

      binary = Transaction.to_binary(tx)

      {:ok, parsed} = Transaction.from_binary(binary)

      assert Transaction.is_segwit?(parsed)
      [parsed_input] = parsed.inputs

      assert Witness.has_items?(parsed_input.witness)

      assert length(parsed_input.witness.items) == 2
    end
  end

  describe "lock_time" do
    test "builder respects lock_time setting" do
      utxo = create_p2pkh_utxo(0x01, 0, 10000, @keypair)

      address = Address.from_pubkey(@keypair.pubkey)

      builder = %Builder{
        inputs: [P2PKH.unlock(utxo, %{keypair: @keypair})],
        outputs: [P2PKH.lock(9000, %{address: address})],
        lock_time: 500_000
      }

      tx = Builder.to_tx(builder)

      assert tx.lock_time == 500_000
    end
  end

  # Helper to create a P2PKH UTXO
  defp create_p2pkh_utxo(txid_byte, vout, satoshis, keypair) do
    address = Address.from_pubkey(keypair.pubkey)

    %UTXO{
      outpoint: %OutPoint{
        hash: :binary.copy(<<txid_byte>>, 32),
        vout: vout
      },
      output: %Output{
        satoshis: satoshis,
        script: %Script{
          chunks: [
            :OP_DUP,
            :OP_HASH160,
            address.pubkey_hash,
            :OP_EQUALVERIFY,
            :OP_CHECKSIG
          ]
        }
      }
    }
  end

  # Helper to create a P2WPKH UTXO
  defp create_p2wpkh_utxo(txid_byte, vout, satoshis, keypair) do
    address = Address.from_pubkey(keypair.pubkey, type: :p2wpkh)

    %UTXO{
      outpoint: %OutPoint{
        hash: :binary.copy(<<txid_byte>>, 32),
        vout: vout
      },
      output: %Output{
        satoshis: satoshis,
        script: %Script{
          chunks: [:OP_0, address.witness_program]
        }
      }
    }
  end
end
