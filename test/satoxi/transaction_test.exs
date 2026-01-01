defmodule Satoxi.TransactionTest do
  use ExUnit.Case, async: true

  alias Satoxi.Script
  alias Satoxi.Transaction
  alias Satoxi.Transaction.Input
  alias Satoxi.Transaction.Output
  alias Satoxi.Transaction.OutPoint
  alias Satoxi.Transaction.Witness

  doctest Transaction

  @legacy_tx_hex "010000000160f61507c2560a0246b53b96e9a8d28f66d82a8b028204b820de6d10c608d8ad030000006a473044022031a761006d72db7a088a4336c50ea4ca5a8aa76cf355e9ae3866ed3994d0748802205abaa90be33ef7211575b933c0f0a688c3ae175ab55cd8e75f0e07364e4e76d6412103d878146ae9f687c95ac05395db7dfdf2698bdc246158f8672257aab631e4c65cffffffff0123020000000000001976a9142eab375745d7799792b5c5f8b5a9406b8ad55bcc88ac00000000"

  @coinbase_tx_hex "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff41031bc50a2f7461616c2e636f6d2f506c656173652070617920302e3520736174732f627974652c20696e666f407461616c2e636f6d0448aa01c3a015e815410100ffffffff01f072a32e000000001976a9147afaeecc8486abdc2473c48c711a57de958d4bcf88ac00000000"

  @segwit_tx_hex "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d37388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"

  describe "Transaction.from_binary/2" do
    test "parses hex encoded p2pkh tx" do
      assert {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)
      assert length(tx.inputs) == 1
      assert length(tx.outputs) == 1
      refute Transaction.is_coinbase?(tx)
    end

    test "parses hex encoded coinbase tx" do
      assert {:ok, tx} = Transaction.from_binary(@coinbase_tx_hex, encoding: :hex)
      assert length(tx.inputs) == 1
      assert length(tx.outputs) == 1
      assert Transaction.is_coinbase?(tx)
    end

    test "parses hex encoded segwit tx" do
      assert {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)
      assert length(tx.inputs) == 1
      assert length(tx.outputs) == 2
      assert Transaction.is_segwit?(tx)

      # Check witness data was parsed
      [input] = tx.inputs
      assert Witness.has_items?(input.witness)
      assert length(input.witness.items) == 2
    end
  end

  describe "Transaction.is_coinbase?/1" do
    test "returns true if coinbase" do
      assert {:ok, tx} = Transaction.from_binary(@coinbase_tx_hex, encoding: :hex)
      assert Transaction.is_coinbase?(tx)
    end

    test "returns false if not coinbase" do
      assert {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)
      refute Transaction.is_coinbase?(tx)
    end
  end

  describe "Transaction.is_segwit?/1" do
    test "returns false for legacy transaction" do
      {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)
      refute Transaction.is_segwit?(tx)
    end

    test "returns true for segwit transaction" do
      {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)
      assert Transaction.is_segwit?(tx)
    end

    test "returns false for transaction with empty witness" do
      tx = %Transaction{
        inputs: [%Input{witness: %Witness{items: []}}],
        outputs: []
      }

      refute Transaction.is_segwit?(tx)
    end

    test "returns true if any input has witness data" do
      tx = %Transaction{
        inputs: [
          %Input{witness: %Witness{items: []}},
          %Input{witness: %Witness{items: [<<1, 2, 3>>]}}
        ],
        outputs: []
      }

      assert Transaction.is_segwit?(tx)
    end
  end

  describe "Transaction.to_binary/2" do
    test "serializes legacy transaction" do
      {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)
      assert Transaction.to_binary(tx, encoding: :hex) == @legacy_tx_hex
    end

    test "serializes segwit transaction" do
      {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)
      assert Transaction.to_binary(tx, encoding: :hex) == @segwit_tx_hex
    end

    test "serializes segwit transaction as legacy with segwit: false" do
      {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)
      legacy_binary = Transaction.to_binary(tx, segwit: false)

      # Should not have marker/flag bytes
      <<_version::binary-4, rest::binary>> = legacy_binary
      refute match?(<<0x00, 0x01, _::binary>>, rest)

      # Should be smaller than segwit version (no witness data)
      segwit_binary = Transaction.to_binary(tx, segwit: true)
      assert byte_size(legacy_binary) < byte_size(segwit_binary)
    end
  end

  describe "Transaction.get_hash/1 and Transaction.get_txid/1" do
    test "returns correct txid for legacy transaction" do
      {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)
      txid = Transaction.get_txid(tx)

      assert is_binary(txid)
      assert byte_size(txid) == 64
    end

    test "returns txid without witness data for segwit transaction" do
      {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)

      # TXID should be hash of non-witness serialization
      txid = Transaction.get_txid(tx)
      wtxid = Transaction.get_wtxid(tx)

      refute txid == wtxid
    end
  end

  describe "Transaction.get_witness_hash/1 and Transaction.get_wtxid/1" do
    test "returns same as txid for legacy transaction" do
      {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)

      assert Transaction.get_txid(tx) == Transaction.get_wtxid(tx)
      assert Transaction.get_hash(tx) == Transaction.get_witness_hash(tx)
    end

    test "includes witness data for segwit transaction" do
      {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)

      wtxid = Transaction.get_wtxid(tx)
      assert is_binary(wtxid)
      assert byte_size(wtxid) == 64
    end
  end

  describe "Transaction.get_size/1" do
    test "returns byte size of legacy transaction" do
      {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)
      expected_size = div(byte_size(@legacy_tx_hex), 2)

      assert Transaction.get_size(tx) == expected_size
    end

    test "returns full size including witness for segwit transaction" do
      {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)
      expected_size = div(byte_size(@segwit_tx_hex), 2)

      assert Transaction.get_size(tx) == expected_size
    end
  end

  describe "Transaction.get_base_size/1" do
    test "returns same as get_size for legacy transaction" do
      {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)

      assert Transaction.get_base_size(tx) == Transaction.get_size(tx)
    end

    test "returns size without witness for segwit transaction" do
      {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)

      base_size = Transaction.get_base_size(tx)
      full_size = Transaction.get_size(tx)

      assert base_size < full_size
    end
  end

  describe "Transaction.get_weight/1" do
    test "returns base_size * 4 for legacy transaction" do
      {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)

      # For legacy tx: weight = base_size * 3 + total_size = base_size * 4
      assert Transaction.get_weight(tx) == Transaction.get_size(tx) * 4
    end

    test "returns correct weight for segwit transaction" do
      {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)

      base_size = Transaction.get_base_size(tx)
      total_size = Transaction.get_size(tx)

      # weight = base_size * 3 + total_size
      expected_weight = base_size * 3 + total_size
      assert Transaction.get_weight(tx) == expected_weight
    end
  end

  describe "Transaction.get_vsize/1" do
    test "returns same as size for legacy transaction" do
      {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)

      # vsize = ceil(weight / 4) = ceil(size * 4 / 4) = size
      assert Transaction.get_vsize(tx) == Transaction.get_size(tx)
    end

    test "returns ceil(weight / 4) for segwit transaction" do
      {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)

      weight = Transaction.get_weight(tx)
      expected_vsize = ceil(weight / 4)

      assert Transaction.get_vsize(tx) == expected_vsize

      # vsize should be between base_size and total_size
      assert Transaction.get_vsize(tx) >= Transaction.get_base_size(tx)
      assert Transaction.get_vsize(tx) <= Transaction.get_size(tx)
    end
  end

  describe "roundtrip parsing and serialization" do
    test "legacy transaction survives roundtrip" do
      {:ok, tx} = Transaction.from_binary(@legacy_tx_hex, encoding: :hex)
      serialized = Transaction.to_binary(tx, encoding: :hex)

      assert serialized == @legacy_tx_hex
    end

    test "segwit transaction survives roundtrip" do
      {:ok, tx} = Transaction.from_binary(@segwit_tx_hex, encoding: :hex)
      serialized = Transaction.to_binary(tx, encoding: :hex)

      assert serialized == @segwit_tx_hex
    end

    test "manually constructed segwit transaction roundtrips" do
      sig = :binary.copy(<<0x30>>, 71)
      pubkey = <<0x02>> <> :binary.copy(<<0x00>>, 32)

      tx = %Transaction{
        version: 1,
        inputs: [
          %Input{
            outpoint: %OutPoint{
              hash: :binary.copy(<<0xAB>>, 32),
              vout: 0
            },
            script: %Script{chunks: []},
            sequence: 0xFFFFFFFF,
            witness: %Witness{items: [sig, pubkey]}
          }
        ],
        outputs: [
          %Output{
            satoshis: 50000,
            script: %Script{chunks: [<<0x00>>, :binary.copy(<<0xCD>>, 20)]}
          }
        ],
        lock_time: 0
      }

      binary = Transaction.to_binary(tx)
      {:ok, parsed} = Transaction.from_binary(binary)

      assert parsed.version == tx.version
      assert parsed.lock_time == tx.lock_time
      assert length(parsed.inputs) == 1
      assert length(parsed.outputs) == 1

      [parsed_input] = parsed.inputs
      assert parsed_input.witness.items == [sig, pubkey]
    end
  end
end
