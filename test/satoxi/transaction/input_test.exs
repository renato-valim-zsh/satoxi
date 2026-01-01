defmodule Satoxi.Transaction.InputTest do
  use ExUnit.Case, async: true

  alias Satoxi.Script
  alias Satoxi.Transaction.Input
  alias Satoxi.Transaction.OutPoint
  alias Satoxi.Transaction.Witness

  @input_hex "5e1bb1a8c3a80dcbed1b08bd55e71e4c3a4e0045bba2dabd8b16103eff2bb062020000006b4830450221008861eda0220f1398701f28020bb61a6cbb36d7467a568f84d0809b59d8b07a580220718bee3962e867132e058ed224607ad345183629a6d4429de8bba1899f0e34ee4121036d2280f540164e6a1fc5b272b2eb4b09b61d6144df474b837d36fbb054e984b7ffffffff"

  @input_script %Script{
    chunks: [
      <<48, 69, 2, 33, 0, 136, 97, 237, 160, 34, 15, 19, 152, 112, 31, 40, 2, 11, 182, 26, 108,
        187, 54, 215, 70, 122, 86, 143, 132, 208, 128, 155, 89, 216, 176, 122, 88, 2, 32, 113,
        139, 238, 57, 98, 232, 103, 19, 46, 5, 142, 210, 36, 96, 122, 211, 69, 24, 54, 41, 166,
        212, 66, 157, 232, 187, 161, 137, 159, 14, 52, 238, 65>>,
      <<3, 109, 34, 128, 245, 64, 22, 78, 106, 31, 197, 178, 114, 178, 235, 75, 9, 182, 29, 97,
        68, 223, 71, 75, 131, 125, 54, 251, 176, 84, 233, 132, 183>>
    ]
  }

  @outpoint_hash <<94, 27, 177, 168, 195, 168, 13, 203, 237, 27, 8, 189, 85, 231, 30, 76, 58, 78,
                   0, 69, 187, 162, 218, 189, 139, 22, 16, 62, 255, 43, 176, 98>>

  doctest Input

  describe "Input.from_binary/2" do
    test "parses hex encoded p2pkh input" do
      assert {:ok, %Input{script: script} = input} = Input.from_binary(@input_hex, encoding: :hex)
      assert input.outpoint.hash == @outpoint_hash
      assert input.outpoint.vout == 2
      assert script == @input_script
    end
  end

  describe "Input.from_binary!/2" do
    test "parses hex encoded p2pkh input" do
      assert %Input{script: script} = input = Input.from_binary!(@input_hex, encoding: :hex)
      assert input.outpoint.hash == @outpoint_hash
      assert input.outpoint.vout == 2
      assert script == @input_script
    end
  end

  describe "Input.get_size/2" do
    test "returns byte size of the input" do
      input = %Input{
        outpoint: %OutPoint{hash: @outpoint_hash, vout: 2},
        script: @input_script
      }

      assert Input.get_size(input) == 148
    end
  end

  describe "Input.to_binary/2" do
    test "serialises p2pkh input as hex string" do
      input = %Input{
        outpoint: %OutPoint{hash: @outpoint_hash, vout: 2},
        script: @input_script
      }

      assert Input.to_binary(input, encoding: :hex) == @input_hex
    end
  end

  describe "Input.has_witness?/1" do
    test "returns false when witness is empty" do
      input = %Input{witness: %Witness{items: []}}
      refute Input.has_witness?(input)
    end

    test "returns false when witness has default value" do
      input = %Input{}
      refute Input.has_witness?(input)
    end

    test "returns true when witness has data" do
      input = %Input{witness: %Witness{items: [<<1, 2, 3>>, <<4, 5, 6>>]}}
      assert Input.has_witness?(input)
    end

    test "returns true with single witness item" do
      input = %Input{witness: %Witness{items: [<<0x00>>]}}
      assert Input.has_witness?(input)
    end
  end

  describe "Input.serialize_witness/1" do
    test "returns single zero byte when witness is empty" do
      input = %Input{witness: %Witness{items: []}}
      assert Input.serialize_witness(input) == <<0x00>>
    end

    test "returns single zero byte when witness has default value" do
      input = %Input{}
      assert Input.serialize_witness(input) == <<0x00>>
    end

    test "serializes witness stack with single item" do
      # Single 3-byte item: [<<1, 2, 3>>]
      # Format: count (1 byte) + len (1 byte) + data (3 bytes)
      input = %Input{witness: %Witness{items: [<<1, 2, 3>>]}}
      serialized = Input.serialize_witness(input)

      # 0x01 = 1 item, 0x03 = 3 bytes length, then the data
      assert serialized == <<0x01, 0x03, 1, 2, 3>>
    end

    test "serializes witness stack with multiple items" do
      # Two items: signature and pubkey (typical P2WPKH)
      sig = <<0x30, 0x44>> <> :binary.copy(<<0>>, 68)
      pubkey = <<0x02>> <> :binary.copy(<<0>>, 32)

      input = %Input{witness: %Witness{items: [sig, pubkey]}}
      serialized = Input.serialize_witness(input)

      # First byte should be item count (2)
      assert <<0x02, rest::binary>> = serialized
      # Next should be length of sig (70) then sig data
      # Then length of pubkey then pubkey data
      assert <<70, _sig::binary-70, 33, _pubkey::binary-33>> = rest
    end

    test "serializes empty witness item" do
      # Empty item (used in multisig for OP_0)
      input = %Input{witness: %Witness{items: [<<>>]}}
      serialized = Input.serialize_witness(input)

      # 0x01 = 1 item, 0x00 = 0 bytes length
      assert serialized == <<0x01, 0x00>>
    end
  end

  describe "Input.get_witness_size/1" do
    test "returns 1 for empty witness" do
      input = %Input{witness: %Witness{items: []}}
      assert Input.get_witness_size(input) == 1
    end

    test "returns 1 for default witness" do
      input = %Input{}
      assert Input.get_witness_size(input) == 1
    end

    test "returns correct size for witness with data" do
      input = %Input{witness: %Witness{items: [<<1, 2, 3>>]}}
      # 1 byte count + 1 byte length + 3 bytes data = 5
      assert Input.get_witness_size(input) == 5
    end

    test "returns correct size for typical P2WPKH witness" do
      # Typical P2WPKH: 71-byte sig + 33-byte pubkey
      sig = :binary.copy(<<0>>, 71)
      pubkey = :binary.copy(<<0>>, 33)

      input = %Input{witness: %Witness{items: [sig, pubkey]}}
      # 1 byte count + 1 byte len + 71 sig + 1 byte len + 33 pubkey = 107
      assert Input.get_witness_size(input) == 107
    end
  end
end
