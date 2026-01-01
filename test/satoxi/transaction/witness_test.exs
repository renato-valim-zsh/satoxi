defmodule Satoxi.Transaction.WitnessTest do
  use ExUnit.Case, async: true

  alias Satoxi.Serializable
  alias Satoxi.Transaction.Witness

  doctest Witness

  describe "Serializable.parse/2" do
    test "parses empty witness" do
      data = <<0x00>>
      assert {:ok, %Witness{items: []}, <<>>} = Serializable.parse(%Witness{}, data)
    end

    test "parses witness with single item" do
      # 1 item, 3 bytes length, data
      data = <<0x01, 0x03, 1, 2, 3>>
      assert {:ok, %Witness{items: [<<1, 2, 3>>]}, <<>>} = Serializable.parse(%Witness{}, data)
    end

    test "parses witness with multiple items" do
      # 2 items: first is 2 bytes, second is 3 bytes
      data = <<0x02, 0x02, 0xAA, 0xBB, 0x03, 0xCC, 0xDD, 0xEE>>

      assert {:ok, %Witness{items: [<<0xAA, 0xBB>>, <<0xCC, 0xDD, 0xEE>>]}, <<>>} =
               Serializable.parse(%Witness{}, data)
    end

    test "parses witness with empty item" do
      # 1 item with 0 bytes (used for OP_0 in multisig)
      data = <<0x01, 0x00>>
      assert {:ok, %Witness{items: [<<>>]}, <<>>} = Serializable.parse(%Witness{}, data)
    end

    test "parses typical P2WPKH witness" do
      # 2 items: 71-byte signature + 33-byte pubkey
      sig = :binary.copy(<<0xAB>>, 71)
      pubkey = :binary.copy(<<0xCD>>, 33)

      data = <<0x02, 71>> <> sig <> <<33>> <> pubkey

      assert {:ok, %Witness{items: [^sig, ^pubkey]}, <<>>} = Serializable.parse(%Witness{}, data)
    end

    test "returns remaining bytes after parsing" do
      # Witness data followed by extra bytes
      data = <<0x01, 0x02, 0xAA, 0xBB, 0xFF, 0xEE>>

      assert {:ok, %Witness{items: [<<0xAA, 0xBB>>]}, <<0xFF, 0xEE>>} =
               Serializable.parse(%Witness{}, data)
    end

    test "parses witness with VarInt count > 252" do
      # 253 items (uses 0xFD prefix for VarInt)
      items = for i <- 1..253, do: <<i::8>>
      items_data = Enum.reduce(items, <<>>, fn item, acc -> acc <> <<1>> <> item end)
      data = <<0xFD, 253, 0>> <> items_data

      assert {:ok, %Witness{items: parsed_items}, <<>>} = Serializable.parse(%Witness{}, data)
      assert length(parsed_items) == 253
    end

    test "parses witness with large item using VarInt length" do
      # Single item with 300 bytes (uses 0xFD prefix for length)
      large_item = :binary.copy(<<0xAA>>, 300)
      data = <<0x01, 0xFD, 44, 1>> <> large_item

      assert {:ok, %Witness{items: [^large_item]}, <<>>} = Serializable.parse(%Witness{}, data)
    end
  end

  describe "Serializable.serialize/1" do
    test "serializes empty witness" do
      witness = %Witness{items: []}
      assert Serializable.serialize(witness) == <<0x00>>
    end

    test "serializes nil items as empty witness" do
      witness = %Witness{items: nil}
      assert Serializable.serialize(witness) == <<0x00>>
    end

    test "serializes witness with single item" do
      witness = %Witness{items: [<<1, 2, 3>>]}
      assert Serializable.serialize(witness) == <<0x01, 0x03, 1, 2, 3>>
    end

    test "serializes witness with multiple items" do
      witness = %Witness{items: [<<0xAA, 0xBB>>, <<0xCC, 0xDD, 0xEE>>]}
      assert Serializable.serialize(witness) == <<0x02, 0x02, 0xAA, 0xBB, 0x03, 0xCC, 0xDD, 0xEE>>
    end

    test "serializes witness with empty item" do
      witness = %Witness{items: [<<>>]}
      assert Serializable.serialize(witness) == <<0x01, 0x00>>
    end

    test "serializes typical P2WPKH witness" do
      sig = :binary.copy(<<0xAB>>, 71)
      pubkey = :binary.copy(<<0xCD>>, 33)
      witness = %Witness{items: [sig, pubkey]}

      serialized = Serializable.serialize(witness)

      assert <<0x02, 71, sig_data::binary-71, 33, pubkey_data::binary-33>> = serialized
      assert sig_data == sig
      assert pubkey_data == pubkey
    end

    test "serializes witness with large item using VarInt" do
      large_item = :binary.copy(<<0xAA>>, 300)
      witness = %Witness{items: [large_item]}

      serialized = Serializable.serialize(witness)

      # 1 item count + VarInt(300) = 0xFD 0x2C 0x01 + 300 bytes
      assert <<0x01, 0xFD, 44, 1, data::binary-300>> = serialized
      assert data == large_item
    end
  end

  describe "roundtrip parse/serialize" do
    test "empty witness roundtrips" do
      witness = %Witness{items: []}
      assert {:ok, ^witness, <<>>} = witness |> Serializable.serialize() |> parse()
    end

    test "single item roundtrips" do
      witness = %Witness{items: [<<1, 2, 3, 4, 5>>]}
      assert {:ok, ^witness, <<>>} = witness |> Serializable.serialize() |> parse()
    end

    test "multiple items roundtrip" do
      witness = %Witness{items: [<<0xDE, 0xAD>>, <<0xBE, 0xEF>>, <<0xCA, 0xFE>>]}
      assert {:ok, ^witness, <<>>} = witness |> Serializable.serialize() |> parse()
    end

    test "P2WPKH witness roundtrips" do
      sig = :binary.copy(<<0x30>>, 71)
      pubkey = <<0x02>> <> :binary.copy(<<0x00>>, 32)
      witness = %Witness{items: [sig, pubkey]}

      assert {:ok, ^witness, <<>>} = witness |> Serializable.serialize() |> parse()
    end

    test "P2WSH multisig witness roundtrips" do
      # Typical 2-of-3 multisig: OP_0 + 2 sigs + redeem script
      witness = %Witness{
        items: [
          <<>>,
          :binary.copy(<<0x30>>, 71),
          :binary.copy(<<0x30>>, 72),
          :binary.copy(<<0x52>>, 105)
        ]
      }

      assert {:ok, ^witness, <<>>} = witness |> Serializable.serialize() |> parse()
    end

    defp parse(data), do: Serializable.parse(%Witness{}, data)
  end

  describe "Witness.has_items?/1" do
    test "returns false for empty items" do
      refute Witness.has_items?(%Witness{items: []})
    end

    test "returns false for nil items" do
      refute Witness.has_items?(%Witness{items: nil})
    end

    test "returns true for single item" do
      assert Witness.has_items?(%Witness{items: [<<0x00>>]})
    end

    test "returns true for multiple items" do
      assert Witness.has_items?(%Witness{items: [<<1>>, <<2>>, <<3>>]})
    end

    test "returns true for empty binary item" do
      # An empty binary is still an item (used for OP_0)
      assert Witness.has_items?(%Witness{items: [<<>>]})
    end
  end

  describe "Witness.get_size/1" do
    test "returns 1 for empty witness" do
      # Just the 0x00 count byte
      assert Witness.get_size(%Witness{items: []}) == 1
    end

    test "returns correct size for single item" do
      # 1 byte count + 1 byte length + 3 bytes data = 5
      assert Witness.get_size(%Witness{items: [<<1, 2, 3>>]}) == 5
    end

    test "returns correct size for multiple items" do
      # 1 byte count + (1 + 2) + (1 + 3) = 8
      assert Witness.get_size(%Witness{items: [<<0xAA, 0xBB>>, <<0xCC, 0xDD, 0xEE>>]}) == 8
    end

    test "returns correct size for empty item" do
      # 1 byte count + 1 byte length (0x00) = 2
      assert Witness.get_size(%Witness{items: [<<>>]}) == 2
    end

    test "returns correct size for typical P2WPKH witness" do
      sig = :binary.copy(<<0>>, 71)
      pubkey = :binary.copy(<<0>>, 33)

      # 1 byte count + 1 byte len + 71 sig + 1 byte len + 33 pubkey = 107
      assert Witness.get_size(%Witness{items: [sig, pubkey]}) == 107
    end

    test "returns correct size for large item with VarInt length" do
      large_item = :binary.copy(<<0>>, 300)

      # 1 byte count + 3 bytes VarInt(300) + 300 bytes = 304
      assert Witness.get_size(%Witness{items: [large_item]}) == 304
    end
  end
end
