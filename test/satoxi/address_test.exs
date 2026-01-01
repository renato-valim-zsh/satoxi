defmodule Satoxi.AddressTest do
  use ExUnit.Case, async: true

  alias Satoxi.Address
  alias Satoxi.Address.Legacy
  alias Satoxi.Address.Nested
  alias Satoxi.Address.P2SH
  alias Satoxi.Address.SegWit
  alias Satoxi.Keys.PubKey

  @pubkey_bin <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232, 175, 144,
                63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
  @legacy_address "18cqNbEBxkAttxcZLuH9LWhZJPd1BNu1A5"
  @p2sh_address "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
  @segwit_address "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

  doctest Address

  describe "from_pubkey/2" do
    test "creates Legacy P2PKH address by default" do
      address = Address.from_pubkey(@pubkey_bin)
      assert %Legacy{} = address
      assert Address.to_string(address) == @legacy_address
    end

    test "creates Legacy address with type: :p2pkh" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2pkh)
      assert %Legacy{} = address
    end

    test "creates SegWit P2WPKH address with type: :p2wpkh" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2wpkh)
      assert %SegWit{} = address
      assert address.type == :p2wpkh
    end

    test "creates Nested SegWit address with type: :p2sh_p2wpkh" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2sh_p2wpkh)
      assert %Nested{} = address
    end

    test "works with PubKey struct" do
      {:ok, pubkey} = PubKey.from_binary(@pubkey_bin)
      address = Address.from_pubkey(pubkey)
      assert %Legacy{} = address
    end
  end

  describe "from_string/1" do
    test "parses Legacy P2PKH address" do
      assert {:ok, address} = Address.from_string(@legacy_address)
      assert %Legacy{} = address
    end

    test "parses P2SH address" do
      assert {:ok, address} = Address.from_string(@p2sh_address)
      assert %P2SH{} = address
    end

    test "parses SegWit P2WPKH address" do
      assert {:ok, address} = Address.from_string(@segwit_address)
      assert %SegWit{} = address
      assert address.type == :p2wpkh
    end

    test "parses SegWit P2WSH address" do
      p2wsh = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
      assert {:ok, address} = Address.from_string(p2wsh)
      assert %SegWit{} = address
      assert address.type == :p2wsh
    end

    test "returns error for invalid address" do
      assert {:error, _} = Address.from_string("invalid")
    end
  end

  describe "from_string!/1" do
    test "parses valid address" do
      address = Address.from_string!(@legacy_address)
      assert %Legacy{} = address
    end

    test "raises on invalid address" do
      assert_raise Satoxi.Error, fn ->
        Address.from_string!("invalid")
      end
    end
  end

  describe "to_string/1" do
    test "encodes Legacy address" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2pkh)
      assert Address.to_string(address) == @legacy_address
    end

    test "encodes SegWit address" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2wpkh)
      string = Address.to_string(address)
      assert String.starts_with?(string, "bc1q")
    end

    test "encodes P2SH address" do
      {:ok, address} = Address.from_string(@p2sh_address)
      assert Address.to_string(address) == @p2sh_address
    end

    test "encodes Nested address" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2sh_p2wpkh)
      string = Address.to_string(address)
      assert String.starts_with?(string, "3")
    end
  end

  describe "get_hash/1" do
    test "returns pubkey hash for Legacy" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2pkh)
      hash = Address.get_hash(address)
      assert byte_size(hash) == 20
    end

    test "returns witness program for SegWit" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2wpkh)
      hash = Address.get_hash(address)
      assert byte_size(hash) == 20
    end

    test "returns script hash for P2SH" do
      {:ok, address} = Address.from_string(@p2sh_address)
      hash = Address.get_hash(address)
      assert byte_size(hash) == 20
    end

    test "returns script hash for Nested" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2sh_p2wpkh)
      hash = Address.get_hash(address)
      assert byte_size(hash) == 20
    end
  end

  describe "type/1" do
    test "returns :p2pkh for Legacy" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2pkh)
      assert Address.type(address) == :p2pkh
    end

    test "returns :p2sh for P2SH" do
      {:ok, address} = Address.from_string(@p2sh_address)
      assert Address.type(address) == :p2sh
    end

    test "returns :p2wpkh for SegWit P2WPKH" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2wpkh)
      assert Address.type(address) == :p2wpkh
    end

    test "returns :p2wsh for SegWit P2WSH" do
      script_hash = :crypto.hash(:sha256, <<1, 2, 3>>)
      address = SegWit.from_witness_script_hash(script_hash)
      assert Address.type(address) == :p2wsh
    end

    test "returns :p2sh_p2wpkh for Nested" do
      address = Address.from_pubkey(@pubkey_bin, type: :p2sh_p2wpkh)
      assert Address.type(address) == :p2sh_p2wpkh
    end
  end

  describe "delegate functions" do
    test "legacy_from_pubkey/1" do
      address = Address.legacy_from_pubkey(@pubkey_bin)
      assert %Legacy{} = address
    end

    test "legacy_from_pubkey_hash/1" do
      hash = <<1::160>>
      address = Address.legacy_from_pubkey_hash(hash)
      assert %Legacy{} = address
    end

    test "p2sh_from_script_hash/1" do
      hash = <<1::160>>
      address = Address.p2sh_from_script_hash(hash)
      assert %P2SH{} = address
    end

    test "p2sh_from_script/1" do
      script = <<1, 2, 3>>
      address = Address.p2sh_from_script(script)
      assert %P2SH{} = address
    end

    test "segwit_from_pubkey/1" do
      address = Address.segwit_from_pubkey(@pubkey_bin)
      assert %SegWit{} = address
      assert address.type == :p2wpkh
    end

    test "segwit_from_pubkey_hash/1" do
      hash = <<1::160>>
      address = Address.segwit_from_pubkey_hash(hash)
      assert %SegWit{} = address
    end

    test "segwit_from_witness_script_hash/1" do
      hash = <<1::256>>
      address = Address.segwit_from_witness_script_hash(hash)
      assert %SegWit{} = address
      assert address.type == :p2wsh
    end

    test "segwit_from_witness_script/1" do
      script = <<1, 2, 3>>
      address = Address.segwit_from_witness_script(script)
      assert %SegWit{} = address
      assert address.type == :p2wsh
    end

    test "nested_from_pubkey/1" do
      address = Address.nested_from_pubkey(@pubkey_bin)
      assert %Nested{} = address
    end

    test "nested_from_pubkey_hash/1" do
      hash = <<1::160>>
      address = Address.nested_from_pubkey_hash(hash)
      assert %Nested{} = address
    end
  end

  describe "roundtrip" do
    test "from_pubkey -> to_string -> from_string for Legacy" do
      address1 = Address.from_pubkey(@pubkey_bin, type: :p2pkh)
      string = Address.to_string(address1)
      {:ok, address2} = Address.from_string(string)
      assert address1 == address2
    end

    test "from_pubkey -> to_string -> from_string for SegWit" do
      address1 = Address.from_pubkey(@pubkey_bin, type: :p2wpkh)
      string = Address.to_string(address1)
      {:ok, address2} = Address.from_string(string)
      assert address1 == address2
    end
  end
end
