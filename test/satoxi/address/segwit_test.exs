defmodule Satoxi.Address.SegWitTest do
  use ExUnit.Case, async: true
  alias Satoxi.Address.{SegWit, Encoding}
  alias Satoxi.Keys.PubKey

  @pubkey_bin <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232, 175, 144,
                63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
  @pubkey_hash <<83, 143, 209, 121, 200, 190, 15, 40, 156, 115, 14, 51, 181, 246, 163, 84, 27,
                 233, 102, 143>>

  @p2wpkh_address "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

  doctest SegWit

  describe "from_pubkey/1" do
    test "creates P2WPKH address from compressed pubkey binary" do
      address = SegWit.from_pubkey(@pubkey_bin)
      assert %SegWit{} = address
      assert address.type == :p2wpkh
      assert address.witness_version == 0
      assert address.witness_program == @pubkey_hash
    end

    test "creates address from uncompressed pubkey binary" do
      uncompressed =
        <<4, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232, 175, 144, 63,
          199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57, 1, 135, 135, 125, 5,
          134, 136, 158, 82, 54, 184, 224, 42, 2, 75, 140, 90, 22, 8, 122, 233, 116, 221, 100, 93,
          180, 96, 132, 105, 242, 152, 151>>

      address = SegWit.from_pubkey(uncompressed)
      assert %SegWit{} = address
      assert address.type == :p2wpkh
      assert byte_size(address.witness_program) == 20
    end

    test "creates address from PubKey struct" do
      {:ok, pubkey} = PubKey.from_binary(@pubkey_bin)
      address = SegWit.from_pubkey(pubkey)
      assert %SegWit{} = address
      assert address.type == :p2wpkh
      assert address.witness_program == @pubkey_hash
    end
  end

  describe "from_pubkey_hash/1" do
    test "creates P2WPKH address from 20-byte hash" do
      address = SegWit.from_pubkey_hash(@pubkey_hash)
      assert %SegWit{} = address
      assert address.type == :p2wpkh
      assert address.witness_version == 0
      assert address.witness_program == @pubkey_hash
    end
  end

  describe "from_witness_script_hash/1" do
    test "creates P2WSH address from 32-byte hash" do
      script_hash = :crypto.hash(:sha256, <<1, 2, 3>>)
      address = SegWit.from_witness_script_hash(script_hash)
      assert %SegWit{} = address
      assert address.type == :p2wsh
      assert address.witness_version == 0
      assert address.witness_program == script_hash
    end
  end

  describe "from_witness_script/1" do
    test "creates P2WSH address from witness script" do
      witness_script = <<0x51, 0x21>> <> <<1::264>> <> <<0x51, 0xAE>>
      address = SegWit.from_witness_script(witness_script)
      assert %SegWit{} = address
      assert address.type == :p2wsh
      assert byte_size(address.witness_program) == 32
    end

    test "different scripts produce different addresses" do
      script1 = <<1, 2, 3>>
      script2 = <<4, 5, 6>>
      address1 = SegWit.from_witness_script(script1)
      address2 = SegWit.from_witness_script(script2)
      assert address1.witness_program != address2.witness_program
    end
  end

  describe "from_string/1" do
    test "decodes valid P2WPKH address" do
      assert {:ok, address} = SegWit.from_string(@p2wpkh_address)
      assert %SegWit{} = address
      assert address.type == :p2wpkh
      assert address.witness_version == 0
      assert byte_size(address.witness_program) == 20
    end

    test "decodes valid P2WSH address" do
      p2wsh_address = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
      assert {:ok, address} = SegWit.from_string(p2wsh_address)
      assert %SegWit{} = address
      assert address.type == :p2wsh
      assert byte_size(address.witness_program) == 32
    end

    test "returns error for invalid bech32" do
      assert {:error, _} = SegWit.from_string("bc1invalid")
    end
  end

  describe "from_string!/1" do
    test "decodes valid address" do
      address = SegWit.from_string!(@p2wpkh_address)
      assert %SegWit{} = address
      assert address.type == :p2wpkh
    end

    test "raises on invalid address" do
      assert_raise Satoxi.Error, fn ->
        SegWit.from_string!("bc1invalid")
      end
    end
  end

  describe "to_string/1" do
    test "encodes P2WPKH address to bech32 string" do
      {:ok, address} = SegWit.from_string(@p2wpkh_address)
      assert SegWit.to_string(address) == @p2wpkh_address
    end

    test "produces address starting with bc1q on mainnet" do
      address = SegWit.from_pubkey(@pubkey_bin)
      string = SegWit.to_string(address)
      assert String.starts_with?(string, "bc1q")
    end
  end

  describe "get_witness_program/1" do
    test "returns the witness program for P2WPKH" do
      address = SegWit.from_pubkey_hash(@pubkey_hash)
      assert SegWit.get_witness_program(address) == @pubkey_hash
    end

    test "returns the witness program for P2WSH" do
      script_hash = :crypto.hash(:sha256, <<1, 2, 3>>)
      address = SegWit.from_witness_script_hash(script_hash)
      assert SegWit.get_witness_program(address) == script_hash
    end
  end

  describe "p2wpkh?/1 and p2wsh?/1" do
    test "p2wpkh? returns true for P2WPKH" do
      address = SegWit.from_pubkey(@pubkey_bin)
      assert SegWit.p2wpkh?(address)
      refute SegWit.p2wsh?(address)
    end

    test "p2wsh? returns true for P2WSH" do
      script_hash = :crypto.hash(:sha256, <<1, 2, 3>>)
      address = SegWit.from_witness_script_hash(script_hash)
      assert SegWit.p2wsh?(address)
      refute SegWit.p2wpkh?(address)
    end
  end

  describe "Encoding protocol" do
    test "to_string/1 encodes via protocol" do
      {:ok, address} = SegWit.from_string(@p2wpkh_address)
      assert Encoding.to_string(address) == @p2wpkh_address
    end

    test "get_hash/1 returns witness program via protocol" do
      address = SegWit.from_pubkey_hash(@pubkey_hash)
      assert Encoding.get_hash(address) == @pubkey_hash
    end
  end

  describe "roundtrip" do
    test "pubkey -> P2WPKH address -> string -> address" do
      address1 = SegWit.from_pubkey(@pubkey_bin)
      string = SegWit.to_string(address1)
      {:ok, address2} = SegWit.from_string(string)
      assert address1 == address2
    end

    test "script_hash -> P2WSH address -> string -> address" do
      script_hash = :crypto.hash(:sha256, <<1, 2, 3, 4, 5>>)
      address1 = SegWit.from_witness_script_hash(script_hash)
      string = SegWit.to_string(address1)
      {:ok, address2} = SegWit.from_string(string)
      assert address1 == address2
    end
  end
end
