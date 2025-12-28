defmodule Satoxi.Address.P2SHTest do
  use ExUnit.Case, async: true
  alias Satoxi.Address.{P2SH, Encoding}
  alias Satoxi.Hash

  @address_str "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"

  doctest P2SH

  describe "from_script_hash/1" do
    test "creates address from 20-byte script hash" do
      script_hash = Hash.sha256_ripemd160(<<1, 2, 3>>)
      address = P2SH.from_script_hash(script_hash)
      assert %P2SH{} = address
      assert address.script_hash == script_hash
    end
  end

  describe "from_script/1" do
    test "creates address from redeem script" do
      redeem_script = <<0x51, 0x21>> <> <<1::256>> <> <<0x51, 0xAE>>
      address = P2SH.from_script(redeem_script)
      assert %P2SH{} = address
      assert byte_size(address.script_hash) == 20
    end

    test "different scripts produce different addresses" do
      script1 = <<1, 2, 3>>
      script2 = <<4, 5, 6>>
      address1 = P2SH.from_script(script1)
      address2 = P2SH.from_script(script2)
      assert address1.script_hash != address2.script_hash
    end
  end

  describe "from_string/1" do
    test "decodes valid mainnet P2SH address" do
      assert {:ok, address} = P2SH.from_string(@address_str)
      assert %P2SH{} = address
      assert byte_size(address.script_hash) == 20
    end

    test "returns error for invalid checksum" do
      invalid = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz"
      assert {:error, _} = P2SH.from_string(invalid)
    end

    test "returns error for legacy P2PKH address (wrong version byte)" do
      legacy_address = "18cqNbEBxkAttxcZLuH9LWhZJPd1BNu1A5"
      assert {:error, {:invalid_version_byte, _, :main}} = P2SH.from_string(legacy_address)
    end
  end

  describe "from_string!/1" do
    test "decodes valid address" do
      address = P2SH.from_string!(@address_str)
      assert %P2SH{} = address
    end

    test "raises on invalid address" do
      assert_raise Satoxi.Error, fn ->
        P2SH.from_string!("invalid")
      end
    end
  end

  describe "to_string/1" do
    test "encodes address to Base58Check string" do
      {:ok, address} = P2SH.from_string(@address_str)
      assert P2SH.to_string(address) == @address_str
    end

    test "produces address starting with 3 on mainnet" do
      script_hash = Hash.sha256_ripemd160(<<1, 2, 3>>)
      address = P2SH.from_script_hash(script_hash)
      string = P2SH.to_string(address)
      assert String.starts_with?(string, "3")
    end
  end

  describe "get_script_hash/1" do
    test "returns the script hash" do
      script_hash = Hash.sha256_ripemd160(<<1, 2, 3>>)
      address = %P2SH{script_hash: script_hash}
      assert P2SH.get_script_hash(address) == script_hash
    end
  end

  describe "Encoding protocol" do
    test "to_string/1 encodes via protocol" do
      {:ok, address} = P2SH.from_string(@address_str)
      assert Encoding.to_string(address) == @address_str
    end

    test "get_hash/1 returns script hash via protocol" do
      script_hash = Hash.sha256_ripemd160(<<1, 2, 3>>)
      address = P2SH.from_script_hash(script_hash)
      assert Encoding.get_hash(address) == script_hash
    end
  end

  describe "roundtrip" do
    test "script_hash -> address -> string -> address" do
      script_hash = Hash.sha256_ripemd160(<<1, 2, 3, 4, 5>>)
      address1 = P2SH.from_script_hash(script_hash)
      string = P2SH.to_string(address1)
      {:ok, address2} = P2SH.from_string(string)
      assert address1 == address2
    end
  end
end
