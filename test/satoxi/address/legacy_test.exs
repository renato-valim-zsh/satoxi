defmodule Satoxi.Address.LegacyTest do
  use ExUnit.Case, async: true
  alias Satoxi.Address.{Legacy, Encoding}
  alias Satoxi.Keys.PubKey

  @pubkey_bin <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232, 175, 144,
                63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
  @pubkey_hash <<83, 143, 209, 121, 200, 190, 15, 40, 156, 115, 14, 51, 181, 246, 163, 84, 27,
                 233, 102, 143>>
  @address_str "18cqNbEBxkAttxcZLuH9LWhZJPd1BNu1A5"

  doctest Legacy

  describe "from_pubkey/1" do
    test "creates address from compressed pubkey binary" do
      address = Legacy.from_pubkey(@pubkey_bin)
      assert %Legacy{} = address
      assert address.pubkey_hash == @pubkey_hash
    end

    test "creates address from uncompressed pubkey binary" do
      # Uncompressed pubkey (65 bytes starting with 0x04)
      uncompressed =
        <<4, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232, 175, 144, 63,
          199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57, 1, 135, 135, 125, 5,
          134, 136, 158, 82, 54, 184, 224, 42, 2, 75, 140, 90, 22, 8, 122, 233, 116, 221, 100, 93,
          180, 96, 132, 105, 242, 152, 151>>

      address = Legacy.from_pubkey(uncompressed)
      assert %Legacy{} = address
      assert byte_size(address.pubkey_hash) == 20
    end

    test "creates address from PubKey struct" do
      {:ok, pubkey} = PubKey.from_binary(@pubkey_bin)
      address = Legacy.from_pubkey(pubkey)
      assert %Legacy{} = address
      assert address.pubkey_hash == @pubkey_hash
    end
  end

  describe "from_pubkey_hash/1" do
    test "creates address from 20-byte hash" do
      address = Legacy.from_pubkey_hash(@pubkey_hash)
      assert %Legacy{} = address
      assert address.pubkey_hash == @pubkey_hash
    end
  end

  describe "from_string/1" do
    test "decodes valid mainnet address" do
      assert {:ok, address} = Legacy.from_string(@address_str)
      assert %Legacy{} = address
      assert address.pubkey_hash == @pubkey_hash
    end

    test "returns error for invalid checksum" do
      invalid = "18cqNbEBxkAttxcZLuH9LWhZJPd1BNu1A6"
      assert {:error, _} = Legacy.from_string(invalid)
    end

    test "returns error for P2SH address (wrong version byte)" do
      p2sh_address = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
      assert {:error, {:invalid_version_byte, _, :main}} = Legacy.from_string(p2sh_address)
    end
  end

  describe "from_string!/1" do
    test "decodes valid address" do
      address = Legacy.from_string!(@address_str)
      assert %Legacy{} = address
      assert address.pubkey_hash == @pubkey_hash
    end

    test "raises on invalid address" do
      assert_raise Satoxi.Error, fn ->
        Legacy.from_string!("invalid")
      end
    end
  end

  describe "to_string/1" do
    test "encodes address to Base58Check string" do
      address = %Legacy{pubkey_hash: @pubkey_hash}
      assert Legacy.to_string(address) == @address_str
    end
  end

  describe "get_pubkey_hash/1" do
    test "returns the pubkey hash" do
      address = %Legacy{pubkey_hash: @pubkey_hash}
      assert Legacy.get_pubkey_hash(address) == @pubkey_hash
    end
  end

  describe "Encoding protocol" do
    test "to_string/1 encodes via protocol" do
      address = Legacy.from_pubkey(@pubkey_bin)
      assert Encoding.to_string(address) == @address_str
    end

    test "get_hash/1 returns pubkey hash via protocol" do
      address = Legacy.from_pubkey(@pubkey_bin)
      assert Encoding.get_hash(address) == @pubkey_hash
    end
  end

  describe "roundtrip" do
    test "pubkey -> address -> string -> address" do
      address1 = Legacy.from_pubkey(@pubkey_bin)
      string = Legacy.to_string(address1)
      {:ok, address2} = Legacy.from_string(string)
      assert address1 == address2
    end
  end
end
