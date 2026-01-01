defmodule Satoxi.Address.NestedTest do
  use ExUnit.Case, async: true

  alias Satoxi.Address.Encoding
  alias Satoxi.Address.Nested
  alias Satoxi.Hash
  alias Satoxi.Keys.PubKey

  @pubkey_bin <<3, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232, 175, 144,
                63, 199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57>>
  @pubkey_hash <<83, 143, 209, 121, 200, 190, 15, 40, 156, 115, 14, 51, 181, 246, 163, 84, 27,
                 233, 102, 143>>

  doctest Nested

  describe "from_pubkey/1" do
    test "creates Nested SegWit address from compressed pubkey binary" do
      address = Nested.from_pubkey(@pubkey_bin)
      assert %Nested{} = address
      assert address.pubkey_hash == @pubkey_hash
      assert byte_size(address.script_hash) == 20
    end

    test "creates address from uncompressed pubkey binary" do
      uncompressed =
        <<4, 248, 31, 140, 139, 144, 245, 236, 6, 238, 66, 69, 234, 177, 102, 232, 175, 144, 63,
          199, 58, 109, 215, 54, 54, 104, 126, 240, 39, 135, 10, 190, 57, 1, 135, 135, 125, 5,
          134, 136, 158, 82, 54, 184, 224, 42, 2, 75, 140, 90, 22, 8, 122, 233, 116, 221, 100, 93,
          180, 96, 132, 105, 242, 152, 151>>

      address = Nested.from_pubkey(uncompressed)
      assert %Nested{} = address
      assert byte_size(address.pubkey_hash) == 20
      assert byte_size(address.script_hash) == 20
    end

    test "creates address from PubKey struct" do
      {:ok, pubkey} = PubKey.from_binary(@pubkey_bin)
      address = Nested.from_pubkey(pubkey)
      assert %Nested{} = address
      assert address.pubkey_hash == @pubkey_hash
    end
  end

  describe "from_pubkey_hash/1" do
    test "creates Nested address from 20-byte hash" do
      address = Nested.from_pubkey_hash(@pubkey_hash)
      assert %Nested{} = address
      assert address.pubkey_hash == @pubkey_hash
      assert byte_size(address.script_hash) == 20
    end

    test "script_hash is derived from redeem script" do
      address = Nested.from_pubkey_hash(@pubkey_hash)
      # Redeem script: OP_0 (0x00) + PUSH_20 (0x14) + pubkey_hash
      expected_redeem_script = <<0x00, 0x14>> <> @pubkey_hash
      expected_script_hash = Hash.sha256_ripemd160(expected_redeem_script)
      assert address.script_hash == expected_script_hash
    end
  end

  describe "to_string/1" do
    test "encodes address to Base58Check string starting with 3" do
      address = Nested.from_pubkey(@pubkey_bin)
      string = Nested.to_string(address)
      assert String.starts_with?(string, "3")
    end

    test "produces consistent output" do
      address = Nested.from_pubkey(@pubkey_bin)
      assert Nested.to_string(address) == "3CzveZV418mVv88DVvFikrapHSV2QaY7pt"
    end
  end

  describe "get_script_hash/1" do
    test "returns the script hash" do
      address = Nested.from_pubkey_hash(@pubkey_hash)
      hash = Nested.get_script_hash(address)
      assert byte_size(hash) == 20
      assert hash == address.script_hash
    end
  end

  describe "get_pubkey_hash/1" do
    test "returns the underlying pubkey hash" do
      address = Nested.from_pubkey_hash(@pubkey_hash)
      assert Nested.get_pubkey_hash(address) == @pubkey_hash
    end
  end

  describe "get_redeem_script/1" do
    test "returns the witness program redeem script" do
      address = Nested.from_pubkey_hash(@pubkey_hash)
      redeem_script = Nested.get_redeem_script(address)

      # Should be: OP_0 + PUSH_20 + pubkey_hash
      assert redeem_script == <<0x00, 0x14>> <> @pubkey_hash
      assert byte_size(redeem_script) == 22
    end

    test "redeem script hashes to script_hash" do
      address = Nested.from_pubkey_hash(@pubkey_hash)
      redeem_script = Nested.get_redeem_script(address)
      computed_hash = Hash.sha256_ripemd160(redeem_script)
      assert computed_hash == address.script_hash
    end
  end

  describe "Encoding protocol" do
    test "to_string/1 encodes via protocol" do
      address = Nested.from_pubkey(@pubkey_bin)
      expected = Nested.to_string(address)
      assert Encoding.to_string(address) == expected
    end

    test "get_hash/1 returns script hash via protocol" do
      address = Nested.from_pubkey(@pubkey_bin)
      assert Encoding.get_hash(address) == address.script_hash
    end
  end

  describe "comparison with native SegWit" do
    test "nested and native segwit have same pubkey_hash" do
      nested = Nested.from_pubkey(@pubkey_bin)
      segwit = Satoxi.Address.SegWit.from_pubkey(@pubkey_bin)

      assert nested.pubkey_hash == segwit.witness_program
    end

    test "nested produces P2SH address while native produces bech32" do
      nested = Nested.from_pubkey(@pubkey_bin)
      segwit = Satoxi.Address.SegWit.from_pubkey(@pubkey_bin)

      nested_str = Nested.to_string(nested)
      segwit_str = Satoxi.Address.SegWit.to_string(segwit)

      assert String.starts_with?(nested_str, "3")
      assert String.starts_with?(segwit_str, "bc1q")
    end
  end
end
