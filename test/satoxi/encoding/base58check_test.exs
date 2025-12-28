defmodule Satoxi.Encoding.Base58CheckTest do
  use ExUnit.Case, async: true

  alias Satoxi.Encoding.Base58Check

  # P2PKH mainnet address (version 0x00, starts with "1")
  @p2pkh_pubkey_hash Base.decode16!("62E907B15CBF27D5425399EBF6F0FB50EBB88F18", case: :upper)
  @p2pkh_address "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

  # P2SH mainnet address (version 0x05, starts with "3")
  @p2sh_script_hash Base.decode16!("89ABCDEFABBAABBAABBAABBAABBAABBAABBAABBA", case: :upper)
  @p2sh_address "3EExK1K1TF3v7zsFtQHt14XqexCwgmXM1y"

  # P2PKH testnet address (version 0x6F, starts with "m" or "n")
  @testnet_pubkey_hash Base.decode16!("751E76E8199196D454941C45D1B3A323F1433BD6", case: :upper)
  @testnet_address "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"

  # WIF mainnet private key (version 0x80, starts with "5")
  @wif_private_key Base.decode16!(
                     "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
                     case: :upper
                   )
  @wif_address "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"

  describe "encode/1" do
    test "encodes P2PKH mainnet address" do
      data = <<0x00>> <> @p2pkh_pubkey_hash
      assert {:ok, address} = Base58Check.encode(data)
      assert address == @p2pkh_address
    end

    test "encodes P2SH mainnet address" do
      data = <<0x05>> <> @p2sh_script_hash
      assert {:ok, address} = Base58Check.encode(data)
      assert address == @p2sh_address
    end

    test "encodes P2PKH testnet address" do
      data = <<0x6F>> <> @testnet_pubkey_hash
      assert {:ok, address} = Base58Check.encode(data)
      assert address == @testnet_address
    end

    test "encodes WIF private key" do
      data = <<0x80>> <> @wif_private_key
      assert {:ok, address} = Base58Check.encode(data)
      assert address == @wif_address
    end
  end

  describe "encode!/1" do
    test "encodes P2PKH mainnet address" do
      data = <<0x00>> <> @p2pkh_pubkey_hash
      assert Base58Check.encode!(data) == @p2pkh_address
    end

    test "encodes WIF private key" do
      data = <<0x80>> <> @wif_private_key
      assert Base58Check.encode!(data) == @wif_address
    end
  end

  describe "decode/1" do
    test "decodes P2PKH mainnet address" do
      assert {:ok, decoded} = Base58Check.decode(@p2pkh_address)
      assert decoded == <<0x00>> <> @p2pkh_pubkey_hash
    end

    test "decodes P2SH mainnet address" do
      assert {:ok, decoded} = Base58Check.decode(@p2sh_address)
      assert decoded == <<0x05>> <> @p2sh_script_hash
    end

    test "decodes P2PKH testnet address" do
      assert {:ok, decoded} = Base58Check.decode(@testnet_address)
      assert decoded == <<0x6F>> <> @testnet_pubkey_hash
    end

    test "decodes WIF private key" do
      assert {:ok, decoded} = Base58Check.decode(@wif_address)
      assert decoded == <<0x80>> <> @wif_private_key
    end

    test "returns error for invalid checksum" do
      # Change last character to invalidate checksum
      invalid_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
      assert {:error, _reason} = Base58Check.decode(invalid_address)
    end

    test "returns error for invalid character" do
      # '0' is not in the Base58 alphabet
      invalid_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a"
      assert {:error, _reason} = Base58Check.decode(invalid_address)
    end

    test "returns error for empty string" do
      assert {:error, _reason} = Base58Check.decode("")
    end
  end

  describe "decode!/1" do
    test "decodes valid P2PKH address" do
      assert decoded = Base58Check.decode!(@p2pkh_address)
      assert decoded == <<0x00>> <> @p2pkh_pubkey_hash
    end

    test "decodes valid WIF private key" do
      assert decoded = Base58Check.decode!(@wif_address)
      assert decoded == <<0x80>> <> @wif_private_key
    end

    test "raises on invalid address" do
      assert_raise ArgumentError, ~r/Base58Check decoding failed/, fn ->
        Base58Check.decode!("invalid_address")
      end
    end

    test "raises on invalid checksum" do
      invalid_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"

      assert_raise ArgumentError, ~r/Base58Check decoding failed/, fn ->
        Base58Check.decode!(invalid_address)
      end
    end
  end

  describe "encode_version/2" do
    test "encodes P2PKH mainnet address with version 0x00" do
      assert {:ok, address} = Base58Check.encode_version(@p2pkh_pubkey_hash, 0x00)
      assert address == @p2pkh_address
    end

    test "encodes P2SH mainnet address with version 0x05" do
      assert {:ok, address} = Base58Check.encode_version(@p2sh_script_hash, 0x05)
      assert address == @p2sh_address
    end

    test "encodes P2PKH testnet address with version 0x6F" do
      assert {:ok, address} = Base58Check.encode_version(@testnet_pubkey_hash, 0x6F)
      assert address == @testnet_address
    end

    test "encodes WIF private key with version 0x80" do
      assert {:ok, address} = Base58Check.encode_version(@wif_private_key, 0x80)
      assert address == @wif_address
    end
  end

  describe "encode_version!/2" do
    test "encodes P2PKH mainnet address with version" do
      assert Base58Check.encode_version!(@p2pkh_pubkey_hash, 0x00) == @p2pkh_address
    end

    test "encodes WIF private key with version" do
      assert Base58Check.encode_version!(@wif_private_key, 0x80) == @wif_address
    end
  end

  describe "decode_version/2" do
    test "decodes P2PKH mainnet address with version verification" do
      assert {:ok, pubkey_hash} = Base58Check.decode_version(@p2pkh_address, 0x00)
      assert pubkey_hash == @p2pkh_pubkey_hash
    end

    test "decodes P2SH mainnet address with version verification" do
      assert {:ok, script_hash} = Base58Check.decode_version(@p2sh_address, 0x05)
      assert script_hash == @p2sh_script_hash
    end

    test "decodes P2PKH testnet address with version verification" do
      assert {:ok, pubkey_hash} = Base58Check.decode_version(@testnet_address, 0x6F)
      assert pubkey_hash == @testnet_pubkey_hash
    end

    test "decodes WIF private key with version verification" do
      assert {:ok, private_key} = Base58Check.decode_version(@wif_address, 0x80)
      assert private_key == @wif_private_key
    end

    test "returns error for wrong version" do
      # Try to decode P2PKH address with P2SH version
      assert {:error, _reason} = Base58Check.decode_version(@p2pkh_address, 0x05)
    end

    test "returns error for invalid checksum" do
      invalid_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
      assert {:error, _reason} = Base58Check.decode_version(invalid_address, 0x00)
    end
  end

  describe "decode_version!/2" do
    test "decodes valid P2PKH address with version" do
      assert pubkey_hash = Base58Check.decode_version!(@p2pkh_address, 0x00)
      assert pubkey_hash == @p2pkh_pubkey_hash
    end

    test "decodes valid WIF private key with version" do
      assert private_key = Base58Check.decode_version!(@wif_address, 0x80)
      assert private_key == @wif_private_key
    end

    test "raises on wrong version" do
      assert_raise ArgumentError, ~r/Base58Check decoding failed/, fn ->
        Base58Check.decode_version!(@p2pkh_address, 0x05)
      end
    end

    test "raises on invalid checksum" do
      invalid_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"

      assert_raise ArgumentError, ~r/Base58Check decoding failed/, fn ->
        Base58Check.decode_version!(invalid_address, 0x00)
      end
    end
  end

  describe "round-trip encode/decode" do
    test "P2PKH mainnet round-trip" do
      data = <<0x00>> <> @p2pkh_pubkey_hash
      {:ok, encoded} = Base58Check.encode(data)
      {:ok, decoded} = Base58Check.decode(encoded)

      assert decoded == data
    end

    test "P2SH mainnet round-trip" do
      data = <<0x05>> <> @p2sh_script_hash
      {:ok, encoded} = Base58Check.encode(data)
      {:ok, decoded} = Base58Check.decode(encoded)

      assert decoded == data
    end

    test "WIF private key round-trip" do
      data = <<0x80>> <> @wif_private_key
      {:ok, encoded} = Base58Check.encode(data)
      {:ok, decoded} = Base58Check.decode(encoded)

      assert decoded == data
    end
  end

  describe "round-trip encode_version/decode_version" do
    test "P2PKH mainnet round-trip with version" do
      {:ok, encoded} = Base58Check.encode_version(@p2pkh_pubkey_hash, 0x00)
      {:ok, decoded} = Base58Check.decode_version(encoded, 0x00)

      assert decoded == @p2pkh_pubkey_hash
    end

    test "P2SH mainnet round-trip with version" do
      {:ok, encoded} = Base58Check.encode_version(@p2sh_script_hash, 0x05)
      {:ok, decoded} = Base58Check.decode_version(encoded, 0x05)

      assert decoded == @p2sh_script_hash
    end

    test "WIF private key round-trip with version" do
      {:ok, encoded} = Base58Check.encode_version(@wif_private_key, 0x80)
      {:ok, decoded} = Base58Check.decode_version(encoded, 0x80)

      assert decoded == @wif_private_key
    end
  end
end
