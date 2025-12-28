defmodule Satoxi.Encoding.Bech32Test do
  use ExUnit.Case, async: true

  alias Satoxi.Encoding.Bech32

  # BIP-173 (SegWit v0 - Bech32)
  # P2WPKH (20-byte witness program)
  @p2wpkh_program Base.decode16!("751E76E8199196D454941C45D1B3A323F1433BD6", case: :upper)
  @p2wpkh_address "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

  # P2WSH (32-byte witness program)
  @p2wsh_program Base.decode16!(
                   "1863143C14C5166804BD19203356DA136C985678CD4D27A1B8C6329604903262",
                   case: :upper
                 )
  @p2wsh_testnet_address "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"

  # BIP-350 (SegWit v1 - Bech32m / Taproot)
  @taproot_program Base.decode16!(
                     "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                     case: :upper
                   )
  @taproot_address "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"

  @taproot_testnet_program Base.decode16!(
                             "000000C4A5CAD46221B2A187905E5266362B99D5E91C6CE24D165DAB93E86433",
                             case: :upper
                           )
  @taproot_testnet_address "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c"

  describe "encode/2 and encode_m/2" do
    test "encodes P2WPKH mainnet address (v0)" do
      assert {:ok, address} = Bech32.encode("bc", @p2wpkh_program)
      assert address == @p2wpkh_address
    end

    test "encodes P2WSH testnet address (v0)" do
      assert {:ok, address} = Bech32.encode("tb", @p2wsh_program)
      assert address == @p2wsh_testnet_address
    end

    test "encodes Taproot mainnet address (v1)" do
      assert {:ok, address} = Bech32.encode_m("bc", @taproot_program)
      assert address == @taproot_address
    end

    test "encodes Taproot testnet address (v1)" do
      assert {:ok, address} = Bech32.encode_m("tb", @taproot_testnet_program)
      assert address == @taproot_testnet_address
    end
  end

  describe "encode!/2 and encode_m!/2" do
    test "encodes P2WPKH mainnet address" do
      assert Bech32.encode!("bc", @p2wpkh_program) == @p2wpkh_address
    end

    test "encodes Taproot mainnet address" do
      assert Bech32.encode_m!("bc", @taproot_program) == @taproot_address
    end
  end

  describe "decode/1" do
    test "decodes P2WPKH mainnet address" do
      assert {:ok, {"bc", 0, program}} = Bech32.decode(@p2wpkh_address)
      assert program == @p2wpkh_program
    end

    test "decodes P2WSH testnet address" do
      assert {:ok, {"tb", 0, program}} = Bech32.decode(@p2wsh_testnet_address)
      assert program == @p2wsh_program
    end

    test "decodes Taproot mainnet address" do
      assert {:ok, {"bc", 1, program}} = Bech32.decode(@taproot_address)
      assert program == @taproot_program
    end

    test "decodes Taproot testnet address" do
      assert {:ok, {"tb", 1, program}} = Bech32.decode(@taproot_testnet_address)
      assert program == @taproot_testnet_program
    end

    test "returns error for invalid checksum" do
      invalid_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"

      assert {:error, _reason} = Bech32.decode(invalid_address)
    end

    test "returns error for invalid character" do
      # 'b' is not in the bech32 alphabet
      invalid_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kb8f3t4"
      assert {:error, _reason} = Bech32.decode(invalid_address)
    end

    test "returns error for empty string" do
      assert {:error, _reason} = Bech32.decode("")
    end
  end

  describe "decode!/1" do
    test "decodes valid P2WPKH address" do
      assert {"bc", 0, program} = Bech32.decode!(@p2wpkh_address)
      assert program == @p2wpkh_program
    end

    test "decodes valid Taproot address" do
      assert {"bc", 1, program} = Bech32.decode!(@taproot_address)
      assert program == @taproot_program
    end

    test "raises on invalid address" do
      assert_raise ArgumentError, ~r/Bech32 decoding failed/, fn ->
        Bech32.decode!("invalid_address")
      end
    end

    test "raises on invalid checksum" do
      invalid_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"

      assert_raise ArgumentError, ~r/Bech32 decoding failed/, fn ->
        Bech32.decode!(invalid_address)
      end
    end
  end

  describe "round-trip encode/decode" do
    test "P2WPKH mainnet round-trip" do
      {:ok, encoded} = Bech32.encode("bc", @p2wpkh_program)
      {:ok, {hrp, version, program}} = Bech32.decode(encoded)

      assert hrp == "bc"
      assert version == 0
      assert program == @p2wpkh_program
    end

    test "P2WSH testnet round-trip" do
      {:ok, encoded} = Bech32.encode("tb", @p2wsh_program)
      {:ok, {hrp, version, program}} = Bech32.decode(encoded)

      assert hrp == "tb"
      assert version == 0
      assert program == @p2wsh_program
    end

    test "Taproot mainnet round-trip" do
      {:ok, encoded} = Bech32.encode_m("bc", @taproot_program)
      {:ok, {hrp, version, program}} = Bech32.decode(encoded)

      assert hrp == "bc"
      assert version == 1
      assert program == @taproot_program
    end
  end

  describe "case insensitivity" do
    test "decodes uppercase address" do
      uppercase = String.upcase(@p2wpkh_address)
      # HRP is returned in the case it was provided
      assert {:ok, {"BC", 0, program}} = Bech32.decode(uppercase)
      assert program == @p2wpkh_program
    end

    test "decodes lowercase address" do
      assert {:ok, {"bc", 0, program}} = Bech32.decode(@p2wpkh_address)
      assert program == @p2wpkh_program
    end
  end
end
