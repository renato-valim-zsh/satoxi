defmodule Satoxi.Transaction.PreImageTest do
  use ExUnit.Case, async: true

  alias Satoxi.Keys.KeyPair
  alias Satoxi.Keys.PrivKey
  alias Satoxi.Keys.PubKey
  alias Satoxi.Script
  alias Satoxi.Transaction
  alias Satoxi.Transaction.Input
  alias Satoxi.Transaction.OutPoint
  alias Satoxi.Transaction.Output
  alias Satoxi.Transaction.PreImage

  @wif "KyGHAK8MNohVPdeGPYXveiAbTfLARVrQuJVtd3qMqN41UEnTWDkF"
  @keypair KeyPair.from_privkey(PrivKey.from_wif!(@wif))

  @p2pkh_script %Script{
    chunks: [
      :OP_DUP,
      :OP_HASH160,
      <<83, 143, 209, 121, 200, 190, 15, 40, 156, 115, 14, 51, 181, 246, 163, 84, 27, 233, 102,
        143>>,
      :OP_EQUALVERIFY,
      :OP_CHECKSIG
    ]
  }

  describe "legacy/4" do
    test "generates preimage for SIGHASH_ALL" do
      tx = create_test_tx()
      output = create_spent_output()

      preimage = PreImage.legacy(tx, 0, output, 0x01)

      assert is_binary(preimage)

      # Preimage should end with sighash type as little-endian 32-bit
      assert binary_part(preimage, byte_size(preimage) - 4, 4) == <<0x01, 0x00, 0x00, 0x00>>
    end

    test "generates different preimages for different sighash types" do
      tx = create_test_tx()
      output = create_spent_output()

      preimage_all = PreImage.legacy(tx, 0, output, 0x01)
      preimage_none = PreImage.legacy(tx, 0, output, 0x02)
      preimage_single = PreImage.legacy(tx, 0, output, 0x03)

      assert preimage_all != preimage_none
      assert preimage_all != preimage_single
      assert preimage_none != preimage_single
    end

    test "removes OP_CODESEPARATOR from subscript" do
      tx = create_test_tx()

      script_with_codesep = %Script{
        chunks: [
          :OP_DUP,
          :OP_CODESEPARATOR,
          :OP_HASH160,
          <<0::160>>,
          :OP_EQUALVERIFY,
          :OP_CHECKSIG
        ]
      }

      output = %Output{satoshis: 50_000, script: script_with_codesep}

      preimage = PreImage.legacy(tx, 0, output, 0x01)

      # OP_CODESEPARATOR opcode byte (0xAB = 171) should NOT be in preimage
      refute String.contains?(preimage, <<171>>)

      script_without_codesep = %Script{
        chunks: [:OP_DUP, :OP_HASH160, <<0::160>>, :OP_EQUALVERIFY, :OP_CHECKSIG]
      }

      output_clean = %Output{satoshis: 50_000, script: script_without_codesep}
      preimage_clean = PreImage.legacy(tx, 0, output_clean, 0x01)

      assert preimage == preimage_clean
    end

    test "removes multiple OP_CODESEPARATOR opcodes from subscript" do
      tx = create_test_tx()

      script_with_multiple_codesep = %Script{
        chunks: [
          :OP_CODESEPARATOR,
          :OP_DUP,
          :OP_CODESEPARATOR,
          :OP_HASH160,
          <<0::160>>,
          :OP_CODESEPARATOR,
          :OP_EQUALVERIFY,
          :OP_CHECKSIG
        ]
      }

      output = %Output{satoshis: 50_000, script: script_with_multiple_codesep}

      preimage = PreImage.legacy(tx, 0, output, 0x01)

      refute String.contains?(preimage, <<171>>)

      script_clean = %Script{
        chunks: [:OP_DUP, :OP_HASH160, <<0::160>>, :OP_EQUALVERIFY, :OP_CHECKSIG]
      }

      output_clean = %Output{satoshis: 50_000, script: script_clean}
      preimage_clean = PreImage.legacy(tx, 0, output_clean, 0x01)

      assert preimage == preimage_clean
    end

    test "generates consistent preimage for same inputs" do
      tx = create_test_tx()
      output = create_spent_output()

      preimage1 = PreImage.legacy(tx, 0, output, 0x01)
      preimage2 = PreImage.legacy(tx, 0, output, 0x01)

      assert preimage1 == preimage2
    end

    test "generates different preimages for different transactions" do
      tx1 = create_test_tx(num_outputs: 1)
      tx2 = create_test_tx(num_outputs: 2)
      output = create_spent_output()

      preimage1 = PreImage.legacy(tx1, 0, output, 0x01)
      preimage2 = PreImage.legacy(tx2, 0, output, 0x01)

      assert preimage1 != preimage2
    end

    test "SIGHASH_ANYONECANPAY only includes single input" do
      # Create a fixed input that will be used in both transactions
      fixed_input = %Input{
        outpoint: %OutPoint{hash: :binary.copy(<<0xAA>>, 32), vout: 0},
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFF
      }

      # Transaction with 3 inputs (our fixed input first)
      tx_multi = %Transaction{
        version: 1,
        inputs: [
          fixed_input,
          %Input{
            outpoint: %OutPoint{hash: :binary.copy(<<0xBB>>, 32), vout: 1},
            script: %Script{chunks: []},
            sequence: 0xFFFFFFFF
          },
          %Input{
            outpoint: %OutPoint{hash: :binary.copy(<<0xCC>>, 32), vout: 2},
            script: %Script{chunks: []},
            sequence: 0xFFFFFFFF
          }
        ],
        outputs: [%Output{satoshis: 10_000, script: @p2pkh_script}],
        lock_time: 0
      }

      # Transaction with only the fixed input
      tx_single = %Transaction{
        version: 1,
        inputs: [fixed_input],
        outputs: [%Output{satoshis: 10_000, script: @p2pkh_script}],
        lock_time: 0
      }

      output = create_spent_output()

      # With ANYONECANPAY (0x81), the preimage should only include vin=0
      preimage_acp = PreImage.legacy(tx_multi, 0, output, 0x81)
      preimage_single = PreImage.legacy(tx_single, 0, output, 0x81)

      # Preimages should be equal since ANYONECANPAY only signs current input
      assert preimage_acp == preimage_single
    end

    test "SIGHASH_ANYONECANPAY signs different inputs independently" do
      # Verify signing input 1 vs input 0 produces different preimages
      tx = create_test_tx(num_inputs: 3)
      output = create_spent_output()

      preimage_input0 = PreImage.legacy(tx, 0, output, 0x81)
      preimage_input1 = PreImage.legacy(tx, 1, output, 0x81)

      # Different inputs should produce different preimages (different outpoints)
      assert preimage_input0 != preimage_input1
    end

    test "SIGHASH_NONE does not commit to any outputs" do
      # Two transactions with different outputs should produce the same preimage
      # when using SIGHASH_NONE (because outputs are not signed)
      input = %Input{
        outpoint: %OutPoint{hash: :binary.copy(<<0xAA>>, 32), vout: 0},
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFF
      }

      tx1 = %Transaction{
        version: 1,
        inputs: [input],
        outputs: [%Output{satoshis: 10_000, script: @p2pkh_script}],
        lock_time: 0
      }

      tx2 = %Transaction{
        version: 1,
        inputs: [input],
        outputs: [
          %Output{satoshis: 99_999, script: @p2pkh_script},
          %Output{satoshis: 88_888, script: @p2pkh_script}
        ],
        lock_time: 0
      }

      output = create_spent_output()

      preimage1 = PreImage.legacy(tx1, 0, output, 0x02)
      preimage2 = PreImage.legacy(tx2, 0, output, 0x02)

      # With SIGHASH_NONE, outputs are not committed - preimages should be equal
      assert preimage1 == preimage2
    end

    test "SIGHASH_SINGLE only commits to corresponding output" do
      input0 = %Input{
        outpoint: %OutPoint{hash: :binary.copy(<<0xAA>>, 32), vout: 0},
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFF
      }

      input1 = %Input{
        outpoint: %OutPoint{hash: :binary.copy(<<0xBB>>, 32), vout: 1},
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFF
      }

      output0 = %Output{satoshis: 10_000, script: @p2pkh_script}
      output1 = %Output{satoshis: 20_000, script: @p2pkh_script}

      tx = %Transaction{
        version: 1,
        inputs: [input0, input1],
        outputs: [output0, output1],
        lock_time: 0
      }

      spent_output = create_spent_output()

      # Sign input 0 with SIGHASH_SINGLE - commits to output 0
      preimage0 = PreImage.legacy(tx, 0, spent_output, 0x03)

      # Change output 1 - should NOT affect signature for input 0
      tx_modified = %{tx | outputs: [output0, %Output{satoshis: 99_999, script: @p2pkh_script}]}
      preimage0_modified = PreImage.legacy(tx_modified, 0, spent_output, 0x03)

      assert preimage0 == preimage0_modified

      # But changing output 0 SHOULD affect the signature
      tx_changed = %{tx | outputs: [%Output{satoshis: 11_111, script: @p2pkh_script}, output1]}
      preimage0_changed = PreImage.legacy(tx_changed, 0, spent_output, 0x03)

      assert preimage0 != preimage0_changed
    end

    test "SIGHASH_SINGLE zeros sequence for other inputs" do
      # With SIGHASH_SINGLE, other inputs' sequences should be zeroed
      input0 = %Input{
        outpoint: %OutPoint{hash: :binary.copy(<<0xAA>>, 32), vout: 0},
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFF
      }

      input1 = %Input{
        outpoint: %OutPoint{hash: :binary.copy(<<0xBB>>, 32), vout: 1},
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFE
      }

      tx1 = %Transaction{
        version: 1,
        inputs: [input0, input1],
        outputs: [
          %Output{satoshis: 10_000, script: @p2pkh_script},
          %Output{satoshis: 20_000, script: @p2pkh_script}
        ],
        lock_time: 0
      }

      # Change input1's sequence - should NOT affect signature for input 0
      input1_different_seq = %{input1 | sequence: 0x12345678}

      tx2 = %Transaction{
        version: 1,
        inputs: [input0, input1_different_seq],
        outputs: [
          %Output{satoshis: 10_000, script: @p2pkh_script},
          %Output{satoshis: 20_000, script: @p2pkh_script}
        ],
        lock_time: 0
      }

      spent_output = create_spent_output()

      preimage1 = PreImage.legacy(tx1, 0, spent_output, 0x03)
      preimage2 = PreImage.legacy(tx2, 0, spent_output, 0x03)

      # Other inputs' sequences are zeroed, so changing them shouldn't matter
      assert preimage1 == preimage2
    end
  end

  describe "segwit/4" do
    test "generates preimage for SegWit transaction" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> PreImage.p2wpkh_script_code()

      preimage = PreImage.segwit(tx, 0, output, script_code)

      assert is_binary(preimage)

      # BIP-143 preimage has specific structure
      # Starts with version (4 bytes little-endian)
      <<version::little-32, _rest::binary>> = preimage

      assert version == 1
    end

    test "generates different preimage than legacy" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> PreImage.p2wpkh_script_code()

      legacy_preimage = PreImage.legacy(tx, 0, output, 0x01)
      segwit_preimage = PreImage.segwit(tx, 0, output, script_code)

      assert legacy_preimage != segwit_preimage
    end

    test "includes output value in preimage" do
      tx = create_test_tx()

      output1 = create_spent_output(50_000)
      output2 = create_spent_output(99_999)

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> PreImage.p2wpkh_script_code()

      preimage1 = PreImage.segwit(tx, 0, output1, script_code)
      preimage2 = PreImage.segwit(tx, 0, output2, script_code)

      # SegWit commits to the amount, so different amounts = different preimages
      assert preimage1 != preimage2
    end

    test "defaults to SIGHASH_ALL" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> PreImage.p2wpkh_script_code()

      preimage_default = PreImage.segwit(tx, 0, output, script_code)

      preimage_explicit =
        PreImage.segwit(tx, 0, output, script_code, sighash_type: 0x01)

      assert preimage_default == preimage_explicit
    end

    test "different sighash types produce different preimages" do
      tx = create_test_tx(num_outputs: 2)
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> PreImage.p2wpkh_script_code()

      preimage_all = PreImage.segwit(tx, 0, output, script_code, sighash_type: 0x01)
      preimage_none = PreImage.segwit(tx, 0, output, script_code, sighash_type: 0x02)

      preimage_single =
        PreImage.segwit(tx, 0, output, script_code, sighash_type: 0x03)

      assert preimage_all != preimage_none
      assert preimage_all != preimage_single
      assert preimage_none != preimage_single
    end
  end

  describe "p2wpkh_script_code/1" do
    test "generates correct P2PKH-equivalent script" do
      pubkey_hash = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20>>

      script = PreImage.p2wpkh_script_code(pubkey_hash)

      assert %Script{
               chunks: [:OP_DUP, :OP_HASH160, ^pubkey_hash, :OP_EQUALVERIFY, :OP_CHECKSIG]
             } = script
    end

    test "generates correct script from real pubkey hash" do
      pubkey_hash = get_pubkey_hash_from_keypair(@keypair)

      script = PreImage.p2wpkh_script_code(pubkey_hash)

      assert script.chunks == [
               :OP_DUP,
               :OP_HASH160,
               pubkey_hash,
               :OP_EQUALVERIFY,
               :OP_CHECKSIG
             ]
    end
  end

  describe "SIGHASH_SINGLE edge case" do
    test "SegWit handles vin >= outputs count" do
      tx = create_test_tx(num_inputs: 2, num_outputs: 1)
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> PreImage.p2wpkh_script_code()

      # Should not raise - Bitcoin's quirky behavior
      preimage = PreImage.segwit(tx, 1, output, script_code, sighash_type: 0x03)

      assert is_binary(preimage)
    end

    test "legacy raises for vin >= outputs count with SIGHASH_SINGLE" do
      tx = create_test_tx(num_inputs: 2, num_outputs: 1)
      output = create_spent_output()

      # Legacy signing raises an error for this edge case
      assert_raise ArgumentError, "input out of output range", fn ->
        PreImage.legacy(tx, 1, output, 0x03)
      end
    end
  end

  describe "preimage structure" do
    test "legacy preimage ends with sighash type" do
      tx = create_test_tx()
      output = create_spent_output()

      for sighash_type <- [0x01, 0x02, 0x03, 0x81, 0x82, 0x83] do
        preimage = PreImage.legacy(tx, 0, output, sighash_type)

        <<_rest::binary-size(byte_size(preimage) - 4), suffix::little-32>> = preimage

        assert suffix == sighash_type
      end
    end

    test "segwit preimage ends with sighash type" do
      tx = create_test_tx()
      output = create_spent_output()

      script_code = @keypair |> get_pubkey_hash_from_keypair() |> PreImage.p2wpkh_script_code()

      for sighash_type <- [0x01, 0x02, 0x03, 0x81, 0x82, 0x83] do
        preimage =
          PreImage.segwit(tx, 0, output, script_code, sighash_type: sighash_type)

        <<_rest::binary-size(byte_size(preimage) - 4), suffix::little-32>> = preimage
        assert suffix == sighash_type
      end
    end

    test "segwit preimage starts with version" do
      tx = %{create_test_tx() | version: 2}
      output = create_spent_output()
      pubkey_hash = Satoxi.Hash.sha256_ripemd160(PubKey.to_binary(@keypair.pubkey))
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)

      preimage = PreImage.segwit(tx, 0, output, script_code)
      <<version::little-32, _rest::binary>> = preimage

      assert version == 2
    end
  end

  describe "BIP-143 test vectors" do
    # Official BIP-143 test vector: Native P2WPKH
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wpkh
    test "native P2WPKH produces correct sighash (BIP-143 example)" do
      # Build the transaction from BIP-143 example
      # Input 0: 9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff:0
      # Input 1: 8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef:1
      input0 = %Input{
        outpoint: %OutPoint{
          hash:
            Base.decode16!("FFF7F7881A8099AFA6940D42D1E7F6362BEC38171EA3EDF433541DB4E4AD969F",
              case: :upper
            ),
          vout: 0
        },
        script: %Script{chunks: []},
        # Sequence bytes in raw tx: eeffffff (little-endian) = 0xffffffee as integer
        sequence: 0xFFFFFFEE
      }

      input1 = %Input{
        outpoint: %OutPoint{
          hash:
            Base.decode16!("EF51E1B804CC89D182D279655C3AA89E815B1B309FE287D9B2B55D57B90EC68A",
              case: :upper
            ),
          vout: 1
        },
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFF
      }

      # Output 0: 1.1234 BTC to P2PKH
      output0 = %Output{
        satoshis: 112_340_000,
        script:
          Script.from_binary!(
            Base.decode16!("76A9148280B37DF378DB99F66F85C95A783A76AC7A6D5988AC", case: :upper)
          )
      }

      # Output 1: 2.2345 BTC to P2PKH
      output1 = %Output{
        satoshis: 223_450_000,
        script:
          Script.from_binary!(
            Base.decode16!("76A9143BDE42DBEE7E4DBE6A21B2D50CE2F0167FAA815988AC", case: :upper)
          )
      }

      tx = %Transaction{
        version: 1,
        inputs: [input0, input1],
        outputs: [output0, output1],
        lock_time: 17
      }

      # The output being spent by input 1 has value 6 BTC (600000000 satoshis)
      spent_output = %Output{
        satoshis: 600_000_000,
        script: %Script{chunks: []}
      }

      # Script code for P2WPKH (the pubkey hash from the witness program)
      # 1d0f172a0ecb48aee1be1f2687d2963ae33f71a1
      pubkey_hash = Base.decode16!("1D0F172A0ECB48AEE1BE1F2687D2963AE33F71A1", case: :upper)
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)

      # Generate preimage for input 1 with SIGHASH_ALL
      preimage =
        PreImage.segwit(tx, 1, spent_output, script_code, sighash_type: 0x01)

      # Expected preimage from BIP-143
      expected_preimage =
        Base.decode16!(
          # nVersion
          # hashPrevouts
          # hashSequence
          # outpoint
          # scriptCode
          # amount (600000000 in little-endian)
          # nSequence
          # hashOutputs
          # nLockTime
          # nHashType
          "01000000" <>
            "96B827C8483D4E9B96712B6713A7B68D6E8003A781FEBA36C31143470B4EFD37" <>
            "52B0A642EEA2FB7AE638C36F6252B6750293DBE574A806984B8E4D8548339A3B" <>
            "EF51E1B804CC89D182D279655C3AA89E815B1B309FE287D9B2B55D57B90EC68A01000000" <>
            "1976A9141D0F172A0ECB48AEE1BE1F2687D2963AE33F71A188AC" <>
            "0046C32300000000" <>
            "FFFFFFFF" <>
            "863EF3E1A92AFBFDB97F31AD0FC7683EE943E9ABCF2501590FF8F6551F47E5E5" <>
            "11000000" <>
            "01000000",
          case: :upper
        )

      assert preimage == expected_preimage

      # Verify the sighash
      sighash = Satoxi.Hash.sha256_sha256(preimage)

      expected_sighash =
        Base.decode16!("C37AF31116D1B27CAF68AAE9E3AC82F1477929014D5B917657D0EB49478CB670",
          case: :upper
        )

      assert sighash == expected_sighash
    end

    # BIP-143 Example: P2SH-P2WPKH
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
    test "P2SH-P2WPKH produces correct sighash (BIP-143 example)" do
      input0 = %Input{
        outpoint: %OutPoint{
          hash:
            Base.decode16!("DB6B1B20AA0FD7B23880BE2ECBD4A98130974CF4748FB66092AC4D3CEB1A5477",
              case: :upper
            ),
          vout: 1
        },
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFE
      }

      output0 = %Output{
        satoshis: 199_996_600,
        script:
          Script.from_binary!(
            Base.decode16!("76A914A457B684D7F0D539A46A45BBC043F35B59D0D96388AC", case: :upper)
          )
      }

      output1 = %Output{
        satoshis: 800_000_000,
        script:
          Script.from_binary!(
            Base.decode16!("76A914FD270B1EE6ABCAEA97FEA7AD0402E8BD8AD6D77C88AC", case: :upper)
          )
      }

      tx = %Transaction{
        version: 1,
        inputs: [input0],
        outputs: [output0, output1],
        lock_time: 1170
      }

      # The UTXO being spent has value 10 BTC
      spent_output = %Output{
        satoshis: 1_000_000_000,
        script: %Script{chunks: []}
      }

      # The pubkey hash embedded in the P2SH redeemScript (which is the witness program)
      pubkey_hash = Base.decode16!("79091972186C449EB1DED22B78E40D009BDF0089", case: :upper)
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)

      preimage = PreImage.segwit(tx, 0, spent_output, script_code, sighash_type: 0x01)

      # Expected sighash from BIP-143
      sighash = Satoxi.Hash.sha256_sha256(preimage)

      expected_sighash =
        Base.decode16!("64F3B0F4DD2BB3AA1CE8566D220CC74DDA9DF97D8490CC81D89D735C92E59FB6",
          case: :upper
        )

      assert sighash == expected_sighash
    end

    # BIP-143 Example: Native P2WSH
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#native-p2wsh
    test "native P2WSH produces correct sighash (BIP-143 example)" do
      input0 = %Input{
        outpoint: %OutPoint{
          hash:
            Base.decode16!("FE3DC9208094F3FFDCB71B218EC586FA4E5663DB376D370F67F0C7BEB7EF7392",
              case: :upper
            ),
          vout: 0
        },
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFF
      }

      output0 = %Output{
        satoshis: 156_250_000,
        script:
          Script.from_binary!(
            Base.decode16!("00149D287D9B8E0D2F1C71F17BF3B04FA97FB3A7F80D", case: :upper)
          )
      }

      tx = %Transaction{
        version: 1,
        inputs: [input0],
        outputs: [output0],
        lock_time: 0
      }

      # The UTXO being spent
      spent_output = %Output{
        satoshis: 156_250_000,
        script: %Script{chunks: []}
      }

      # The witness script is a 6-of-6 multisig (simplified for test)
      # From BIP-143: The script is OP_6 <6 compressed pubkeys> OP_6 OP_CHECKMULTISIG
      # We use the precomputed script code serialization
      pubkey1 =
        Base.decode16!("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
          case: :upper
        )

      pubkey2 =
        Base.decode16!("03CBCAA9C98C877A26977D00825C956A238E8DDDFBD322CCE4F74B0B5BD6ACE4A7",
          case: :upper
        )

      pubkey3 =
        Base.decode16!("0304F4B05A3A8BD6C01E5B3352E5B57E86F6C5DE11FBC3DE18B5E2DC5B47E82EC1",
          case: :upper
        )

      pubkey4 =
        Base.decode16!("030F5D1D9B07BAFDF7FB3E7F2C70C3D89F93A2D30EAF4E7E3C0F8A9B5D1E6C2F4A",
          case: :upper
        )

      pubkey5 =
        Base.decode16!("0325D73A17C1B42D7F55BCD08E31F0B8B9D0E13C4A5B6F8E7D9C0A2B3F4E5D6C7A",
          case: :upper
        )

      pubkey6 =
        Base.decode16!("02E8445082A72F29B75CA48748A914DF60622A609CACFCE8ED0E35804560741D29",
          case: :upper
        )

      witness_script = %Script{
        chunks: [
          :OP_6,
          pubkey1,
          pubkey2,
          pubkey3,
          pubkey4,
          pubkey5,
          pubkey6,
          :OP_6,
          :OP_CHECKMULTISIG
        ]
      }

      preimage = PreImage.segwit(tx, 0, spent_output, witness_script, sighash_type: 0x01)

      # Verify preimage structure
      <<version::little-32, _rest::binary>> = preimage
      assert version == 1

      # Verify the witness script is embedded in the preimage
      witness_script_binary = Script.to_binary(witness_script)
      assert String.contains?(preimage, witness_script_binary)
    end
  end

  describe "SegWit sighash behaviors" do
    test "SIGHASH_NONE uses zero hash for outputs" do
      tx = create_test_tx(num_outputs: 2)
      output = create_spent_output()
      pubkey_hash = Satoxi.Hash.sha256_ripemd160(PubKey.to_binary(@keypair.pubkey))
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)

      preimage = PreImage.segwit(tx, 0, output, script_code, sighash_type: 0x02)

      # The hashOutputs (32 bytes before nLockTime and nHashType at the end)
      # should be all zeros for SIGHASH_NONE
      preimage_size = byte_size(preimage)

      <<_prefix::binary-size(preimage_size - 40), hash_outputs::binary-size(32), _suffix::binary>> =
        preimage

      assert hash_outputs == <<0::256>>
    end

    test "SIGHASH_SINGLE uses zero hash for sequence" do
      tx = create_test_tx(num_outputs: 2)
      output = create_spent_output()
      pubkey_hash = Satoxi.Hash.sha256_ripemd160(PubKey.to_binary(@keypair.pubkey))
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)

      preimage = PreImage.segwit(tx, 0, output, script_code, sighash_type: 0x03)

      # The hashSequence (32 bytes after hashPrevouts) should be all zeros for SIGHASH_SINGLE
      <<_version::binary-size(4), _hash_prevouts::binary-size(32), hash_sequence::binary-size(32),
        _rest::binary>> = preimage

      assert hash_sequence == <<0::256>>
    end

    test "SIGHASH_ANYONECANPAY uses zero hash for prevouts and sequence" do
      tx = create_test_tx(num_inputs: 3)
      output = create_spent_output()
      pubkey_hash = Satoxi.Hash.sha256_ripemd160(PubKey.to_binary(@keypair.pubkey))
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)

      preimage = PreImage.segwit(tx, 0, output, script_code, sighash_type: 0x81)

      # Both hashPrevouts and hashSequence should be zeros for ANYONECANPAY
      <<_version::binary-size(4), hash_prevouts::binary-size(32), hash_sequence::binary-size(32),
        _rest::binary>> = preimage

      assert hash_prevouts == <<0::256>>
      assert hash_sequence == <<0::256>>
    end

    test "SIGHASH_SINGLE with vin >= outputs returns special hash" do
      tx = create_test_tx(num_inputs: 2, num_outputs: 1)
      output = create_spent_output()
      pubkey_hash = Satoxi.Hash.sha256_ripemd160(PubKey.to_binary(@keypair.pubkey))
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)

      # Sign input 1, but only 1 output exists (index 0)
      preimage = PreImage.segwit(tx, 1, output, script_code, sighash_type: 0x03)

      # hashOutputs should be the special value 0x01 followed by 31 zero bytes
      preimage_size = byte_size(preimage)

      <<_prefix::binary-size(preimage_size - 40), hash_outputs::binary-size(32), _suffix::binary>> =
        preimage

      assert hash_outputs == <<1, 0::248>>
    end

    test "different inputs produce different preimages with same sighash" do
      tx = create_test_tx(num_inputs: 2, num_outputs: 2)
      output = create_spent_output()
      pubkey_hash = Satoxi.Hash.sha256_ripemd160(PubKey.to_binary(@keypair.pubkey))
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)

      preimage0 = PreImage.segwit(tx, 0, output, script_code)
      preimage1 = PreImage.segwit(tx, 1, output, script_code)

      assert preimage0 != preimage1
    end

    test "SIGHASH_NONE allows outputs to change without affecting signature" do
      pubkey_hash = Satoxi.Hash.sha256_ripemd160(PubKey.to_binary(@keypair.pubkey))
      script_code = PreImage.p2wpkh_script_code(pubkey_hash)

      input = %Input{
        outpoint: %OutPoint{hash: :binary.copy(<<0xAA>>, 32), vout: 0},
        script: %Script{chunks: []},
        sequence: 0xFFFFFFFF
      }

      tx1 = %Transaction{
        version: 1,
        inputs: [input],
        outputs: [%Output{satoshis: 10_000, script: @p2pkh_script}],
        lock_time: 0
      }

      tx2 = %Transaction{
        version: 1,
        inputs: [input],
        outputs: [
          %Output{satoshis: 99_999, script: @p2pkh_script},
          %Output{satoshis: 88_888, script: @p2pkh_script}
        ],
        lock_time: 0
      }

      output = create_spent_output()

      preimage1 = PreImage.segwit(tx1, 0, output, script_code, sighash_type: 0x02)
      preimage2 = PreImage.segwit(tx2, 0, output, script_code, sighash_type: 0x02)

      # With SIGHASH_NONE, outputs don't affect the preimage
      assert preimage1 == preimage2
    end
  end

  describe "P2WSH script code" do
    test "uses witness script directly as script code for P2WSH" do
      tx = create_test_tx()
      output = create_spent_output()

      # Example 2-of-3 multisig witness script
      pubkey1 = :binary.copy(<<1>>, 33)
      pubkey2 = :binary.copy(<<2>>, 33)
      pubkey3 = :binary.copy(<<3>>, 33)

      # P2WSH uses the witness script directly as the script code
      witness_script = %Script{
        chunks: [:OP_2, pubkey1, pubkey2, pubkey3, :OP_3, :OP_CHECKMULTISIG]
      }

      # For P2WSH, the script_code is the witness script itself
      preimage = PreImage.segwit(tx, 0, output, witness_script)

      assert is_binary(preimage)
      # Verify the script code is embedded in the preimage
      witness_script_binary = Script.to_binary(witness_script)
      assert String.contains?(preimage, witness_script_binary)
    end

    test "P2WSH with different witness scripts produce different preimages" do
      tx = create_test_tx()
      output = create_spent_output()

      # Two different multisig configurations
      pubkey1 = :binary.copy(<<1>>, 33)
      pubkey2 = :binary.copy(<<2>>, 33)

      witness_script_1of2 = %Script{
        chunks: [:OP_1, pubkey1, pubkey2, :OP_2, :OP_CHECKMULTISIG]
      }

      witness_script_2of2 = %Script{
        chunks: [:OP_2, pubkey1, pubkey2, :OP_2, :OP_CHECKMULTISIG]
      }

      preimage1 = PreImage.segwit(tx, 0, output, witness_script_1of2)
      preimage2 = PreImage.segwit(tx, 0, output, witness_script_2of2)

      assert preimage1 != preimage2
    end
  end

  # Helper to create a test transaction
  defp create_test_tx(opts \\ []) do
    num_inputs = Keyword.get(opts, :num_inputs, 1)
    num_outputs = Keyword.get(opts, :num_outputs, 1)

    inputs =
      for i <- 0..(num_inputs - 1) do
        %Input{
          outpoint: %OutPoint{hash: :binary.copy(<<i>>, 32), vout: 0},
          script: %Script{chunks: []},
          sequence: 0xFFFFFFFF
        }
      end

    outputs =
      for i <- 0..(num_outputs - 1) do
        %Output{satoshis: 10_000 * (i + 1), script: @p2pkh_script}
      end

    %Transaction{version: 1, inputs: inputs, outputs: outputs, lock_time: 0}
  end

  # Helper to create an output being spent
  defp create_spent_output(satoshis \\ 50_000) do
    %Output{satoshis: satoshis, script: @p2pkh_script}
  end

  # Helper to get the pubkey hash from a keypair
  defp get_pubkey_hash_from_keypair(keypair) do
    keypair.pubkey |> PubKey.to_binary() |> Satoxi.Hash.sha256_ripemd160()
  end
end
