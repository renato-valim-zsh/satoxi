defmodule Satoxi.Contract.HelpersTest do
  use ExUnit.Case

  alias Satoxi.Contract
  alias Satoxi.Contract.Helpers
  alias Satoxi.Contract.P2PKH
  alias Satoxi.Keys.KeyPair
  alias Satoxi.Keys.PrivKey
  alias Satoxi.Script
  alias Satoxi.Transaction
  alias Satoxi.Transaction.Input
  alias Satoxi.Transaction.Output
  alias Satoxi.Transaction.OutPoint
  alias Satoxi.Transaction.UTXO

  @wif "KyGHAK8MNohVPdeGPYXveiAbTfLARVrQuJVtd3qMqN41UEnTWDkF"
  @keypair KeyPair.from_privkey(PrivKey.from_wif!(@wif))

  @wif2 "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi"
  @keypair2 KeyPair.from_privkey(PrivKey.from_wif!(@wif2))

  describe "each/3" do
    test "iterates over enumerable and applies function" do
      contract = %Contract{script: %Script{chunks: []}}

      result =
        Helpers.each(contract, [:OP_1, :OP_2, :OP_3], fn opcode, c ->
          Helpers.push(c, opcode)
        end)

      assert result.script.chunks == [:OP_1, :OP_2, :OP_3]
    end

    test "works with empty enumerable" do
      contract = %Contract{script: %Script{chunks: [:OP_TRUE]}}

      result =
        Helpers.each(contract, [], fn _el, c ->
          Helpers.push(c, :OP_FALSE)
        end)

      assert result.script.chunks == [:OP_TRUE]
    end

    test "passes element and contract to handler" do
      contract = %Contract{script: %Script{chunks: []}}

      # Push each element twice
      result =
        Helpers.each(contract, ["a", "b"], fn el, c ->
          c
          |> Helpers.push(el)
          |> Helpers.push(el)
        end)

      assert result.script.chunks == ["a", "a", "b", "b"]
    end
  end

  describe "push/2 with single value" do
    test "pushes opcode" do
      contract = %Contract{script: %Script{chunks: []}}

      result = Helpers.push(contract, :OP_DUP)

      assert result.script.chunks == [:OP_DUP]
    end

    test "pushes binary data" do
      contract = %Contract{script: %Script{chunks: []}}

      result = Helpers.push(contract, <<1, 2, 3>>)

      assert result.script.chunks == [<<1, 2, 3>>]
    end

    test "pushes integer" do
      contract = %Contract{script: %Script{chunks: []}}

      # Integers get converted to ScriptNum binary encoding
      result = Helpers.push(contract, 42)

      # Script.push converts integers to binary
      assert length(result.script.chunks) == 1
      assert is_binary(hd(result.script.chunks))
    end

    test "appends to existing chunks" do
      contract = %Contract{script: %Script{chunks: [:OP_1]}}

      result = Helpers.push(contract, :OP_2)

      assert result.script.chunks == [:OP_1, :OP_2]
    end
  end

  describe "push/2 with list" do
    test "pushes multiple values from list" do
      contract = %Contract{script: %Script{chunks: []}}

      result = Helpers.push(contract, [:OP_DUP, :OP_HASH160, :OP_EQUALVERIFY])

      assert result.script.chunks == [:OP_DUP, :OP_HASH160, :OP_EQUALVERIFY]
    end

    test "pushes mixed types from list" do
      contract = %Contract{script: %Script{chunks: []}}

      result = Helpers.push(contract, [:OP_RETURN, <<0xDE, 0xAD>>, :OP_2])

      assert result.script.chunks == [:OP_RETURN, <<0xDE, 0xAD>>, :OP_2]
    end

    test "handles empty list" do
      contract = %Contract{script: %Script{chunks: [:OP_TRUE]}}

      result = Helpers.push(contract, [])

      assert result.script.chunks == [:OP_TRUE]
    end

    test "handles single-element list" do
      contract = %Contract{script: %Script{chunks: []}}

      result = Helpers.push(contract, [:OP_CHECKSIG])

      assert result.script.chunks == [:OP_CHECKSIG]
    end
  end

  describe "sig/2 with single privkey" do
    test "pushes placeholder when no context" do
      utxo = create_test_utxo()

      contract =
        %Contract{
          ctx: nil,
          mfa: {P2PKH, :unlocking_script, [%{keypair: @keypair}]},
          subject: utxo,
          script: %Script{chunks: []}
        }

      result = Helpers.sig(contract, @keypair.privkey)

      # Without context, should push 71 bytes of zeros
      assert [<<0::568>>] = result.script.chunks
    end

    test "pushes real signature when context is present" do
      utxo = create_test_utxo()
      tx = create_test_tx()

      contract =
        %Contract{
          ctx: {tx, 0},
          mfa: {P2PKH, :unlocking_script, [%{keypair: @keypair}]},
          opts: [],
          subject: utxo,
          script: %Script{chunks: []}
        }

      result = Helpers.sig(contract, @keypair.privkey)

      [signature] = result.script.chunks

      # Should be a real DER signature
      assert is_binary(signature)
      assert byte_size(signature) >= 70
      assert byte_size(signature) <= 73
      # Should not be zeros
      refute signature == <<0::568>>
    end

    test "signature ends with sighash byte" do
      utxo = create_test_utxo()
      tx = create_test_tx()

      contract =
        %Contract{
          ctx: {tx, 0},
          mfa: {P2PKH, :unlocking_script, [%{keypair: @keypair}]},
          opts: [],
          subject: utxo,
          script: %Script{chunks: []}
        }

      result = Helpers.sig(contract, @keypair.privkey)

      [signature] = result.script.chunks

      # Default sighash is SIGHASH_ALL (0x01)
      assert binary_part(signature, byte_size(signature) - 1, 1) == <<0x01>>
    end
  end

  describe "sig/2 with list of privkeys" do
    test "pushes placeholder for each key when no context" do
      utxo = create_test_utxo()

      contract =
        %Contract{
          ctx: nil,
          mfa: {P2PKH, :unlocking_script, [%{keypair: @keypair}]},
          subject: utxo,
          script: %Script{chunks: []}
        }

      result = Helpers.sig(contract, [@keypair.privkey, @keypair2.privkey])

      # Should have two placeholder signatures
      assert [<<0::568>>, <<0::568>>] = result.script.chunks
    end

    test "pushes multiple signatures when context is present" do
      utxo = create_test_utxo()
      tx = create_test_tx()

      contract =
        %Contract{
          ctx: {tx, 0},
          mfa: {P2PKH, :unlocking_script, [%{keypair: @keypair}]},
          opts: [],
          subject: utxo,
          script: %Script{chunks: []}
        }

      result = Helpers.sig(contract, [@keypair.privkey, @keypair2.privkey])

      [sig1, sig2] = result.script.chunks

      # Both should be real signatures
      assert is_binary(sig1)
      assert is_binary(sig2)
      assert byte_size(sig1) >= 70
      assert byte_size(sig2) >= 70

      # Signatures should be different (different keys)
      assert sig1 != sig2
    end

    test "handles empty list of privkeys" do
      utxo = create_test_utxo()

      contract =
        %Contract{
          ctx: nil,
          mfa: {P2PKH, :unlocking_script, [%{keypair: @keypair}]},
          subject: utxo,
          script: %Script{chunks: [:OP_0]}
        }

      result = Helpers.sig(contract, [])

      # Should not add anything
      assert result.script.chunks == [:OP_0]
    end

    test "handles single privkey in list" do
      utxo = create_test_utxo()
      tx = create_test_tx()

      contract =
        %Contract{
          ctx: {tx, 0},
          mfa: {P2PKH, :unlocking_script, [%{keypair: @keypair}]},
          opts: [],
          subject: utxo,
          script: %Script{chunks: []}
        }

      result = Helpers.sig(contract, [@keypair.privkey])

      [signature] = result.script.chunks
      assert is_binary(signature)
      assert byte_size(signature) >= 70
    end
  end

  describe "integration with Contract module" do
    test "helpers are imported when using Contract" do
      # P2PKH uses these helpers internally
      utxo = create_test_utxo()
      tx = create_test_tx()

      contract =
        utxo
        |> P2PKH.unlock(%{keypair: @keypair})
        |> Contract.put_ctx({tx, 0})

      script = Contract.to_script(contract)

      # Should have signature and pubkey
      [sig, pubkey] = script.chunks
      assert is_binary(sig)
      assert byte_size(pubkey) == 33
    end
  end

  # Helper to create a test UTXO
  defp create_test_utxo(satoshis \\ 10000) do
    %UTXO{
      outpoint: %OutPoint{
        hash: :binary.copy(<<0xAB>>, 32),
        vout: 0
      },
      output: %Output{
        satoshis: satoshis,
        script: %Script{
          chunks: [
            :OP_DUP,
            :OP_HASH160,
            <<0::160>>,
            :OP_EQUALVERIFY,
            :OP_CHECKSIG
          ]
        }
      }
    }
  end

  # Helper to create a minimal transaction for context
  defp create_test_tx do
    %Transaction{
      version: 1,
      inputs: [
        %Input{
          outpoint: %OutPoint{hash: :binary.copy(<<0>>, 32), vout: 0},
          script: %Script{chunks: []},
          sequence: 0xFFFFFFFF
        }
      ],
      outputs: [
        %Output{satoshis: 5000, script: %Script{chunks: [:OP_TRUE]}}
      ],
      lock_time: 0
    }
  end
end
