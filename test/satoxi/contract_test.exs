defmodule Satoxi.ContractTest do
  use ExUnit.Case

  alias Satoxi.Address
  alias Satoxi.Contract
  alias Satoxi.Contract.P2PKH
  alias Satoxi.Contract.P2SH_P2WPKH
  alias Satoxi.Contract.P2WPKH
  alias Satoxi.Keys.KeyPair
  alias Satoxi.Keys.PrivKey
  alias Satoxi.Script
  alias Satoxi.Transaction
  alias Satoxi.Transaction.Input
  alias Satoxi.Transaction.Output
  alias Satoxi.Transaction.OutPoint
  alias Satoxi.Transaction.UTXO
  alias Satoxi.Transaction.Witness

  @wif "KyGHAK8MNohVPdeGPYXveiAbTfLARVrQuJVtd3qMqN41UEnTWDkF"
  @keypair KeyPair.from_privkey(PrivKey.from_wif!(@wif))

  describe "put_ctx/2" do
    test "attaches transaction context to contract" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})
      tx = create_test_tx()

      updated = Contract.put_ctx(contract, {tx, 0})

      assert updated.ctx == {tx, 0}
    end

    test "allows different vin indices" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})
      tx = create_test_tx()

      updated = Contract.put_ctx(contract, {tx, 5})

      assert updated.ctx == {tx, 5}
    end
  end

  describe "script_push/2" do
    test "pushes opcode to script" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      updated = Contract.script_push(contract, :OP_DUP)

      assert :OP_DUP in updated.script.chunks
    end

    test "pushes binary data to script" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      data = <<1, 2, 3, 4, 5>>
      updated = Contract.script_push(contract, data)

      assert data in updated.script.chunks
    end

    test "pushes integer to script" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      # Script.push converts integers to binary (ScriptNum encoding)
      updated = Contract.script_push(contract, 42)

      # The integer is converted to a binary
      assert length(updated.script.chunks) > 0

      # Find the pushed binary (the last chunk since we pushed it)
      assert is_binary(List.last(updated.script.chunks))
    end
  end

  describe "script_size/1" do
    test "returns size of locking script" do
      address = Address.from_pubkey(@keypair.pubkey)
      contract = P2PKH.lock(1000, %{address: address})

      size = Contract.script_size(contract)

      # P2PKH script: OP_DUP (1) + OP_HASH160 (1) + push20 (1) + hash (20) + OP_EQUALVERIFY (1) + OP_CHECKSIG (1) = 25
      assert size == 25
    end

    test "returns size of P2WPKH locking script" do
      address = Address.from_pubkey(@keypair.pubkey, type: :p2wpkh)
      contract = P2WPKH.lock(1000, %{address: address})

      size = Contract.script_size(contract)

      # P2WPKH script: OP_0 (1) + push20 (1) + witness_program (20) = 22
      assert size == 22
    end
  end

  describe "to_script/1" do
    test "compiles P2PKH locking contract to script" do
      address = Address.from_pubkey(@keypair.pubkey)
      contract = P2PKH.lock(1000, %{address: address})

      script = Contract.to_script(contract)

      assert %Script{} = script
      assert [:OP_DUP, :OP_HASH160, _, :OP_EQUALVERIFY, :OP_CHECKSIG] = script.chunks
    end

    test "compiles P2PKH unlocking contract to script" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      script = Contract.to_script(contract)

      assert %Script{} = script

      # Without context, signature is zeros
      assert [<<0::568>>, pubkey] = script.chunks
      assert byte_size(pubkey) == 33
    end

    test "compiles P2WPKH locking contract to script" do
      address = Address.from_pubkey(@keypair.pubkey, type: :p2wpkh)
      contract = P2WPKH.lock(1000, %{address: address})

      script = Contract.to_script(contract)

      assert %Script{} = script
      assert [:OP_0, witness_program] = script.chunks
      assert byte_size(witness_program) == 20
    end

    test "P2WPKH unlocking script is empty" do
      utxo = create_test_utxo()
      contract = P2WPKH.unlock(utxo, %{keypair: @keypair})

      script = Contract.to_script(contract)

      assert %Script{chunks: []} = script
    end
  end

  describe "to_input/1" do
    test "generates Input struct from unlocking contract" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      input = Contract.to_input(contract)

      assert %Input{} = input
      assert input.outpoint == utxo.outpoint
      assert input.sequence == 0xFFFFFFFF
    end

    test "includes script in Input" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      input = Contract.to_input(contract)

      assert %Script{} = input.script
      assert length(input.script.chunks) == 2
    end

    test "respects custom sequence from opts" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair}, sequence: 0xFFFFFFFE)

      input = Contract.to_input(contract)

      assert input.sequence == 0xFFFFFFFE
    end

    test "includes witness for SegWit contracts" do
      utxo = create_test_utxo()
      contract = P2WPKH.unlock(utxo, %{keypair: @keypair})

      input = Contract.to_input(contract)

      assert %Witness{} = input.witness

      # Without context, placeholder witness
      assert Witness.has_items?(input.witness)
    end

    test "P2PKH has empty witness" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      input = Contract.to_input(contract)

      refute Witness.has_items?(input.witness)
    end
  end

  describe "to_output/1" do
    test "generates Output struct from locking contract" do
      address = Address.from_pubkey(@keypair.pubkey)
      contract = P2PKH.lock(5000, %{address: address})

      output = Contract.to_output(contract)

      assert %Output{} = output
      assert output.satoshis == 5000
    end

    test "includes correct script in Output" do
      address = Address.from_pubkey(@keypair.pubkey)
      contract = P2PKH.lock(5000, %{address: address})

      output = Contract.to_output(contract)

      assert %Script{} = output.script
      assert [:OP_DUP, :OP_HASH160, _, :OP_EQUALVERIFY, :OP_CHECKSIG] = output.script.chunks
    end

    test "P2WPKH output has correct script" do
      address = Address.from_pubkey(@keypair.pubkey, type: :p2wpkh)
      contract = P2WPKH.lock(5000, %{address: address})

      output = Contract.to_output(contract)

      assert output.satoshis == 5000
      assert [:OP_0, _program] = output.script.chunks
    end
  end

  describe "to_witness/1" do
    test "returns empty list for non-SegWit contracts" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      witness = Contract.to_witness(contract)

      assert witness == []
    end

    test "returns witness items for SegWit contracts" do
      utxo = create_test_utxo()
      contract = P2WPKH.unlock(utxo, %{keypair: @keypair})

      witness = Contract.to_witness(contract)

      # P2WPKH: [signature, pubkey]
      assert length(witness) == 2
      [sig, pubkey] = witness
      assert is_binary(sig)
      assert byte_size(pubkey) == 33
    end

    test "returns real signature when context is provided" do
      utxo = create_test_utxo()
      tx = create_test_tx()

      contract =
        utxo
        |> P2WPKH.unlock(%{keypair: @keypair})
        |> Contract.put_ctx({tx, 0})

      witness = Contract.to_witness(contract)

      [sig, _pubkey] = witness

      # Real signature, not placeholder zeros
      refute sig == <<0::568>>
    end
  end

  describe "is_segwit?/1" do
    test "returns false for P2PKH contracts" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      refute Contract.is_segwit?(contract)
    end

    test "returns true for P2WPKH contracts" do
      utxo = create_test_utxo()
      contract = P2WPKH.unlock(utxo, %{keypair: @keypair})

      assert Contract.is_segwit?(contract)
    end

    test "returns false for P2PKH locking contracts" do
      address = Address.from_pubkey(@keypair.pubkey)
      contract = P2PKH.lock(1000, %{address: address})

      refute Contract.is_segwit?(contract)
    end

    test "returns true for P2WPKH locking contracts" do
      address = Address.from_pubkey(@keypair.pubkey, type: :p2wpkh)
      contract = P2WPKH.lock(1000, %{address: address})

      assert Contract.is_segwit?(contract)
    end
  end

  describe "convenience functions" do
    test "lock_p2pkh/3 delegates to P2PKH.lock/3" do
      address = Address.from_pubkey(@keypair.pubkey)

      contract1 = Contract.lock_p2pkh(1000, %{address: address})
      contract2 = P2PKH.lock(1000, %{address: address})

      # Should produce equivalent contracts
      assert Contract.to_script(contract1) == Contract.to_script(contract2)
    end

    test "unlock_p2pkh/3 delegates to P2PKH.unlock/3" do
      utxo = create_test_utxo()

      contract1 = Contract.unlock_p2pkh(utxo, %{keypair: @keypair})
      contract2 = P2PKH.unlock(utxo, %{keypair: @keypair})

      assert Contract.to_script(contract1) == Contract.to_script(contract2)
    end

    test "lock_p2wpkh/3 delegates to P2WPKH.lock/3" do
      address = Address.from_pubkey(@keypair.pubkey, type: :p2wpkh)

      contract1 = Contract.lock_p2wpkh(1000, %{address: address})
      contract2 = P2WPKH.lock(1000, %{address: address})

      assert Contract.to_script(contract1) == Contract.to_script(contract2)
    end

    test "unlock_p2wpkh/3 delegates to P2WPKH.unlock/3" do
      utxo = create_test_utxo()

      contract1 = Contract.unlock_p2wpkh(utxo, %{keypair: @keypair})
      contract2 = P2WPKH.unlock(utxo, %{keypair: @keypair})

      assert Contract.to_script(contract1) == Contract.to_script(contract2)
    end

    test "lock_p2sh_p2wpkh/3 delegates to P2SH_P2WPKH.lock/3" do
      address = Address.from_pubkey(@keypair.pubkey, type: :p2sh_p2wpkh)

      contract1 = Contract.lock_p2sh_p2wpkh(1000, %{address: address})
      contract2 = P2SH_P2WPKH.lock(1000, %{address: address})

      assert Contract.to_script(contract1) == Contract.to_script(contract2)
    end

    test "unlock_p2sh_p2wpkh/3 delegates to P2SH_P2WPKH.unlock/3" do
      utxo = create_test_utxo()

      contract1 = Contract.unlock_p2sh_p2wpkh(utxo, %{keypair: @keypair})
      contract2 = P2SH_P2WPKH.unlock(utxo, %{keypair: @keypair})

      assert Contract.to_script(contract1) == Contract.to_script(contract2)
    end
  end

  describe "contract struct" do
    test "lock creates contract with locking_script mfa" do
      address = Address.from_pubkey(@keypair.pubkey)
      contract = P2PKH.lock(1000, %{address: address})

      assert {P2PKH, :locking_script, [%{address: ^address}]} = contract.mfa
      assert contract.subject == 1000
    end

    test "unlock creates contract with unlocking_script mfa" do
      utxo = create_test_utxo()
      contract = P2PKH.unlock(utxo, %{keypair: @keypair})

      assert {P2PKH, :unlocking_script, [%{keypair: @keypair}]} = contract.mfa
      assert contract.subject == utxo
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
