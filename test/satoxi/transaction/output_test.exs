defmodule Satoxi.Transaction.OutputTest do
  use ExUnit.Case, async: true

  alias Satoxi.Script
  alias Satoxi.Transaction.Output

  @output_hex "efbee82f000000001976a9145ae866af9de106847de6111e5f1faa168b2be68988ac"
  @output_script %Script{
    chunks: [
      :OP_DUP,
      :OP_HASH160,
      <<90, 232, 102, 175, 157, 225, 6, 132, 125, 230, 17, 30, 95, 31, 170, 22, 139, 43, 230,
        137>>,
      :OP_EQUALVERIFY,
      :OP_CHECKSIG
    ]
  }

  doctest Output

  describe "Output.from_binary/2" do
    test "parses hex encoded p2pkh output" do
      assert {:ok, %Output{script: script} = output} =
               Output.from_binary(@output_hex, encoding: :hex)

      assert output.satoshis == 803_782_383
      assert script == @output_script
    end
  end

  describe "Output.from_binary!/2" do
    test "parses hex encoded p2pkh output" do
      assert %Output{script: script} = output = Output.from_binary!(@output_hex, encoding: :hex)
      assert output.satoshis == 803_782_383
      assert script == @output_script
    end
  end

  describe "Output.get_size/2" do
    test "returns byte size of the output" do
      output = %Output{satoshis: 803_782_383, script: @output_script}
      assert Output.get_size(output) == 34
    end
  end

  describe "Output.to_binary/2" do
    test "serialises p2pkh output as hex string" do
      output = %Output{satoshis: 803_782_383, script: @output_script}
      assert Output.to_binary(output, encoding: :hex) == @output_hex
    end
  end
end
