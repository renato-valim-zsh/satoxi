defmodule Satoxi.Contract.OpCodeHelpers do
  @moduledoc """
  Helper module for using Op Codes in `Satoxi.Contract` modules.

  All known Op Codes are available as a function which simply pushes the Op Code word onto the Contract Script. 
  Refer to `Satoxi.VM` for descriptions of each Op Code.
  """
  alias Satoxi.Contract
  alias Satoxi.Script.OpCode

  # Iterrates over all opcodes
  # Defines a function to push the specified opcode onto the contract script
  Enum.each(OpCode.all(), fn {op, _} ->
    key =
      op
      |> Atom.to_string()
      |> String.downcase()
      |> String.to_atom()

    @doc "Pushes the `#{op}` word onto the script."
    @spec unquote(key)(Contract.t()) :: Contract.t()
    def unquote(key)(%Contract{} = contract) do
      Contract.script_push(contract, unquote(op))
    end
  end)
end
