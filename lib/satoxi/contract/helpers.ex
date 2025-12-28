defmodule Satoxi.Contract.Helpers do
  @moduledoc """
  Collection of helper functions for use in `Satoxi.Contract` modules.

  Using `Satoxi.Contract.Helpers` will import itself and all related helper modules into your context.

      use Satoxi.Contract.Helpers

  Alternative, helper modules can be imported individually.

      import Satoxi.Contract.Helpers
      import Satoxi.Contract.OpCodeHelpers
  """
  alias Satoxi.Contract
  alias Satoxi.Keys.PrivKey
  alias Satoxi.Transaction.Sig
  alias Satoxi.Transaction.UTXO

  defmacro __using__(_) do
    quote do
      import Satoxi.Contract.Helpers
      import Satoxi.Contract.OpCodeHelpers
    end
  end

  @doc """
  Iterates over the given enumerable, invoking the `handle_each` function on each.

  ## Example

      contract
      |> each(["foo", "bar", "baz"], fn el, c ->
        c
        |> push(el)
        |> op_dup()
      end)
  """
  @spec each(
          Contract.t(),
          Enum.t(),
          (Enum.element(), Contract.t() -> Contract.t())
        ) :: Contract.t()
  def each(%Contract{} = contract, enum, handle_each)
      when is_function(handle_each),
      do: Enum.reduce(enum, contract, handle_each)

  @doc """
  Pushes the given data onto the script. If a list of data elements is given, each will be pushed to the script as seperate push.
  """
  @spec push(
          Contract.t(),
          atom() | binary() | integer() | list(atom() | binary() | integer())
        ) :: Contract.t()
  def push(%Contract{} = contract, data) when is_list(data),
    do: each(contract, data, &push(&2, &1))

  def push(%Contract{} = contract, data),
    do: Contract.script_push(contract, data)

  @doc """
  Signs the transaction [`context`](`t:Satoxi.Contract.ctx/0`) and pushes the signature onto the script.

  A list of private keys can be given, in which case each is used to sign and multiple signatures are added.

  If no context is available in the [`contract`](`t:Satoxi.Contract.t/0`), then 71 bytes of zeros are pushed onto the script for each private key.
  """
  @spec sig(Contract.t(), PrivKey.t() | list(PrivKey.t())) :: Contract.t()
  def sig(%Contract{} = contract, privkey) when is_list(privkey),
    do: each(contract, privkey, &sig(&2, &1))

  def sig(
        %Contract{ctx: {tx, index}, opts: opts, subject: %UTXO{output: output}} = contract,
        %PrivKey{} = privkey
      ) do
    signature = Sig.sign(tx, index, output, privkey, opts)

    Contract.script_push(contract, signature)
  end

  def sig(%Contract{ctx: nil} = contract, %PrivKey{} = _privkey),
    do: Contract.script_push(contract, <<0::568>>)
end
