defmodule Satoxi.Transaction.Builder do
  @moduledoc """
  A flexible and powerful transaction building module and API.

  The Builder accepts inputs and outputs that are modules implementing the `Satoxi.Contract` behaviour. 
  This abstraction makes for a succinct and elegant approach to building transactions. 

  The `Satoxi.Contract` behaviour is flexible and can be used to define any kind of locking and unlocking script, not limited to a handful of standard transactions.

  ## Examples

  Because each input and output is prepared with all the information it needs, calling `to_tx/1` is all that is needed to build and sign the transaction.

      iex> utxo = Satoxi.Transaction.UTXO.from_params!(%{
      ...>   "txid" => "5e3014372338f079f005eedc85359e4d96b8440e7dbeb8c35c4182e0c19a1a12",
      ...>   "vout" => 0,
      ...>   "satoshis" => 11000,
      ...>   "script" => "76a914538fd179c8be0f289c730e33b5f6a3541be9668f88ac"
      ...> })
      iex>
      iex> builder = %Satoxi.Transaction.Builder{
      ...>   inputs: [
      ...>     Satoxi.Contract.P2PKH.unlock(utxo, %{keypair: @keypair})
      ...>   ],
      ...>   outputs: [
      ...>     Satoxi.Contract.P2PKH.lock(5000, %{address: @address}),
      ...>     Satoxi.Contract.P2PKH.lock(5000, %{address: @change_address}),
      ...>   ]
      ...> }
      iex>
      iex> tx = Satoxi.Transaction.Builder.to_tx(builder)
      iex> rawtx = Transaction.to_binary(tx, encoding: :hex) # already signed and encoded, ready to be broadcasted
  """

  alias Satoxi.Contract
  alias Satoxi.Script
  alias Satoxi.Transaction
  alias Satoxi.Transaction.UTXO

  import Satoxi.Binary

  defstruct inputs: [],
            outputs: [],
            lock_time: 0

  @typedoc "Transaction Builder struct"
  @type t() :: %__MODULE__{
          inputs: list(Contract.t()),
          outputs: list(Contract.t()),
          lock_time: non_neg_integer()
        }

  @doc """
  Adds the given unlocking script contract to the builder.
  """
  @spec add_input(t(), Contract.t()) :: t()
  def add_input(%__MODULE__{} = builder, %Contract{mfa: {_, :unlocking_script, _}} = input),
    do: update_in(builder.inputs, &(&1 ++ [input]))

  @doc """
  Adds the given locking script contract to the builder.
  """
  @spec add_output(t(), Contract.t()) :: t()
  def add_output(%__MODULE__{} = builder, %Contract{mfa: {_, :locking_script, _}} = output),
    do: update_in(builder.outputs, &(&1 ++ [output]))

  @doc """
  Returns the sum of all inputs defined in the builder.
  """
  @spec input_sum(t()) :: integer()
  def input_sum(%__MODULE__{inputs: inputs}) do
    inputs
    |> Enum.map(& &1.subject.output.satoshis)
    |> Enum.sum()
  end

  @doc """
  Returns the sum of all outputs defined in the builder.
  """
  @spec output_sum(t()) :: integer()
  def output_sum(%__MODULE__{outputs: outputs}) do
    outputs
    |> Enum.map(& &1.subject)
    |> Enum.sum()
  end

  @doc """
  Sorts the TransactionBuilder inputs and outputs according to [BIP-69](https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki).

  BIP-69 defines deterministic lexographical indexing of transaction inputs and outputs.
  """
  @spec sort(t()) :: t()
  def sort(%__MODULE__{} = builder) do
    builder
    |> Map.update!(:inputs, fn inputs ->
      Enum.sort(inputs, fn %{subject: %UTXO{outpoint: a}}, %{subject: %UTXO{outpoint: b}} ->
        {reverse_binary(a.hash), a.vout} < {reverse_binary(b.hash), b.vout}
      end)
    end)
    |> Map.update!(:outputs, fn outputs ->
      Enum.sort(outputs, fn a, b ->
        script_a = Contract.to_script(a)
        script_b = Contract.to_script(b)

        {a.subject, Script.to_binary(script_a)} < {b.subject, Script.to_binary(script_b)}
      end)
    end)
  end

  @doc """
  Builds and returns the signed transaction.
  """
  @spec to_tx(t()) :: Transaction.t()
  def to_tx(%__MODULE__{inputs: inputs, outputs: outputs} = builder) do
    builder = sort(builder)

    tx = struct(Transaction, lock_time: builder.lock_time)

    # First pass on populating inputs will zero out signatures
    tx =
      Enum.reduce(inputs, tx, fn contract, tx ->
        Transaction.add_input(tx, Contract.to_input(contract))
      end)

    # Create outputs
    tx =
      Enum.reduce(outputs, tx, fn contract, tx ->
        Transaction.add_output(tx, Contract.to_output(contract))
      end)

    # Second pass on populating inputs with actual sigs
    Enum.reduce(Enum.with_index(inputs), tx, fn {contract, vin}, tx ->
      input =
        contract
        |> Contract.put_ctx({tx, vin})
        |> Contract.to_input()

      update_in(tx.inputs, &List.replace_at(&1, vin, input))
    end)
  end
end
