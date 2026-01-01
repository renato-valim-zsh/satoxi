defmodule Satoxi.Transaction.Input do
  @moduledoc """
  An Input is a data structure representing a single input in a `t:Satoxi.Transaction.t/0`.

  An Input consists of the `t:Satoxi.OutPoint.t/0` of the output which is being spent, a Script known as the unlocking script, and a sequence number.

  An Input spends a previous output by concatenating the unlocking script with the locking script in the order:

    unlocking_script <> locking_script

  The entire script is evaluated and if it returns a truthy value, the output is unlocked and spent.

  When the sequence value is less that `0xFFFFFFFF` and that transaction locktime is set in the future, that transaction is considered non-final and will not be mined in a block. 
  This mechanism can be used to build payment channels.
  """

  alias Satoxi.Script
  alias Satoxi.Serializable
  alias Satoxi.Transaction.OutPoint
  alias Satoxi.Transaction.Witness

  import Satoxi.Encoding,
    only: [decode: 2, encode: 2, parse_varint_data: 1, encode_varint_binary: 1]

  @max_sequence 0xFFFFFFFF

  defstruct outpoint: %OutPoint{}, script: %Script{}, sequence: @max_sequence, witness: %Witness{}

  @typedoc "Input struct"
  @type t() :: %__MODULE__{
          outpoint: OutPoint.t(),
          script: Script.t(),
          sequence: non_neg_integer(),
          witness: Witness.t()
        }

  @typedoc """
  Vin - Vector of an input in a Bitcoin transaction

  In integer representing the index of an Input
  """
  @type vin() :: non_neg_integer()

  @doc """
  Parses the given binary into a `t:Satoxi.Transaction.Input.t/0`.

  ## Options

  The accepted options are:

  * `:encoding` - Optionally decode the binary with either the `:base64` or `:hex` encoding scheme.
  """
  @spec from_binary(binary(), keyword()) :: {:ok, t()} | {:error, term()}
  def from_binary(data, opts \\ []) when is_binary(data) do
    encoding = Keyword.get(opts, :encoding)

    with {:ok, data} <- decode(data, encoding),
         {:ok, input, _rest} <- Serializable.parse(%__MODULE__{}, data) do
      {:ok, input}
    end
  end

  @doc """
  Parses the given binary into a `t:Satoxi.Transaction.Input.t/0`.

  As `from_binary/2` but returns the result or raises an exception.
  """
  @spec from_binary!(binary(), keyword()) :: t()
  def from_binary!(data, opts \\ []) when is_binary(data) do
    case from_binary(data, opts) do
      {:ok, input} ->
        input

      {:error, error} ->
        raise Satoxi.Error, error
    end
  end

  @doc """
  Returns the number of bytes of the given `t:Satoxi.Transaction.Input.t/0`.
  """
  @spec get_size(t()) :: non_neg_integer()
  def get_size(%__MODULE__{} = input),
    do: to_binary(input) |> byte_size()

  @doc """
  Returns true if the input has witness data.
  """
  @spec has_witness?(t()) :: boolean()
  def has_witness?(%__MODULE__{witness: witness}),
    do: Witness.has_items?(witness)

  @doc """
  Serializes the witness stack for this input.
  """
  @spec serialize_witness(t()) :: binary()
  def serialize_witness(%__MODULE__{witness: witness}),
    do: Serializable.serialize(witness)

  @doc """
  Returns the size of the witness data in bytes.
  """
  @spec get_witness_size(t()) :: non_neg_integer()
  def get_witness_size(%__MODULE__{witness: witness}),
    do: Witness.get_size(witness)

  @doc """
  Serialises the given `t:Satoxi.Transaction.Input.t/0` into a binary.

  ## Options

  The accepted options are:

  * `:encoding` - Optionally encode the binary with either the `:base64` or `:hex` encoding scheme.
  """
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{} = input, opts \\ []) do
    encoding = Keyword.get(opts, :encoding)

    input
    |> Serializable.serialize()
    |> encode(encoding)
  end

  defimpl Serializable do
    @impl true
    def parse(input, data) do
      with {:ok, outpoint, data} <- Serializable.parse(%OutPoint{}, data),
           {:ok, script, data} <- parse_varint_data(data),
           <<sequence::little-32, rest::binary>> = data do
        script =
          case OutPoint.is_null?(outpoint) do
            false -> Script.from_binary!(script)
            true -> %Script{coinbase: script}
          end

        {:ok,
         struct(input,
           outpoint: outpoint,
           script: script,
           sequence: sequence
         ), rest}
      end
    end

    @impl true
    def serialize(%{outpoint: outpoint, script: script, sequence: sequence}) do
      outpoint_data = Serializable.serialize(outpoint)

      script_data =
        script
        |> Script.to_binary()
        |> encode_varint_binary()

      <<
        outpoint_data::binary,
        script_data::binary,
        sequence::little-32
      >>
    end
  end
end
