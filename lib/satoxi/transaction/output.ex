defmodule Satoxi.Transaction.Output do
  @moduledoc """
  An Output is a data structure representing a single output in a `t:Satoxi.Transaction.t/0`.

  An Output consists of the number of satoshis being locked in the output, and a `t:Satoxi.Script.t/0`, otherwise known as the locking script. 

  The output can later be spent by creating an input in a new transaction with a corresponding unlocking script.

  The index of the output within it's containing `t:Satoxi.Transaction.t/0`, denotes it's `t:Satoxi.Transaction.Output.vout/0`.
  """
  alias Satoxi.Script
  alias Satoxi.Serializable

  import Satoxi.Encoding,
    only: [decode: 2, encode: 2, encode_varint_binary: 1, parse_varint_data: 1]

  defstruct satoshis: 0, script: %Script{}

  @typedoc "Output struct"
  @type t() :: %__MODULE__{
          satoshis: non_neg_integer(),
          script: Script.t()
        }

  @typedoc """
  Vout - Vector of an output in a Bitcoin transaction

  In integer representing the index of an Output.
  """
  @type vout() :: non_neg_integer()

  @doc """
  Parses the given binary into a `t:Satoxi.Transaction.Output.t/0`.

  ## Options

  The accepted options are:

  * `:encoding` - Optionally decode the binary with either the `:base64` or `:hex` encoding scheme.
  """
  @spec from_binary(binary(), keyword()) :: {:ok, t()} | {:error, term()}
  def from_binary(data, opts \\ []) when is_binary(data) do
    encoding = Keyword.get(opts, :encoding)

    with {:ok, data} <- decode(data, encoding),
         {:ok, output, _rest} <- Serializable.parse(%__MODULE__{}, data) do
      {:ok, output}
    end
  end

  @doc """
  Parses the given binary into a `t:Satoxi.Transaction.Output.t/0`.

  As `from_binary/2` but returns the result or raises an exception.
  """
  @spec from_binary!(binary(), keyword()) :: t()
  def from_binary!(data, opts \\ []) when is_binary(data) do
    case from_binary(data, opts) do
      {:ok, output} ->
        output

      {:error, error} ->
        raise Satoxi.Error, error
    end
  end

  @doc """
  Returns the number of bytes of the given `t:Satoxi.Transaction.Output.t/0`.
  """
  @spec get_size(t()) :: non_neg_integer()
  def get_size(%__MODULE__{} = output),
    do: to_binary(output) |> byte_size()

  @doc """
  Serialises the given `t:Satoxi.Transaction.Output.t/0` into a binary.

  ## Options

  The accepted options are:

  * `:encoding` - Optionally encode the binary with either the `:base64` or `:hex` encoding scheme.
  """
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{} = output, opts \\ []) do
    encoding = Keyword.get(opts, :encoding)

    output
    |> Serializable.serialize()
    |> encode(encoding)
  end

  defimpl Serializable do
    @impl true
    def parse(output, data) do
      with <<satoshis::little-64, data::binary>> <- data,
           {:ok, script, rest} <- parse_varint_data(data),
           {:ok, script} <- Script.from_binary(script) do
        {:ok,
         struct(output,
           satoshis: satoshis,
           script: script
         ), rest}
      end
    end

    @impl true
    def serialize(%{satoshis: satoshis, script: script}) do
      script_data =
        script
        |> Script.to_binary()
        |> encode_varint_binary()

      <<
        satoshis::little-64,
        script_data::binary
      >>
    end
  end
end
