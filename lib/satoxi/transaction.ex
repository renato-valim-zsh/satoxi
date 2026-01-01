defmodule Satoxi.Transaction do
  @moduledoc """
  A Transaction is a data structure representing a Bitcoin transaction.

  A Transaction consists of a version number, a list of inputs, list of outputs, and a locktime value.

  A Bitcoin transaction is used to transfer custody of Bitcoins. 
  It can also be used for smart contracts, recording and timestamping data, and many other functionalities.

  The Transaction module is used for parsing and serialising transaction data. 
  Use the `Satoxi.Transaction.Builder` module for building transactions.

  ## Transaction Layouts

  ### Legacy Transaction

      +----------------+----------------------------------+
      |    Version     |            4 bytes               |
      +----------------+----------------------------------+
      |  Input Count   |         VarInt (1-9 bytes)       |
      +----------------+----------------------------------+
      |                |  OutPoint (36 bytes)             |
      |    Input 0     |  ScriptSig Length (VarInt)       |
      |                |  ScriptSig (variable)            |
      |                |  Sequence (4 bytes)              |
      +----------------+----------------------------------+
      |      ...       |         more inputs              |
      +----------------+----------------------------------+
      |  Output Count  |         VarInt (1-9 bytes)       |
      +----------------+----------------------------------+
      |                |  Value (8 bytes)                 |
      |   Output 0     |  ScriptPubKey Length (VarInt)    |
      |                |  ScriptPubKey (variable)         |
      +----------------+----------------------------------+
      |      ...       |         more outputs             |
      +----------------+----------------------------------+
      |   Lock Time    |            4 bytes               |
      +----------------+----------------------------------+

  ### SegWit Transaction

      +----------------+----------------------------------+
      |    Version     |            4 bytes               |
      +----------------+----------------------------------+
      |    Marker      |       0x00 (1 byte)              |
      +----------------+----------------------------------+
      |     Flag       |       0x01 (1 byte)              |
      +----------------+----------------------------------+
      |  Input Count   |         VarInt (1-9 bytes)       |
      +----------------+----------------------------------+
      |                |  OutPoint (36 bytes)             |
      |    Input 0     |  ScriptSig Length (VarInt)       |
      |                |  ScriptSig (variable)            |
      |                |  Sequence (4 bytes)              |
      +----------------+----------------------------------+
      |      ...       |         more inputs              |
      +----------------+----------------------------------+
      |  Output Count  |         VarInt (1-9 bytes)       |
      +----------------+----------------------------------+
      |                |  Value (8 bytes)                 |
      |   Output 0     |  ScriptPubKey Length (VarInt)    |
      |                |  ScriptPubKey (variable)         |
      +----------------+----------------------------------+
      |      ...       |         more outputs             |
      +----------------+----------------------------------+
      |                |  Item Count (VarInt)             |
      |   Witness 0    |  Item 0 Length + Data            |
      |   (Input 0)    |  Item 1 Length + Data            |
      |                |  ...                             |
      +----------------+----------------------------------+
      |      ...       |    witness for each input        |
      +----------------+----------------------------------+
      |   Lock Time    |            4 bytes               |
      +----------------+----------------------------------+

  The marker (0x00) and flag (0x01) bytes distinguish SegWit transactions from legacy ones. 
  The witness data appears after all outputs and before the locktime, with one witness stack per input.
  """
  alias Satoxi.{Contract, Hash, Serializable}
  alias Satoxi.Transaction.{Builder, OutPoint, Input, Output, UTXO, Witness}
  import Satoxi.Binary, only: [reverse_binary: 1]
  import Satoxi.Encoding

  defstruct version: 1, inputs: [], outputs: [], lock_time: 0

  @typedoc "Transaction struct"
  @type t() :: %__MODULE__{
          version: non_neg_integer(),
          inputs: list(Input.t()),
          outputs: list(Output.t()),
          lock_time: non_neg_integer()
        }

  @typedoc """
  Transaction hash

  Result of hashing the transaction data through the SHA-256 algorithm twice.
  """
  @type hash() :: <<_::256>>

  @typedoc """
  TXID

  Result of reversing and hex-encoding the `t:Satoxi.Transaction.hash/0`.
  """
  @type txid() :: String.t()

  @doc """
  Creates a new `t:Satoxi.Transaction.Builder.t/0`.
  """
  @spec builder() :: Builder.t()
  def builder, do: %Builder{}

  @doc """
  Converts a `t:Satoxi.Transaction.Builder.t/0` to a `t:Satoxi.Transaction.t/0`.

  Delegates to `Satoxi.Transaction.Builder.to_tx/1`.
  """
  @spec builder_to_tx(Builder.t()) :: t()
  def builder_to_tx(%Builder{} = builder), do: Builder.to_tx(builder)

  @doc """
  Builds a `t:Satoxi.Transaction.UTXO.t/0` from the given map of params.

  Delegates to `Satoxi.Transaction.UTXO.from_params!/1`.
  """
  @spec utxo_from_params!(map()) :: UTXO.t()
  def utxo_from_params!(%{} = params), do: UTXO.from_params!(params)

  @doc """
  Adds an input to a transaction or builder.

  When given a `t:Satoxi.Transaction.t/0` and `t:Satoxi.Transaction.Input.t/0`, adds the input to the transaction.

  When given a `t:Satoxi.Transaction.Builder.t/0` and `t:Satoxi.Contract.t/0`, delegates to `Satoxi.Transaction.Builder.add_input/2`.
  """
  @spec add_input(t(), Input.t()) :: t()
  @spec add_input(Builder.t(), Contract.t()) :: Builder.t()
  def add_input(tx_or_builder, input)

  def add_input(%__MODULE__{} = tx, %Input{} = input),
    do: update_in(tx.inputs, &(&1 ++ [input]))

  def add_input(%Builder{} = builder, %Contract{} = input),
    do: Builder.add_input(builder, input)

  @doc """
  Adds an output to a transaction or builder.

  When given a `t:Satoxi.Transaction.t/0` and `t:Satoxi.Transaction.Output.t/0`, adds the output to the transaction.

  When given a `t:Satoxi.Transaction.Builder.t/0` and `t:Satoxi.Contract.t/0`, delegates to `Satoxi.Transaction.Builder.add_output/2`.
  """
  @spec add_output(t(), Output.t()) :: t()
  @spec add_output(Builder.t(), Contract.t()) :: Builder.t()
  def add_output(tx_or_builder, output)

  def add_output(%__MODULE__{} = tx, %Output{} = output),
    do: update_in(tx.outputs, &(&1 ++ [output]))

  def add_output(%Builder{} = builder, %Contract{} = output),
    do: Builder.add_output(builder, output)

  @doc """
  Returns true if the given `t:Satoxi.Transaction.t/0` is a coinbase transaction (the first transaction in a block, containing the miner block reward).
  """
  @spec is_coinbase?(t()) :: boolean()
  def is_coinbase?(%__MODULE__{inputs: [input]}),
    do: OutPoint.is_null?(input.outpoint)

  def is_coinbase?(%__MODULE__{}), do: false

  @doc """
  Returns true if the given `t:Satoxi.Transaction.t/0` is a SegWit transaction.

  A transaction is considered SegWit if any of its inputs has witness data.
  """
  @spec is_segwit?(t()) :: boolean()
  def is_segwit?(%__MODULE__{inputs: inputs}) do
    Enum.any?(inputs, &Input.has_witness?/1)
  end

  @doc """
  Parses the given binary into a `t:Satoxi.Transaction.t/0`.

  ## Options

  The accepted options are:

  * `:encoding` - Optionally decode the binary with either the `:base64` or `:hex` encoding scheme.
  """
  @spec from_binary(binary(), keyword()) :: {:ok, t()} | {:error, term()}
  def from_binary(data, opts \\ []) when is_binary(data) do
    encoding = Keyword.get(opts, :encoding)

    with {:ok, data} <- decode(data, encoding),
         {:ok, tx, _rest} <- Serializable.parse(%__MODULE__{}, data) do
      {:ok, tx}
    end
  end

  @doc """
  Parses the given binary into a `t:Satoxi.Transaction.t/0`.

  As `from_binary/2` but returns the result or raises an exception.
  """
  @spec from_binary!(binary(), keyword()) :: t()
  def from_binary!(data, opts \\ []) when is_binary(data) do
    case from_binary(data, opts) do
      {:ok, tx} ->
        tx

      {:error, error} ->
        raise Satoxi.Error, error
    end
  end

  @doc """
  Returns the `t:Satoxi.Transaction.hash/0` of the given transaction.

  For SegWit transactions, this returns the hash of the non-witness serialization (the TXID hash). 
  Use `get_witness_hash/1` for the witness-inclusive hash.
  """
  @spec get_hash(t()) :: hash()
  def get_hash(%__MODULE__{} = tx) do
    tx
    |> to_binary(segwit: false)
    |> Hash.sha256_sha256()
  end

  @doc """
  Returns the witness hash (wtxid hash) of the given transaction.

  For non-SegWit transactions, this is identical to `get_hash/1`.
  For SegWit transactions, this includes the witness data in the hash.
  """
  @spec get_witness_hash(t()) :: hash()
  def get_witness_hash(%__MODULE__{} = tx) do
    tx
    |> to_binary(segwit: true)
    |> Hash.sha256_sha256()
  end

  @doc """
  Returns the number of bytes of the given `t:Satoxi.Transaction.t/0`.

  For SegWit transactions, this returns the full size including witness data.
  Use `get_base_size/1` for the size without witness data.
  """
  @spec get_size(t()) :: non_neg_integer()
  def get_size(%__MODULE__{} = tx),
    do: to_binary(tx) |> byte_size()

  @doc """
  Returns the base size (non-witness) of the given `t:Satoxi.Transaction.t/0`.
  """
  @spec get_base_size(t()) :: non_neg_integer()
  def get_base_size(%__MODULE__{} = tx),
    do: to_binary(tx, segwit: false) |> byte_size()

  @doc """
  Returns the weight of the given `t:Satoxi.Transaction.t/0`.

  Weight = base_size * 3 + total_size
  This is used for fee calculation in SegWit transactions.
  """
  @spec get_weight(t()) :: non_neg_integer()
  def get_weight(%__MODULE__{} = tx) do
    base_size = get_base_size(tx)
    total_size = get_size(tx)
    base_size * 3 + total_size
  end

  @doc """
  Returns the virtual size (vsize) of the given `t:Satoxi.Transaction.t/0`.

  Virtual size = ceil(weight / 4)
  This is used for fee calculation in SegWit transactions.
  """
  @spec get_vsize(t()) :: non_neg_integer()
  def get_vsize(%__MODULE__{} = tx),
    do: ceil(get_weight(tx) / 4)

  @doc """
  Returns the `t:Satoxi.Transaction.txid/0` of the given transaction.
  """
  @spec get_txid(t()) :: txid()
  def get_txid(%__MODULE__{} = tx) do
    tx
    |> get_hash()
    |> reverse_binary()
    |> encode(:hex)
  end

  @doc """
  Returns the witness transaction ID (wtxid) of the given transaction.

  For non-SegWit transactions, this is identical to `get_txid/1`.
  """
  @spec get_wtxid(t()) :: txid()
  def get_wtxid(%__MODULE__{} = tx) do
    tx
    |> get_witness_hash()
    |> reverse_binary()
    |> encode(:hex)
  end

  @doc """
  Serialises the given `t:Satoxi.Transaction.t/0` into a binary.

  ## Options

  The accepted options are:

  * `:encoding` - Optionally encode the binary with either the `:base64` or `:hex` encoding scheme.
  * `:segwit` - If true, include witness data in SegWit format. If false, use legacy format.
    Defaults to true if the transaction has witness data.
  """
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{} = tx, opts \\ []) do
    encoding = Keyword.get(opts, :encoding)
    segwit = Keyword.get(opts, :segwit, is_segwit?(tx))

    data =
      if segwit and is_segwit?(tx) do
        serialize_segwit(tx)
      else
        Serializable.serialize(tx)
      end

    encode(data, encoding)
  end

  # Serializes transaction in SegWit format
  defp serialize_segwit(%{
         version: version,
         inputs: inputs,
         outputs: outputs,
         lock_time: lock_time
       }) do
    inputs_data =
      Enum.reduce(inputs, encode(length(inputs), :var_int), fn input, data ->
        data <> Serializable.serialize(input)
      end)

    outputs_data =
      Enum.reduce(outputs, encode(length(outputs), :var_int), fn output, data ->
        data <> Serializable.serialize(output)
      end)

    witness_data =
      Enum.reduce(inputs, <<>>, fn input, data ->
        data <> Input.serialize_witness(input)
      end)

    <<
      version::little-32,
      # marker
      0x00,
      # flag
      0x01,
      inputs_data::binary,
      outputs_data::binary,
      witness_data::binary,
      lock_time::little-32
    >>
  end

  defimpl Serializable do
    @impl true
    def parse(tx, data) do
      <<version::little-32, rest::binary>> = data

      case rest do
        # Segwit format: marker=0x00, flag=0x01 
        <<0x00, 0x01, data::binary>> ->
          parse_segwit(tx, version, data)

        # Legacy format 
        data ->
          parse_legacy(tx, version, data)
      end
    end

    defp parse_legacy(tx, version, data) do
      with {:ok, inputs, data} <- parse_varint_items(data, Input),
           {:ok, outputs, data} <- parse_varint_items(data, Output),
           <<lock_time::little-32, rest::binary>> = data do
        {:ok,
         struct(tx,
           version: version,
           inputs: inputs,
           outputs: outputs,
           lock_time: lock_time
         ), rest}
      end
    end

    defp parse_segwit(tx, version, data) do
      with {:ok, inputs, data} <- parse_varint_items(data, Input),
           {:ok, outputs, data} <- parse_varint_items(data, Output),
           {:ok, inputs, data} <- parse_witnesses(inputs, data),
           <<lock_time::little-32, rest::binary>> = data do
        {:ok,
         struct(tx,
           version: version,
           inputs: inputs,
           outputs: outputs,
           lock_time: lock_time
         ), rest}
      end
    end

    defp parse_witnesses(inputs, data) do
      Enum.reduce_while(inputs, {:ok, [], data}, fn input, {:ok, acc, data} ->
        case Serializable.parse(%Witness{}, data) do
          {:ok, witness, rest} ->
            {:cont, {:ok, acc ++ [%{input | witness: witness}], rest}}

          error ->
            {:halt, error}
        end
      end)
    end

    @impl true
    def serialize(%{version: version, inputs: inputs, outputs: outputs, lock_time: lock_time}) do
      inputs_data =
        Enum.reduce(inputs, encode(length(inputs), :var_int), fn input, data ->
          data <> Serializable.serialize(input)
        end)

      outputs_data =
        Enum.reduce(outputs, encode(length(outputs), :var_int), fn output, data ->
          data <> Serializable.serialize(output)
        end)

      <<
        version::little-32,
        inputs_data::binary,
        outputs_data::binary,
        lock_time::little-32
      >>
    end
  end
end
