defmodule Satoxi.Transaction.Witness do
  @moduledoc """
  A Witness is a data structure representing the witness data for a SegWit transaction input.

  The witness consists of a list of binary items (stack elements) that provide the data needed to satisfy the spending conditions of a SegWit output.

  For `P2WPKH` inputs, the witness typically contains:
  - A signature
  - A public key

  For `P2WSH` inputs, the witness contains:
  - Stack elements required by the script
  - The witness script itself
  """
  alias Satoxi.Serializable
  import Satoxi.Encoding

  defstruct items: []

  @typedoc "Witness struct"
  @type t() :: %__MODULE__{items: list(binary())}

  @doc """
  Returns true if the witness has any items.
  """
  @spec has_items?(t()) :: boolean()
  def has_items?(%__MODULE__{items: items}),
    do: items != [] and items != nil

  @doc """
  Returns the number of bytes of the serialized witness.
  """
  @spec get_size(t()) :: non_neg_integer()
  def get_size(%__MODULE__{} = witness),
    do: Serializable.serialize(witness) |> byte_size()

  defimpl Serializable do
    @impl true
    def parse(_witness, data) do
      with {:ok, count, data} <- parse_varint_int(data) do
        parse_items(count, data, [])
      end
    end

    defp parse_items(0, data, acc),
      do: {:ok, %Satoxi.Transaction.Witness{items: Enum.reverse(acc)}, data}

    defp parse_items(count, data, acc) do
      with {:ok, item, data} <- parse_varint_data(data) do
        parse_items(count - 1, data, [item | acc])
      end
    end

    @impl true
    def serialize(%{items: []}), do: <<0x00>>
    def serialize(%{items: nil}), do: <<0x00>>

    def serialize(%{items: items}) do
      items_data =
        Enum.reduce(items, <<>>, fn item, acc ->
          acc <> encode_varint_binary(item)
        end)

      encode(length(items), :var_int) <> items_data
    end
  end
end
