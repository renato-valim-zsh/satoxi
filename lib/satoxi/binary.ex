defmodule Satoxi.Binary do
  @moduledoc """
  Collection of helper function to handle binaries
  """

  @doc """
  Reverses the bytes of the given binary data.

  ## Examples

      iex> Satoxi.Binary.reverse_binary("abcdefg")
      "gfedcba"

      iex> Satoxi.Binary.reverse_binary(<<1, 2, 3, 0>>)
      <<0, 3, 2, 1>>
  """
  @spec reverse_binary(binary()) :: binary()
  def reverse_binary(data) when is_binary(data) do
    data
    |> :binary.bin_to_list()
    |> Enum.reverse()
    |> :binary.list_to_bin()
  end
end
