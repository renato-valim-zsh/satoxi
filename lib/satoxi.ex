defmodule Satoxi do
  @moduledoc """
  Documentation for `Satoxi`.

  ## Configuration

  Optionally, Satoxi can be configured for testnet network by editing your
  application's configuration:

  ```elixir
  config :satoxi,
    network: :test  # defaults to :main
  ```
  """

  @typedoc "Bitcoin network"
  @type network() :: :main | :test

  @doc """
  Returns the currently configured Bitcoin network.
  """
  @spec network() :: network()
  def network(), do: Application.get_env(:satoxi, :network, :main)
end
