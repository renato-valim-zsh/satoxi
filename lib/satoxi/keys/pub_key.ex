defmodule Satoxi.Keys.PubKey do
  @moduledoc """
  A PubKey is a data structure representing a Bitcoin public key.

  Internally, a public key is the `x` and `y` coordiantes of a point of the `secp256k1` curve. 
  It is derived by performaing elliptic curve multiplication on a corresponding private key.
  """
  alias Satoxi.Keys.PrivKey
  alias Curvy.{Key, Point}
  import Satoxi.Encoding, only: [decode: 2, encode: 2]

  defstruct [:point, compressed: true]

  @typedoc "Public key struct"
  @type t() :: %__MODULE__{
          point: Point.t() | nil,
          compressed: boolean()
        }

  @doc """
  Parses the given binary into a `t:Satoxi.Keys.PubKey.t/0`.

  ## Options

  The accepted options are:

  * `:encoding` - Optionally decode the binary with either the `:base64` or `:hex` encoding scheme.

  ## Examples

      iex> Satoxi.Keys.PubKey.from_binary("03f81f8c8b90f5ec06ee4245eab166e8af903fc73a6dd73636687ef027870abe39", encoding: :hex)
      {:ok, %Satoxi.Keys.PubKey{
        compressed: true,
        point: %Curvy.Point{
          x: 112229328714845468078961951285525025245993969218674417992740440691709714284089,
          y: 691772308660403791193362590139379363593914935665750098177712560871566383255
        }
      }}
  """
  @spec from_binary(binary(), keyword()) :: {:ok, t()} | {:error, term()}
  def from_binary(pubkey, opts \\ []) when is_binary(pubkey) do
    encoding = Keyword.get(opts, :encoding)

    with {:ok, pubkey} <- decode(pubkey, encoding),
         :ok <- valid_pubkey_length?(pubkey) do
      %Key{point: point, compressed: compressed} = Key.from_pubkey(pubkey)

      {:ok, %__MODULE__{compressed: compressed, point: point}}
    end
  end

  @doc """
  Parses the given binary into a `t:Satoxi.Keys.PubKey.t/0`.

  As `from_binary/2` but returns the result or raises an exception.
  """
  @spec from_binary!(binary(), keyword()) :: t()
  def from_binary!(pubkey, opts \\ []) when is_binary(pubkey) do
    case from_binary(pubkey, opts) do
      {:ok, pubkey} ->
        pubkey

      {:error, {:invalid_pubkey, _length} = error} ->
        raise Satoxi.Error, error

      {:error, error} ->
        raise error
    end
  end

  @doc """
  Returns a `t:Satoxi.Keys.PubKey.t/0` derived from the given `t:Satoxi.Keys.PrivKey.t/0`.
  """
  @spec from_privkey(PrivKey.t()) :: t()
  def from_privkey(%PrivKey{d: d, compressed: compressed}) do
    {pubkey, _privkey} = :crypto.generate_key(:ecdh, :secp256k1, d)

    %Key{point: point} = Key.from_pubkey(pubkey)

    %__MODULE__{point: point, compressed: compressed}
  end

  @doc """
  Serialises the given `t:Satoxi.Keys.PrivKey.t/0` into a binary.

  ## Options

  The accepted options are:

  * `:encoding` - Optionally encode the binary with either the `:base64` or `:hex` encoding scheme.

  ## Examples
      
      iex> pubkey = %Satoxi.Keys.PubKey{
      ...> point: %Curvy.Point{
      ...> x: 112229328714845468078961951285525025245993969218674417992740440691709714284089,
      ...> y: 691772308660403791193362590139379363593914935665750098177712560871566383255}, 
      ...> compressed: true}
      iex> Satoxi.Keys.PubKey.to_binary(pubkey, encoding: :hex)
      "03f81f8c8b90f5ec06ee4245eab166e8af903fc73a6dd73636687ef027870abe39"
  """
  @spec to_binary(t(), keyword()) :: binary()
  def to_binary(%__MODULE__{point: point, compressed: compressed}, opts \\ []) do
    encoding = Keyword.get(opts, :encoding)

    %Key{point: point, compressed: compressed}
    |> Key.to_pubkey()
    |> encode(encoding)
  end

  # Checks if pubkey has a valid size
  @spec valid_pubkey_length?(binary()) :: :ok | {:error, {:invalid_pubkey, non_neg_integer()}}
  defp valid_pubkey_length?(pubkey) when byte_size(pubkey) in [33, 65], do: :ok
  defp valid_pubkey_length?(pubkey), do: {:error, {:invalid_pubkey, byte_size(pubkey)}}
end
