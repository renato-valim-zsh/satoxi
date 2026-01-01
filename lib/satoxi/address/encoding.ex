defprotocol Satoxi.Address.Encoding do
  @moduledoc """
  Protocol for encoding Bitcoin addresses to their string representation.

  Each address type (Legacy, `P2SH`, SegWit, etc.) implements this protocol to provide consistent encoding behavior.
  """

  @doc """
  Encodes the address struct to its string representation.

  Returns the address as a `Base58Check` or `Bech32` encoded string, depending on the address type.
  """
  @spec to_string(t) :: String.t()
  def to_string(address)

  @doc """
  Returns the hash or program data used for creating `scriptPubKey`.

  For `P2PKH`/`P2WPKH` addresses, this returns the pubkey hash (20 bytes).
  For `P2SH` addresses, this returns the script hash (20 bytes).
  For `P2WSH` addresses, this returns the witness script hash (32 bytes).
  """
  @spec get_hash(t) :: binary()
  def get_hash(address)
end
