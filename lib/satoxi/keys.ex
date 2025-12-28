defmodule Satoxi.Keys do
  @moduledoc """
  Key generation, parsing, and encoding utilities for Bitcoin private and public keys.

  Supports [PrivKey](https://hexdocs.pm/satoxi/Satoxi.Keys.PrivKey.html),
  [PubKey](https://hexdocs.pm/satoxi/Satoxi.Keys.PubKey.html) and [ExtKey](https://hexdocs.pm/satoxi/Satoxi.Keys.ExtKey.html) operations commonly
  used in Bitcoin applications.
  """

  # ============================================================================
  # PrivKey
  # ============================================================================

  @doc """
  Generates and returns a new private key.

  See `Satoxi.Keys.PrivKey.new/1` for details.
  """
  defdelegate new_privkey(opts \\ []),
    to: Satoxi.Keys.PrivKey,
    as: :new

  @doc """
  Parses a binary into a private key.

  See `Satoxi.Keys.PrivKey.from_binary/2` for details.
  """
  defdelegate privkey_from_binary(privkey, opts \\ []),
    to: Satoxi.Keys.PrivKey,
    as: :from_binary

  @doc """
  Parses a binary into a private key.

  As `privkey_from_binary/2` but returns the result or raises an exception.
  """
  defdelegate privkey_from_binary!(privkey, opts \\ []),
    to: Satoxi.Keys.PrivKey,
    as: :from_binary!

  @doc """
  Serialises a private key into a binary.

  See `Satoxi.Keys.PrivKey.to_binary/2` for details.
  """
  defdelegate privkey_to_binary(privkey, opts \\ []),
    to: Satoxi.Keys.PrivKey,
    as: :to_binary

  @doc """
  Decodes a WIF string into a private key.

  See `Satoxi.Keys.PrivKey.from_wif/1` for details.
  """
  defdelegate privkey_from_wif(wif),
    to: Satoxi.Keys.PrivKey,
    as: :from_wif

  @doc """
  Decodes a WIF string into a private key.

  As `privkey_from_wif/1` but returns the result or raises an exception.
  """
  defdelegate privkey_from_wif!(wif),
    to: Satoxi.Keys.PrivKey,
    as: :from_wif!

  @doc """
  Encodes a private key as a WIF string.

  See `Satoxi.Keys.PrivKey.to_wif/1` for details.
  """
  defdelegate privkey_to_wif(privkey),
    to: Satoxi.Keys.PrivKey,
    as: :to_wif

  @doc """
  Encodes a private key as a WIF string.

  As `privkey_to_wif/1` but returns the result or raises an exception.
  """
  defdelegate privkey_to_wif!(privkey),
    to: Satoxi.Keys.PrivKey,
    as: :to_wif!

  # ============================================================================
  # PubKey
  # ============================================================================

  @doc """
  Parses a binary into a public key.

  See `Satoxi.Keys.PubKey.from_binary/2` for details.
  """
  defdelegate pubkey_from_binary(pubkey, opts \\ []),
    to: Satoxi.Keys.PubKey,
    as: :from_binary

  @doc """
  Parses a binary into a public key.

  As `pubkey_from_binary/2` but returns the result or raises an exception.
  """
  defdelegate pubkey_from_binary!(pubkey, opts \\ []),
    to: Satoxi.Keys.PubKey,
    as: :from_binary!

  @doc """
  Returns a public key derived from the given private key.

  See `Satoxi.Keys.PubKey.from_privkey/1` for details.
  """
  defdelegate pubkey_from_privkey(privkey),
    to: Satoxi.Keys.PubKey,
    as: :from_privkey

  @doc """
  Serialises a public key into a binary.

  See `Satoxi.Keys.PubKey.to_binary/2` for details.
  """
  defdelegate pubkey_to_binary(pubkey, opts \\ []),
    to: Satoxi.Keys.PubKey,
    as: :to_binary

  @doc """
  Generates and returns a new keypair.

  See `Satoxi.Keys.KeyPair.new/1` for details.
  """
  defdelegate new_keypair(opts \\ []), to: Satoxi.Keys.KeyPair, as: :new

  @doc """
  Returns a keypair from the given private key.

  See `Satoxi.Keys.KeyPair.from_privkey/1` for details.
  """
  defdelegate keypair_from_privkey(privkey), to: Satoxi.Keys.KeyPair, as: :from_privkey

  # ============================================================================
  # ExtKey
  # ============================================================================

  @doc """
  Generates and returns a new random extended key.

  See `Satoxi.Keys.ExtKey.new/0` for details.
  """
  defdelegate new_extkey(),
    to: Satoxi.Keys.ExtKey,
    as: :new

  @doc """
  Generates and returns an extended key from the given binary seed.

  See `Satoxi.Keys.ExtKey.from_seed/2` for details.
  """
  defdelegate extkey_from_seed(seed, opts \\ []),
    to: Satoxi.Keys.ExtKey,
    as: :from_seed

  @doc """
  Generates and returns an extended key from the given binary seed.

  As `extkey_from_seed/2` but returns the result or raises an exception.
  """
  defdelegate extkey_from_seed!(seed, opts \\ []),
    to: Satoxi.Keys.ExtKey,
    as: :from_seed!

  @doc """
  Decodes the given xprv or xpub string into an extended key.

  See `Satoxi.Keys.ExtKey.from_string/1` for details.
  """
  defdelegate extkey_from_string(data),
    to: Satoxi.Keys.ExtKey,
    as: :from_string

  @doc """
  Decodes the given xprv or xpub string into an extended key.

  As `extkey_from_string/1` but returns the result or raises an exception.
  """
  defdelegate extkey_from_string!(data),
    to: Satoxi.Keys.ExtKey,
    as: :from_string!

  @doc """
  Converts the given extended key into a public extended key.

  See `Satoxi.Keys.ExtKey.to_public/1` for details.
  """
  defdelegate extkey_to_public(extkey),
    to: Satoxi.Keys.ExtKey,
    as: :to_public

  @doc """
  Encodes the given extended key into an xprv or xpub string.

  See `Satoxi.Keys.ExtKey.to_string/1` for details.
  """
  defdelegate extkey_to_string(extkey),
    to: Satoxi.Keys.ExtKey,
    as: :to_string

  @doc """
  Derives a new extended key from the given extended key and derivation path.

  See `Satoxi.Keys.ExtKey.derive/2` for details.
  """
  defdelegate extkey_derive(extkey, path),
    to: Satoxi.Keys.ExtKey,
    as: :derive
end
