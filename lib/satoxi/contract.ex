defmodule Satoxi.Contract do
  @moduledoc """
  A behaviour module for implementing Bitcoin transaction contracts.

  A Bitcoin transaction contains two sides: inputs and outputs.

  Transaction outputs are script puzzles, called "locking scripts" (sometimes also known as a `ScriptPubKey`) which lock a number of satoshis. 
  Transaction inputs contain an "unlocking script" (or the `ScriptSig`) and unlock the satoshis contained in the previous transaction's outputs.

  Therefore, each locking script is unlocked by a corresponding unlocking script.

  The `Satoxi.Contract` module provides a way to define a locking script and unlocking script in a plain Elixir function. 
  Because it is *just Elixir*, it is trivial to add helper functions and macros to reduce boilerplate and create more complex contract types and scripts.

  ## Defining a contract

  The following module implements a Pay to Public Key Hash contract.
  Implementing a contract is just a case of defining `c:locking_script/2` and `c:unlocking_script/2`.

      defmodule P2PKH do
        @moduledoc "Pay to Public Key Hash contract."
        use Satoxi.Contract

        @impl true
        def locking_script(ctx, %{address: address}) do
          ctx
          |> op_dup
          |> op_hash160
          |> push(address.pubkey_hash)
          |> op_equalverify
          |> op_checksig
        end

        @impl true
        def unlocking_script(ctx, %{keypair: keypair}) do
          ctx
          |> signature(keypair.privkey)
          |> push(Satoxi.PubKey.to_binary(keypair.pubkey))
        end
      end

  ## Locking a contract

  A contract locking script is initiated by calling `lock/2` on the contract module, passing the number of satoshis and a map of parameters expected by `c:locking_script/2` defined in the contract.

      # Initiate the contract locking script
      contract = P2PKH.lock(10_000, %{address: Address.from_pubkey(bob_pubkey)})

      script = Contract.to_script(contract)   # returns the locking script
      output = Contract.to_output(contract)   # returns the full output

  ## Unlocking a contract

  To unlock and spend the contract, a `t:Satoxi.Transaction.UTXO.t/0` is passed to `unlock/2` with the parameters expected by `c:unlocking_script/2` defined in the contract.

      # Initiate the contract unlocking script
      contract = P2PKH.unlock(utxo, %{keypair: keypair})

  Optionally the current transaction [`context`](`t:Satoxi.Contract.ctx/0`) can be given to the [`contract`](`t:Satoxi.Contract.t/0`). 
  This allows the correct [`sighash`](`t:Satoxi.Transaction.Sig.sighash/0`) to be calculated for any signatures.

      # Pass the current transaction ctx
      contract = Contract.put_ctx(contract, {tx, vin})

      # returns the signed input
      input = Contract.to_input(contract)

  ## Building transactions

  The `Satoxi.Contract` behaviour is taken advantage of in the `Satoxi.Transaction.Builder` module, resulting in transaction building semantics that are easy to grasp and pleasing to work with.

      builder = %Satoxi.Transaction.Builder{
        inputs: [
          P2PKH.unlock(utxo, %{keypair: keypair})
        ],
        outputs: [
          P2PKH.lock(10_000, %{address: address})
        ]
      }

      # Returns a fully signed transaction
      Satoxi.Transaction.builder_to_tx(builder)

  For more information, refer to `Satoxi.Transaction.Builder`.
  """
  alias Satoxi.Contract.{P2PKH, P2SH_P2WPKH, P2WPKH}
  alias Satoxi.Script
  alias Satoxi.Transaction
  alias Satoxi.Transaction.Input
  alias Satoxi.Transaction.Output
  alias Satoxi.Transaction.UTXO
  alias Satoxi.Transaction.Witness

  defstruct ctx: nil, mfa: nil, opts: [], subject: nil, script: %Script{}

  @typedoc "Satoxi Contract struct"
  @type t() :: %__MODULE__{
          ctx: ctx() | nil,
          mfa: {module(), atom(), list()},
          opts: keyword(),
          subject: non_neg_integer() | UTXO.t(),
          script: Script.t()
        }

  @typedoc """
  Transaction context.

  A tuple containing a `t:Satoxi.Transaction.t/0` and [`vin`](`t:Satoxi.Transaction.Input.vin/0`). 
  """
  @type ctx() :: {Transaction.t(), non_neg_integer()}

  defmacro __using__(_) do
    quote do
      alias Satoxi.Contract
      use Contract.Helpers

      @behaviour Contract

      @doc """
      Returns a locking script contract with the given parameters.
      """
      @spec lock(non_neg_integer(), map(), keyword()) :: Contract.t()
      def lock(satoshis, %{} = params, opts \\ []) do
        struct(Contract,
          mfa: {__MODULE__, :locking_script, [params]},
          opts: opts,
          subject: satoshis
        )
      end

      @doc """
      Returns an unlocking script contract with the given parameters.
      """
      @spec unlock(UTXO.t(), map(), keyword()) :: Contract.t()
      def unlock(%UTXO{} = utxo, %{} = params, opts \\ []) do
        struct(Contract,
          mfa: {__MODULE__, :unlocking_script, [params]},
          opts: opts,
          subject: utxo
        )
      end
    end
  end

  @doc """
  Callback executed to generate the contract locking script.

  Is passed the [`contract`](`t:Satoxi.Contract.t/0`) and a map of parameters. 
  It must return the updated [`contract`](`t:Satoxi.Contract.t/0`).
  """
  @callback locking_script(t(), map()) :: t()

  @doc """
  Callback executed to generate the contract unlocking script.

  Is passed the [`contract`](`t:Satoxi.Contract.t/0`) and a map of parameters. 
  It must return the updated [`contract`](`t:Satoxi.Contract.t/0`).
  """
  @callback unlocking_script(t(), map()) :: t()

  @doc """
  Callback executed to generate the witness stack for SegWit inputs.

  Is passed the [`contract`](`t:Satoxi.Contract.t/0`) and a map of parameters. 
  It must return a list of binaries representing the witness stack items.

  This callback is only needed for SegWit contracts (`P2WPKH`, `P2WSH`, `P2SH-P2WPKH`, `P2SH-P2WSH`).
  """
  @callback witness_script(t(), map()) :: list(binary())

  @optional_callbacks unlocking_script: 2, witness_script: 2

  @doc """
  Puts the given [`transaction context`](`t:Satoxi.Contract.ctx/0`) (tx and vin) onto the contract.

  When the transaction context is attached, the contract can generate valid signatures. 
  If it is not attached, all signatures will be 71 bytes of zeros.
  """
  @spec put_ctx(t(), ctx()) :: t()
  def put_ctx(%__MODULE__{} = contract, {%Transaction{} = tx, vin}) when is_integer(vin),
    do: Map.put(contract, :ctx, {tx, vin})

  @doc """
  Appends the given value onto the end of the contract script.
  """
  @spec script_push(t(), atom() | integer() | binary()) :: t()
  def script_push(%__MODULE__{} = contract, val),
    do: update_in(contract.script, &Script.push(&1, val))

  @doc """
  Returns the size (in bytes) of the contract script.
  """
  @spec script_size(t()) :: non_neg_integer()
  def script_size(%__MODULE__{} = contract) do
    contract
    |> to_script()
    |> Script.to_binary()
    |> byte_size()
  end

  @doc """
  Compiles the contract and returns the script.
  """
  @spec to_script(t()) :: Script.t()
  def to_script(%__MODULE__{mfa: {mod, fun, args}} = contract) do
    %{script: script} = apply(mod, fun, [contract | args])
    script
  end

  @doc """
  Compiles the unlocking contract and returns the `t:Satoxi.Transaction.Input.t/0`.

  For SegWit contracts, this also includes the witness data.
  """
  @spec to_input(t()) :: Input.t()
  def to_input(%__MODULE__{subject: %UTXO{outpoint: outpoint}} = contract) do
    sequence = Keyword.get(contract.opts, :sequence, 0xFFFFFFFF)
    script = to_script(contract)
    witness_items = to_witness(contract)
    witness = %Witness{items: witness_items}
    struct(Input, outpoint: outpoint, script: script, sequence: sequence, witness: witness)
  end

  @doc """
  Compiles the locking contract and returns the `t:Satoxi.Transaction.Output.t/0`.
  """
  @spec to_output(t()) :: Output.t()
  def to_output(%__MODULE__{subject: satoshis} = contract)
      when is_integer(satoshis) do
    script = to_script(contract)
    struct(Output, satoshis: satoshis, script: script)
  end

  @doc """
  Compiles the witness stack for a SegWit contract.

  Returns an empty list for non-SegWit contracts.
  """
  @spec to_witness(t()) :: list(binary())
  def to_witness(%__MODULE__{mfa: {mod, _fun, [params]}} = contract) do
    if segwit?(contract) do
      mod.witness_script(contract, params)
    else
      []
    end
  end

  @doc """
  Returns true if the contract is a SegWit contract (has witness data).
  """
  @spec segwit?(t()) :: boolean()
  def segwit?(%__MODULE__{mfa: {mod, _fun, _args}}) do
    function_exported?(mod, :witness_script, 2)
  end

  # Convenience functions for P2PKH contracts

  @doc """
  Returns a `P2PKH` locking script contract with the given parameters.

  Delegates to `Satoxi.Contract.P2PKH.lock/3`.
  """
  @spec lock_p2pkh(non_neg_integer(), map(), keyword()) :: t()
  def lock_p2pkh(satoshis, params, opts \\ []), do: P2PKH.lock(satoshis, params, opts)

  @doc """
  Returns a `P2PKH` unlocking script contract with the given parameters.

  Delegates to `Satoxi.Contract.P2PKH.unlock/3`.
  """
  @spec unlock_p2pkh(UTXO.t(), map(), keyword()) :: t()
  def unlock_p2pkh(utxo, params, opts \\ []), do: P2PKH.unlock(utxo, params, opts)

  # Convenience functions for P2WPKH contracts

  @doc """
  Returns a `P2WPKH` locking script contract with the given parameters.

  Delegates to `Satoxi.Contract.P2WPKH.lock/3`.
  """
  @spec lock_p2wpkh(non_neg_integer(), map(), keyword()) :: t()
  def lock_p2wpkh(satoshis, params, opts \\ []), do: P2WPKH.lock(satoshis, params, opts)

  @doc """
  Returns a `P2WPKH` unlocking script contract with the given parameters.

  Delegates to `Satoxi.Contract.P2WPKH.unlock/3`.
  """
  @spec unlock_p2wpkh(UTXO.t(), map(), keyword()) :: t()
  def unlock_p2wpkh(utxo, params, opts \\ []), do: P2WPKH.unlock(utxo, params, opts)

  @doc """
  Returns a `P2SH_P2WPKH` locking script contract with the given parameters.

  Delegates to `Satoxi.Contract.P2SH_P2WPKH.lock/3`.
  """
  @spec lock_p2sh_p2wpkh(non_neg_integer(), map(), keyword()) :: t()
  def lock_p2sh_p2wpkh(satoshis, params, opts \\ []), do: P2SH_P2WPKH.lock(satoshis, params, opts)

  @doc """
  Returns a `P2SH_P2WPKH` unlocking script contract with the given parameters.

  Delegates to `Satoxi.Contract.P2SH_P2WPKH.unlock/3`.
  """
  @spec unlock_p2sh_p2wpkh(UTXO.t(), map(), keyword()) :: t()
  def unlock_p2sh_p2wpkh(utxo, params, opts \\ []),
    do: P2SH_P2WPKH.unlock(utxo, params, opts)
end
