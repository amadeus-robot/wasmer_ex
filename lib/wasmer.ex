defmodule WasmerEx do
  use Rustler,
    otp_app: :wasmer_ex,
    crate: :wasmer_ex
    
  def call(_wasm_bytes, _readonly, _mapenv, _function_name, _function_args), do: :erlang.nif_error(:nif_not_loaded)
end
