defmodule WasmerEx do
  use Rustler,
    otp_app: :wasmer_ex,
    crate: :wasmer_ex
    
  def call(_rpc_pid, _wasm_bytes, _readonly, _mapenv, _function_name, _function_args), do: :erlang.nif_error(:nif_not_loaded)
  
  def respond_to_rust(_request_id, _response), do: :erlang.nif_error(:nif_not_loaded)
  def request_from_rust(_reply_to_pid, _request), do: :erlang.nif_error(:nif_not_loaded)
end
