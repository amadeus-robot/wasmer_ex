defmodule WasmerEx do
  use Rustler,
    otp_app: :wasmer_ex,
    crate: :wasmer_ex
    
  def call(_rpc_pid, _mapenv, _wasm_bytes, _function_name, _function_args), do: :erlang.nif_error(:nif_not_loaded)
  def validate_contract(_mapenv, _wasm_bytes), do: :erlang.nif_error(:nif_not_loaded)
  
  def respond_to_rust_storage_kv_get(_request_id, _response), do: :erlang.nif_error(:nif_not_loaded)
  def respond_to_rust_storage_kv_exists(_request_id, _response), do: :erlang.nif_error(:nif_not_loaded)
  def respond_to_rust_storage_kv_get_prev_next(_request_id, _response), do: :erlang.nif_error(:nif_not_loaded)
  def respond_to_rust_storage(_request_id, _response), do: :erlang.nif_error(:nif_not_loaded)
  
  def respond_to_rust_call(_request_id, _main_error, _logs, _exec_cost, _result), do: :erlang.nif_error(:nif_not_loaded)
end
