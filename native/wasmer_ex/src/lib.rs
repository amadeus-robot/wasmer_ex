use rustler::types::{Binary, OwnedBinary, LocalPid};
use rustler::{Encoder, Error, Env, Term, NifResult, ResourceArc, OwnedEnv, Atom};

use wasmer::{
    imports,
    wasmparser::Operator,
    sys::{EngineBuilder, Features},
    Function, FunctionEnv, FunctionEnvMut, FunctionType, Global, Instance, Memory, MemoryType,
    MemoryView, Module, Pages, Store, Type, Value,
    RuntimeError
};
use wasmer_compiler_singlepass::Singlepass;

use std::sync::Arc;
use wasmer_middlewares::{
    metering::{get_remaining_points, set_remaining_points, MeteringPoints},
    Metering,
};

use std::collections::HashMap;

use rand::random;
use std::{sync::{LazyLock, Mutex, mpsc}};
static REQ_REGISTRY: LazyLock<Mutex<HashMap<u64, mpsc::Sender<String>>>> = 
    LazyLock::new(|| {
        Mutex::new(HashMap::new())
    });

mod atoms {
    rustler::atoms! {
        ok,
        error,
        nil,
        rust_request
    }
}

#[derive(Debug, Clone, Copy)]
struct ExitCode(u32);

#[derive(Clone)]
struct HostEnv {
    memory: Option<Memory>,
    readonly: bool,
    error: Option<Vec<u8>>,
    return_value: Option<Vec<u8>>,
    logs: Vec<Vec<u8>>,
    rpc_pid: LocalPid,
}

//RPC LOL
#[rustler::nif]
fn respond_to_rust<'a>(env: Env<'a>, request_id: u64, response: String) -> NifResult<Term> {
    let mut map = REQ_REGISTRY.lock().unwrap();

    if let Some(tx) = map.remove(&request_id) {
        let _ = tx.send(response);
        Ok(atoms::ok().encode(env))
    } else {
        Ok((atoms::error(), "no_request_found").encode(env))
    }
}

fn request_from_rust(reply_to_pid: LocalPid, request: String) -> i64 {
    let mut env = OwnedEnv::new();

    let (tx, rx) = mpsc::channel::<String>();
    let request_id = rand::random::<u64>();
    {
        let mut map = REQ_REGISTRY.lock().unwrap();
        map.insert(request_id, tx);
    }


    let payload = (
        atoms::rust_request(),
        request_id,
        request
    );
    let _ = env.send_and_clear(&reply_to_pid, |env| payload.encode(env));
    //env.send(&reply_to_pid, payload);

    match rx.recv_timeout(std::time::Duration::from_secs(3)) {
        Ok(response) => {
            // Return {:ok, response} to the Elixir caller
            println!("rpc OK");
            1
        }
        Err(_) => {
            println!("rpc TIMEOUT");

            // If we time out or there's an error, remove from the registry so we don't leak.
            let mut map = REQ_REGISTRY.lock().unwrap();
            map.remove(&request_id);
            0
        }
    }
}


//AssemblyScript specific
fn abort_implementation(mut env: FunctionEnvMut<HostEnv>, _message: i32, _fileName: i32, line: i32, column: i32) -> Result<(), RuntimeError> {
    let (data, store) = env.data_and_store_mut();
    //data.error = Some(b"abort".to_vec());
    //print!("abort>> line: {} column: {} \n", line, column);
    Err(RuntimeError::new("abort"))
}

fn import_log_implementation(mut env: FunctionEnvMut<HostEnv>, ptr: i32, len: i32) -> Result<(), RuntimeError> {
    let (data, store) = env.data_and_store_mut();
    let memory = match &data.memory {
        Some(mem) => mem,
        None => { return Err(RuntimeError::new("invalid_memory")) }
    };
    let view: MemoryView = memory.view(&store);

    let mut buffer = vec![0u8; len as usize];
    match view.read(ptr as u64, &mut buffer) {
        Ok(_) => {
            //print!("log>> {} \n", String::from_utf8_lossy(&buffer));
            data.logs.push(buffer);
            Ok(())
        }
        Err(read_err) => { Err(RuntimeError::new("invalid_memory")) }
    }
}

fn import_return_value_implementation(mut env: FunctionEnvMut<HostEnv>, ptr: i32, len: i32) -> Result<(), RuntimeError> {
    let (data, store) = env.data_and_store_mut();
    let memory = match &data.memory {
        Some(mem) => mem,
        None => { return Err(RuntimeError::new("invalid_memory")) }
    };
    let view: MemoryView = memory.view(&store);

    let mut buffer = vec![0u8; len as usize];
    match view.read(ptr as u64, &mut buffer) {
        Ok(_) => {
            //println!("return was {}", String::from_utf8_lossy(&buffer));
            data.return_value = Some(buffer);
            Err(RuntimeError::new("return"))
        }
        Err(read_err) => { Err(RuntimeError::new("invalid_memory")) }
    }
}

fn import_kv_increment_implementation(mut env: FunctionEnvMut<HostEnv>, ptr: i32, len: i32, amount: i64) -> Result<i64, RuntimeError> {
    let (data, store) = env.data_and_store_mut();
    if (data.readonly) {
        return Err(RuntimeError::new("read_only"))
    }
    let memory = match &data.memory {
        Some(mem) => mem,
        None => { return Err(RuntimeError::new("invalid_memory")) }
    };
    let view: MemoryView = memory.view(&store);

    let mut buffer = vec![0u8; len as usize];
    match view.read(ptr as u64, &mut buffer) {
        Ok(_) => {
            //println!("key was {} {}", String::from_utf8_lossy(&buffer), amount);

            Ok(amount)
        }
        Err(read_err) => { Err(RuntimeError::new("invalid_memory")) }
    }
}

fn import_call_implementation(mut env: FunctionEnvMut<HostEnv>, module_ptr: i32, module_len: i32, 
    function_ptr: i32, function_len: i32, args_ptr: i32, args_len: i32) -> Result<i32, RuntimeError> {
    let (data, store) = env.data_and_store_mut();
    let memory = match &data.memory {
        Some(mem) => mem,
        None => { return Err(RuntimeError::new("invalid_memory")) }
    };
    let view: MemoryView = memory.view(&store);

    let mut buffer = vec![0u8; module_len as usize];
    match view.read(module_ptr as u64, &mut buffer) {
        Ok(_) => {
            let lol = request_from_rust(data.rpc_pid, "hello".to_string());
            println!("lolao {}", lol);
            //let _ = call_inner(env.)
            Ok(1)
        }
        Err(read_err) => { Err(RuntimeError::new("invalid_memory")) }
    }
}

fn cost_function(operator: &Operator) -> u64 {
    2
    /*match operator {
        Operator::Loop { .. }
        | Operator::Block { .. }
        | Operator::If { .. }
        | Operator::Else { .. }
        | Operator::End { .. }
        | Operator::Br { .. }
        | Operator::BrIf { .. }
        | Operator::Return { .. }
        | Operator::Unreachable { .. } => 1,

        Operator::Call { .. } | Operator::CallIndirect { .. } => 5,

        Operator::I32Load { .. }
        | Operator::I64Load { .. }
        | Operator::F32Load { .. }
        | Operator::F64Load { .. }
        | Operator::I32Store { .. }
        | Operator::I64Store { .. }
        | Operator::F32Store { .. }
        | Operator::F64Store { .. } => 3,

        _ => 2,
    }*/
}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn call<'a>(env: Env<'a>, rpc_pid: LocalPid, wasm_bytes: Binary, readonly: bool, mapenv: Term<'a>, function_name: String, function_args: Vec<Term<'a>>) -> Result<rustler::Term<'a>, rustler::Error> {
    //let wasm_vec = wasm_bytes.as_slice().to_vec();
    
    //let mapenv_decoded: HashMap<String, Term<'a>> = mapenv.decode()?;

    //let (s1, s2, str_vec, number, bytes_vec) = call_inner(env, wasm_bytes, readonly, mapenv, function_name, function_args);
    //Ok((s1, s2, str_vec, number, bytes_vec).encode(env))

    call_inner(env, rpc_pid, wasm_bytes, readonly, mapenv, function_name, function_args)
}

fn call_inner<'a>(
    env: Env<'a>,
    rpc_pid: LocalPid,
    wasm_bytes: Binary,
    readonly: bool,
    //mapenv: HashMap<String, Term<'a>>,
    mapenv: Term<'a>,
    function_name: String,
    function_args: Vec<Term<'a>>,
//) -> (String, String, Vec<String>, u64, Vec<u8>) {
) -> Result<rustler::Term<'a>, rustler::Error> {

    let metering = Arc::new(Metering::new(3_000, cost_function));
    let mut compiler = Singlepass::default();
    compiler.canonicalize_nans(true);

    use wasmer::CompilerConfig;
    compiler.push_middleware(metering);

    let mut features = Features::new();
    //features.bulk_memory(false); #required for modern compilers to WASM
    features.threads(false);
    features.reference_types(false);
    features.simd(false);
    features.multi_value(false);
    features.tail_call(false);
    features.module_linking(false);
    features.multi_memory(false);
    features.memory64(false);

    let engine = EngineBuilder::new(compiler).set_features(Some(features));
    let mut store = Store::new(engine);

    let module = Module::new(&store, &wasm_bytes.as_slice()).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;

    let memory = Memory::new(&mut store, MemoryType::new(Pages(8), None, false)).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    // memory.view(&mut store).copy_to_memory

    let map: HashMap<String, Term> = mapenv.decode()?;

    let it1 = map.get("seed").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(10_000, &((32 as i32).to_le_bytes())).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    memory.view(&mut store).write(10_004, it1).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it2 = map.get("entry_signer").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(10_100, &((48 as i32).to_le_bytes())).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    memory.view(&mut store).write(10_104, it2).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it3 = map.get("entry_prev_hash").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(10_200, &((32 as i32).to_le_bytes())).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    memory.view(&mut store).write(10_204, it3).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it4 = map.get("entry_vr").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(10_300, &((96 as i32).to_le_bytes())).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    memory.view(&mut store).write(10_304, it4).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it5 = map.get("entry_dr").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(10_400, &((96 as i32).to_le_bytes())).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    memory.view(&mut store).write(10_404, it5).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it6 = map.get("tx_signer").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(11_000, &((48 as i32).to_le_bytes())).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    memory.view(&mut store).write(11_004, it6).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it7 = map.get("current_account").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(12_000, &((it7.len() as i32).to_le_bytes())).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    memory.view(&mut store).write(12_004, it7).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it8 = map.get("caller_account").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(13_000, &((it8.len() as i32).to_le_bytes())).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    memory.view(&mut store).write(13_004, it8).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;

    let mut offset: u64 = 20_000;
    let mut wasm_args: Vec<Value> = Vec::with_capacity(function_args.len());

    for term in &function_args {
        if let Ok(i) = term.decode::<i64>() {
            wasm_args.push(Value::I64(i));
        } else if let Ok(b) = term.decode::<Binary>() {
            let bytes = b.as_slice();
            let length = bytes.len();

            memory
                .view(&mut store)
                .write(offset, &(length as i32).to_le_bytes())
                .map_err(|err| Error::Term(Box::new(err.to_string())))?;
            memory
                .view(&mut store)
                .write(offset + 4, bytes)
                .map_err(|err| Error::Term(Box::new(err.to_string())))?;

            let pointer = offset as i32;
            offset += 4 + length as u64;
            wasm_args.push(Value::I32(pointer));
        } else {
            return Err(Error::BadArg);
        }
    }

    let host_env = FunctionEnv::new(&mut store, HostEnv { memory: None, error: None, return_value: None, logs: vec![], readonly: readonly, rpc_pid: rpc_pid});
    let import_log_func = Function::new_typed_with_env(&mut store, &host_env, import_log_implementation);
    let import_call_func = Function::new_typed_with_env(&mut store, &host_env, import_call_implementation);
    let import_return_value_func = Function::new_typed_with_env(&mut store, &host_env, import_return_value_implementation);
    
    let import_kv_increment_func = Function::new_typed_with_env(&mut store, &host_env, import_kv_increment_implementation);

    let abort_func = Function::new_typed_with_env(&mut store, &host_env, abort_implementation);


    let import_object = imports! {
        "env" => {
            "memory" => memory,
            "seed_ptr" => Global::new(&mut store, Value::I32(10_000)),
            "entry_signer_ptr" => Global::new(&mut store, Value::I32(10_100)),
            "entry_prev_hash_ptr" => Global::new(&mut store, Value::I32(10_200)),
            "entry_slot" => Global::new(&mut store, Value::I64(map.get("entry_slot").ok_or(Error::BadArg)?.decode::<i64>()?)),
            "entry_prev_slot" => Global::new(&mut store, Value::I64(map.get("entry_prev_slot").ok_or(Error::BadArg)?.decode::<i64>()?)),
            "entry_height" => Global::new(&mut store, Value::I64(map.get("entry_height").ok_or(Error::BadArg)?.decode::<i64>()?)),
            "entry_epoch" => Global::new(&mut store, Value::I64(map.get("entry_epoch").ok_or(Error::BadArg)?.decode::<i64>()?)),
            "entry_vr_ptr" => Global::new(&mut store, Value::I32(10_300)),
            "entry_dr_ptr" => Global::new(&mut store, Value::I32(10_400)),

            "tx_signer_ptr" => Global::new(&mut store, Value::I32(11_000)),
            "tx_nonce" => Global::new(&mut store, Value::I64(map.get("tx_nonce").ok_or(Error::BadArg)?.decode::<i64>()?)),

            "current_account_ptr" => Global::new(&mut store, Value::I32(12_000)),
            "caller_account_ptr" => Global::new(&mut store, Value::I32(13_000)),

            "import_log" => import_log_func,
            "import_return_value" => import_return_value_func,

            "import_call" => import_call_func,

            //storage
            "import_kv_put" => Function::new_typed(&mut store, || println!("called_kv_put_in_rust")),
            "import_kv_put_int" => Function::new_typed(&mut store, || println!("called_kv_put_in_rust")),
            "import_kv_increment" => import_kv_increment_func,
            "import_kv_delete" => Function::new_typed(&mut store, || println!("called_kv_put_in_rust")),
            "import_kv_get" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),
            "import_kv_get_prev" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),
            "import_kv_get_prefix" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),
            "import_kv_exists" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),
            "import_kv_clear" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),

            //AssemblyScript specific
            "abort" => abort_func,
            //"seed" => abort_func,
        }
    };

    let instance = Instance::new(&mut store, &module, &import_object).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;

    let instance_memory = instance.exports.get_memory("memory").map_err(|err| {
        rustler::Error::Term(Box::new(format!(
            "Failed to get 'memory' export from Wasm instance: {}",
            err
        )))
    })?;
    host_env.as_mut(&mut store).memory = Some(instance_memory.clone()); // Update env

    let entry_to_call = instance.exports.get_function(&function_name).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let call_result = entry_to_call.call(&mut store, &wasm_args);

    let remaining_u64 = match get_remaining_points(&mut store, &instance) {
        MeteringPoints::Remaining(value) => value,
        MeteringPoints::Exhausted => { 0 }
    };

    match call_result {
        Err(err) => {
            //println!("9 {:?}", get_remaining_points(&mut store, &instance));

            let data = host_env.as_ref(&store); // Read-only access to HostEnv data

            //println!("wtf {:?} {:?} {:?} {:?} {}", data.error, data.return_value, err.message(), err.to_string(), String::from_utf8_lossy(data.return_value.as_ref().unwrap()));
        
            let encoded_logs: Vec<Binary> = data.logs.iter().map(|bytes| {
                let mut bin = OwnedBinary::new(bytes.len()).unwrap();
                bin.as_mut_slice().copy_from_slice(bytes);
                Binary::from_owned(bin, env)
            })
            .collect();

            let data_error = match &data.error {
                Some(bytes) => {
                    let mut owned = OwnedBinary::new(bytes.len()).unwrap();
                    owned.as_mut_slice().copy_from_slice(&bytes);
                    Binary::from_owned(owned, env).encode(env)
                },
                None => { atoms::nil().encode(env) }
            };

            let return_value = match &data.return_value {
                Some(bytes) => {
                    let mut owned = OwnedBinary::new(bytes.len()).unwrap();
                    owned.as_mut_slice().copy_from_slice(&bytes);
                    Binary::from_owned(owned, env).encode(env)
                },
                None => { atoms::nil().encode(env) }
            };
            Ok((err.message(), data_error, encoded_logs, remaining_u64, return_value).encode(env))
        }
        Ok(_values) => {
            //println!("99 {:?}", get_remaining_points(&mut store, &instance));

            let data = host_env.as_ref(&store); // Read-only access to HostEnv data

            let encoded_logs: Vec<Binary> = data.logs.iter().map(|bytes| {
                let mut bin = OwnedBinary::new(bytes.len()).unwrap();
                bin.as_mut_slice().copy_from_slice(bytes);
                Binary::from_owned(bin, env)
            })
            .collect();

            Ok((atoms::nil(), atoms::nil(), encoded_logs, remaining_u64, atoms::nil()).encode(env))
        }
    }
    //println!("wtf {}", extract_i32_ref(&result1[0]));
}

fn extract_i32_ref(val: &Value) -> i32 {
    match val {
        Value::I32(i) => *i,
        _ => panic!("Expected Value::I32, got something else"),
    }
}

fn extract_i64_ref(val: &Value) -> i64 {
    match val {
        Value::I64(i) => *i,
        _ => panic!("Expected Value::I64, got something else"),
    }
}

rustler::init!("Elixir.WasmerEx");

