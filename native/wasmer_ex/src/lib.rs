use rustler::types::{Binary, OwnedBinary, LocalPid};
use rustler::{Encoder, Error, Env, Term, NifResult, ResourceArc, OwnedEnv, Atom};

use wasmer::{
    imports,
    wasmparser::Operator,
    sys::{EngineBuilder, Features},
    Function, FunctionEnv, FunctionEnvMut, FunctionType, Global, Instance, Memory, MemoryType, Engine,
    MemoryView, Module, Pages, Store, Type, Value,
    RuntimeError
};
use wasmer_compiler_singlepass::Singlepass;

use std::sync::{Arc, Mutex, OnceLock};
use wasmer_middlewares::{
    metering::{get_remaining_points, set_remaining_points, MeteringPoints},
    Metering,
};

use std::collections::HashMap;

use sha2::{Sha256, Digest};
static MODULE_CACHE: OnceLock<Mutex<HashMap<[u8; 32], (Arc<Engine>, Arc<Module>)>>> = OnceLock::new();

use rand::random;
use std::{sync::{LazyLock, mpsc}};
static REQ_REGISTRY_STORAGE_KV_GET: LazyLock<Mutex<HashMap<u64, mpsc::Sender< Option<Vec<u8>> >>>> = 
    LazyLock::new(|| {
        Mutex::new(HashMap::new())
    });
static REQ_REGISTRY_STORAGE_KV_EXISTS: LazyLock<Mutex<HashMap<u64, mpsc::Sender< bool >>>> = 
    LazyLock::new(|| {
        Mutex::new(HashMap::new())
    });
static REQ_REGISTRY_STORAGE_KV_GET_PREV_NEXT: LazyLock<Mutex<HashMap<u64, mpsc::Sender< (Option<Vec<u8>>, Option<Vec<u8>>) >>>> = 
    LazyLock::new(|| {
        Mutex::new(HashMap::new())
    });

static REQ_REGISTRY_STORAGE: LazyLock<Mutex<HashMap<u64, mpsc::Sender< Vec<u8> >>>> = 
    LazyLock::new(|| {
        Mutex::new(HashMap::new())
    });

static REQ_REGISTRY_CALL: LazyLock<Mutex<HashMap<u64, mpsc::Sender< (Vec<u8>, Vec<u8>, Vec<Vec<u8>>, u64, Vec<u8>) >>>> = 
    LazyLock::new(|| {
        Mutex::new(HashMap::new())
    });

mod atoms {
    rustler::atoms! {
        ok,
        error,
        nil,

        rust_request_call,

        rust_request_storage_kv_put,
        rust_request_storage_kv_increment,
        rust_request_storage_kv_delete,
        rust_request_storage_kv_clear,

        rust_request_storage_kv_get,
        rust_request_storage_kv_exists,
        rust_request_storage_kv_get_prev,
        rust_request_storage_kv_get_next,
    }
}

#[derive(Debug, Clone, Copy)]
struct ExitCode(u32);

#[derive(Clone)]
//struct HostEnv<'a> {
struct HostEnv {
    memory: Option<Memory>,
    readonly: bool,
    error: Option<Vec<u8>>,
    return_value: Option<Vec<u8>>,
    logs: Vec<Vec<u8>>,
    current_account: Vec<u8>,
    rpc_pid: LocalPid,
    //env: Env<'a>
    instance: Option<Arc<Instance>>,
}
//unsafe impl Sync for HostEnv<'_> {}
//unsafe impl Send for HostEnv<'_> {}



//RPC LOL
#[rustler::nif]
fn respond_to_rust_storage_kv_get<'a>(env: Env<'a>, request_id: u64, response: Option<Vec<u8>>) -> NifResult<Term> {
    let mut map = REQ_REGISTRY_STORAGE_KV_GET.lock().unwrap();

    if let Some(tx) = map.remove(&request_id) {
        let _ = tx.send(response);
        Ok(atoms::ok().encode(env))
    } else {
        Ok((atoms::error(), "no_request_found").encode(env))
    }
}
#[rustler::nif]
fn respond_to_rust_storage_kv_exists<'a>(env: Env<'a>, request_id: u64, response: bool) -> NifResult<Term> {
    let mut map = REQ_REGISTRY_STORAGE_KV_EXISTS.lock().unwrap();

    if let Some(tx) = map.remove(&request_id) {
        let _ = tx.send(response);
        Ok(atoms::ok().encode(env))
    } else {
        Ok((atoms::error(), "no_request_found").encode(env))
    }
}
#[rustler::nif]
fn respond_to_rust_storage_kv_get_prev_next<'a>(env: Env<'a>, request_id: u64, response: (Option<Vec<u8>>, Option<Vec<u8>>)) -> NifResult<Term> {
    let mut map = REQ_REGISTRY_STORAGE_KV_GET_PREV_NEXT.lock().unwrap();

    if let Some(tx) = map.remove(&request_id) {
        let _ = tx.send(response);
        Ok(atoms::ok().encode(env))
    } else {
        Ok((atoms::error(), "no_request_found").encode(env))
    }
}

#[rustler::nif]
fn respond_to_rust_storage<'a>(env: Env<'a>, request_id: u64, response: Vec<u8>) -> NifResult<Term> {
    let mut map = REQ_REGISTRY_STORAGE.lock().unwrap();

    if let Some(tx) = map.remove(&request_id) {
        let _ = tx.send(response);
        Ok(atoms::ok().encode(env))
    } else {
        Ok((atoms::error(), "no_request_found").encode(env))
    }
}

#[rustler::nif]
fn respond_to_rust_call<'a>(env: Env<'a>, request_id: u64, main_error: Vec<u8>, user_error: Vec<u8>, logs: Vec<Vec<u8>>, exec_cost: u64, result: Vec<u8>) -> NifResult<Term> {
    let mut map = REQ_REGISTRY_CALL.lock().unwrap();

    if let Some(tx) = map.remove(&request_id) {
        let _ = tx.send( (main_error, user_error, logs, exec_cost, result) );
        Ok(atoms::ok().encode(env))
    } else {
        Ok((atoms::error(), "no_request_found").encode(env))
    }
}

//AssemblyScript specific
fn abort_implementation(mut env: FunctionEnvMut<HostEnv>, _message: i32, _fileName: i32, line: i32, column: i32) -> Result<(), RuntimeError> {
    let (data, store) = env.data_and_store_mut();
    Err(RuntimeError::new("abort"))
}

fn import_log_implementation(mut env: FunctionEnvMut<HostEnv>, ptr: i32, len: i32) -> Result<(), RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();

    //charge exec cost
    let instance_arc = data.instance.as_ref().ok_or_else(|| RuntimeError::new("invalid_instance"))?;
    let mut remaining_u64 = match get_remaining_points(&mut store, instance_arc.as_ref()) {
        MeteringPoints::Remaining(value) => value,
        MeteringPoints::Exhausted => { 0 }
    };

    let storage_cost = (len as u64) * 1000;
    remaining_u64 = remaining_u64 - storage_cost;
    if remaining_u64 <= 0 { return Err(RuntimeError::new("unreachable")) };
    set_remaining_points(&mut store, instance_arc.as_ref(), remaining_u64);


    let Some(memory) = &data.memory else { return Err(RuntimeError::new("invalid_memory")) };
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
    let (data, mut store) = env.data_and_store_mut();
    
    //charge exec cost
    let instance_arc = data.instance.as_ref().ok_or_else(|| RuntimeError::new("invalid_instance"))?;
    let mut remaining_u64 = match get_remaining_points(&mut store, instance_arc.as_ref()) {
        MeteringPoints::Remaining(value) => value,
        MeteringPoints::Exhausted => { 0 }
    };

    let storage_cost = (len as u64) * 1000;
    remaining_u64 = remaining_u64 - storage_cost;
    if remaining_u64 <= 0 { return Err(RuntimeError::new("unreachable")) };
    set_remaining_points(&mut store, instance_arc.as_ref(), remaining_u64);


    let Some(memory) = &data.memory else { return Err(RuntimeError::new("invalid_memory")) };
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



//MOVE THESE OUT TO SEPERATA FILES
//KVGET
fn request_from_rust_storage_kv_get(reply_to_pid: LocalPid, key: Vec<u8>) -> (std::sync::mpsc::Receiver< Option<Vec<u8>> >, u64) {
    let (tx, rx) = mpsc::channel::<Option<Vec<u8>>>();
    let request_id = rand::random::<u64>();
    {
        let mut map = REQ_REGISTRY_STORAGE_KV_GET.lock().unwrap();
        map.insert(request_id, tx);
    }

    std::thread::spawn(move || {
        let mut env = OwnedEnv::new();
        let _ = env.send_and_clear(&reply_to_pid, |cenv| {
            let mut owned_key = OwnedBinary::new(key.len()).unwrap();
            owned_key.as_mut_slice().copy_from_slice(&key);
            let payload = (
                atoms::rust_request_storage_kv_get(), 
                request_id, 
                Binary::from_owned(owned_key, cenv));
            payload.encode(cenv)
        });
    });

    (rx, request_id)
}
fn import_storage_kv_get_implementation(mut env: FunctionEnvMut<HostEnv>, key_ptr: i32, key_len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();

    let instance_arc = data.instance.as_ref().ok_or_else(|| RuntimeError::new("invalid_instance"))?;
    let mut remaining_u64 = match get_remaining_points(&mut store, instance_arc.as_ref()) {
        MeteringPoints::Remaining(value) => value,
        MeteringPoints::Exhausted => { 0 }
    };

    let storage_cost = (48 + (key_len as u64)) * 100;
    remaining_u64 = remaining_u64 - storage_cost;
    if remaining_u64 <= 0 { return Err(RuntimeError::new("unreachable")) };
    set_remaining_points(&mut store, instance_arc.as_ref(), remaining_u64);

    let Some(memory) = &data.memory else { return Err(RuntimeError::new("invalid_memory")) };
    let view: MemoryView = memory.view(&store);

    let mut key_buffer_suffix = vec![0u8; key_len as usize];
    let Ok(_) = view.read(key_ptr as u64, &mut key_buffer_suffix) else { return Err(RuntimeError::new("invalid_memory")) };
    let mut key_buffer = data.current_account.clone();
    key_buffer.extend_from_slice(&key_buffer_suffix);

    let (rx, request_id) = request_from_rust_storage_kv_get(data.rpc_pid, key_buffer);

    match rx.recv_timeout(std::time::Duration::from_secs(6)) {
        Ok(option_response) => { 
            match option_response {
                Some(response) => {
                    println!("rpc OK with Some(...)");
                    let _ = view.write(30_000, &((response.len() as i32).to_le_bytes())).map_err(|err| RuntimeError::new("invalid_memory"));
                    let _ = view.write(30_004, &response).map_err(|err| RuntimeError::new("invalid_memory"));
                    Ok(30_000)
                },
                None => {
                    println!("rpc OK with None");
                    let _ = view.write(30_000, &(-1 as i32).to_le_bytes()).map_err(|err| RuntimeError::new("invalid_memory"));
                    Ok(30_000)
                }
            }
        },
        Err(_) => {
            let mut map = REQ_REGISTRY_STORAGE_KV_GET.lock().unwrap();
            map.remove(&request_id);
            Err(RuntimeError::new("no_elixir_callback"))
        }
    }
}

///EXISTS
fn request_from_rust_storage_kv_exists(reply_to_pid: LocalPid, key: Vec<u8>) -> (std::sync::mpsc::Receiver< bool >, u64) {
    let (tx, rx) = mpsc::channel::<bool>();
    let request_id = rand::random::<u64>();
    {
        let mut map = REQ_REGISTRY_STORAGE_KV_EXISTS.lock().unwrap();
        map.insert(request_id, tx);
    }

    std::thread::spawn(move || {
        let mut env = OwnedEnv::new();
        let _ = env.send_and_clear(&reply_to_pid, |cenv| {
            let mut owned_key = OwnedBinary::new(key.len()).unwrap();
            owned_key.as_mut_slice().copy_from_slice(&key);
            let payload = (
                atoms::rust_request_storage_kv_exists(), 
                request_id, 
                Binary::from_owned(owned_key, cenv));
            payload.encode(cenv)
        });
    });

    (rx, request_id)
}
fn import_storage_kv_exists_implementation(mut env: FunctionEnvMut<HostEnv>, key_ptr: i32, key_len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();

    let instance_arc = data.instance.as_ref().ok_or_else(|| RuntimeError::new("invalid_instance"))?;
    let mut remaining_u64 = match get_remaining_points(&mut store, instance_arc.as_ref()) {
        MeteringPoints::Remaining(value) => value,
        MeteringPoints::Exhausted => { 0 }
    };

    let storage_cost = (48 + (key_len as u64)) * 100;
    remaining_u64 = remaining_u64 - storage_cost;
    if remaining_u64 <= 0 { return Err(RuntimeError::new("unreachable")) };
    set_remaining_points(&mut store, instance_arc.as_ref(), remaining_u64);

    let Some(memory) = &data.memory else { return Err(RuntimeError::new("invalid_memory")) };
    let view: MemoryView = memory.view(&store);

    let mut key_buffer_suffix = vec![0u8; key_len as usize];
    let Ok(_) = view.read(key_ptr as u64, &mut key_buffer_suffix) else { return Err(RuntimeError::new("invalid_memory")) };
    let mut key_buffer = data.current_account.clone();
    key_buffer.extend_from_slice(&key_buffer_suffix);

    let (rx, request_id) = request_from_rust_storage_kv_exists(data.rpc_pid, key_buffer);

    match rx.recv_timeout(std::time::Duration::from_secs(6)) {
        Ok(true) => {
            let _ = view.write(30_000, &(1 as i32).to_le_bytes()).map_err(|err| RuntimeError::new("invalid_memory"));
            Ok(30_000)
        },
        Ok(false) => {
            let _ = view.write(30_000, &(0 as i32).to_le_bytes()).map_err(|err| RuntimeError::new("invalid_memory"));
            Ok(30_000)
        },
        Err(_) => {
            let mut map = REQ_REGISTRY_STORAGE_KV_EXISTS.lock().unwrap();
            map.remove(&request_id);
            Err(RuntimeError::new("no_elixir_callback"))
        }
    }
}

///PREV
fn request_from_rust_storage_kv_get_prev(reply_to_pid: LocalPid, suffix: Vec<u8>, key: Vec<u8>) -> (std::sync::mpsc::Receiver< (Option<Vec<u8>>, Option<Vec<u8>>) >, u64) {
    let (tx, rx) = mpsc::channel::< (Option<Vec<u8>>, Option<Vec<u8>>) >();
    let request_id = rand::random::<u64>();
    {
        let mut map = REQ_REGISTRY_STORAGE_KV_GET_PREV_NEXT.lock().unwrap();
        map.insert(request_id, tx);
    }

    std::thread::spawn(move || {
        let mut env = OwnedEnv::new();
        let _ = env.send_and_clear(&reply_to_pid, |cenv| {
            let mut owned_suffix = OwnedBinary::new(suffix.len()).unwrap();
            owned_suffix.as_mut_slice().copy_from_slice(&suffix);
            let mut owned_key = OwnedBinary::new(key.len()).unwrap();
            owned_key.as_mut_slice().copy_from_slice(&key);
            let payload = (
                atoms::rust_request_storage_kv_get_prev(), 
                request_id, 
                Binary::from_owned(owned_suffix, cenv),
                Binary::from_owned(owned_key, cenv));
            payload.encode(cenv)
        });
    });

    (rx, request_id)
}
fn import_storage_kv_get_prev_implementation(mut env: FunctionEnvMut<HostEnv>, suffix_ptr: i32, suffix_len: i32, key_ptr: i32, key_len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();

    let instance_arc = data.instance.as_ref().ok_or_else(|| RuntimeError::new("invalid_instance"))?;
    let mut remaining_u64 = match get_remaining_points(&mut store, instance_arc.as_ref()) {
        MeteringPoints::Remaining(value) => value,
        MeteringPoints::Exhausted => { 0 }
    };

    let storage_cost = (48 + (key_len as u64)) * 100;
    remaining_u64 = remaining_u64 - storage_cost;
    if remaining_u64 <= 0 { return Err(RuntimeError::new("unreachable")) };
    set_remaining_points(&mut store, instance_arc.as_ref(), remaining_u64);

    let Some(memory) = &data.memory else { return Err(RuntimeError::new("invalid_memory")) };
    let view: MemoryView = memory.view(&store);

    let mut suffix_buffer_suffix = vec![0u8; suffix_len as usize];
    let Ok(_) = view.read(suffix_ptr as u64, &mut suffix_buffer_suffix) else { return Err(RuntimeError::new("invalid_memory")) };
    let mut suffix_buffer = data.current_account.clone();
    suffix_buffer.extend_from_slice(&suffix_buffer_suffix);

    let mut key_buffer = vec![0u8; key_len as usize];
    let Ok(_) = view.read(key_ptr as u64, &mut key_buffer) else { return Err(RuntimeError::new("invalid_memory")) };

    let (rx, request_id) = request_from_rust_storage_kv_get_prev(data.rpc_pid, suffix_buffer, key_buffer);

    match rx.recv_timeout(std::time::Duration::from_secs(6)) {
        Ok((maybe_prev_key, maybe_value)) => {
            match (maybe_prev_key, maybe_value) {
                (Some(prev_key), Some(value)) => {
                    println!("Got Some(prev_key), Some(value)");
                    let _ = view.write(30_000, &((prev_key.len() as i32).to_le_bytes())).map_err(|err| RuntimeError::new("invalid_memory"));
                    let _ = view.write(30_004, &prev_key).map_err(|err| RuntimeError::new("invalid_memory"));
                    let _ = view.write(30_000+4+(prev_key.len() as u64), &((value.len() as i32).to_le_bytes())).map_err(|err| RuntimeError::new("invalid_memory"));
                    let _ = view.write(30_004+4+(prev_key.len() as u64)+4, &value).map_err(|err| RuntimeError::new("invalid_memory"));
                    Ok(30_000)
                },
                _ => {
                    let _ = view.write(30_000, &(-1 as i32).to_le_bytes()).map_err(|err| RuntimeError::new("invalid_memory"));
                    Ok(30_000)
                }
            }
        },
        Err(_) => {
            let mut map = REQ_REGISTRY_STORAGE_KV_GET_PREV_NEXT.lock().unwrap();
            map.remove(&request_id);
            Err(RuntimeError::new("no_elixir_callback"))
        }
    }
}


///NEXT
fn request_from_rust_storage_kv_get_next(reply_to_pid: LocalPid, suffix: Vec<u8>, key: Vec<u8>) -> (std::sync::mpsc::Receiver< (Option<Vec<u8>>, Option<Vec<u8>>) >, u64) {
    let (tx, rx) = mpsc::channel::< (Option<Vec<u8>>, Option<Vec<u8>>) >();
    let request_id = rand::random::<u64>();
    {
        let mut map = REQ_REGISTRY_STORAGE_KV_GET_PREV_NEXT.lock().unwrap();
        map.insert(request_id, tx);
    }

    std::thread::spawn(move || {
        let mut env = OwnedEnv::new();
        let _ = env.send_and_clear(&reply_to_pid, |cenv| {
            let mut owned_suffix = OwnedBinary::new(suffix.len()).unwrap();
            owned_suffix.as_mut_slice().copy_from_slice(&suffix);
            let mut owned_key = OwnedBinary::new(key.len()).unwrap();
            owned_key.as_mut_slice().copy_from_slice(&key);
            let payload = (
                atoms::rust_request_storage_kv_get_next(), 
                request_id, 
                Binary::from_owned(owned_suffix, cenv),
                Binary::from_owned(owned_key, cenv));
            payload.encode(cenv)
        });
    });

    (rx, request_id)
}
fn import_storage_kv_get_next_implementation(mut env: FunctionEnvMut<HostEnv>, suffix_ptr: i32, suffix_len: i32, key_ptr: i32, key_len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();

    let instance_arc = data.instance.as_ref().ok_or_else(|| RuntimeError::new("invalid_instance"))?;
    let mut remaining_u64 = match get_remaining_points(&mut store, instance_arc.as_ref()) {
        MeteringPoints::Remaining(value) => value,
        MeteringPoints::Exhausted => { 0 }
    };

    let storage_cost = (48 + (key_len as u64)) * 100;
    remaining_u64 = remaining_u64 - storage_cost;
    if remaining_u64 <= 0 { return Err(RuntimeError::new("unreachable")) };
    set_remaining_points(&mut store, instance_arc.as_ref(), remaining_u64);

    let Some(memory) = &data.memory else { return Err(RuntimeError::new("invalid_memory")) };
    let view: MemoryView = memory.view(&store);

    let mut suffix_buffer_suffix = vec![0u8; suffix_len as usize];
    let Ok(_) = view.read(suffix_ptr as u64, &mut suffix_buffer_suffix) else { return Err(RuntimeError::new("invalid_memory")) };
    let mut suffix_buffer = data.current_account.clone();
    suffix_buffer.extend_from_slice(&suffix_buffer_suffix);

    let mut key_buffer = vec![0u8; key_len as usize];
    let Ok(_) = view.read(key_ptr as u64, &mut key_buffer) else { return Err(RuntimeError::new("invalid_memory")) };

    let (rx, request_id) = request_from_rust_storage_kv_get_next(data.rpc_pid, suffix_buffer, key_buffer);

    match rx.recv_timeout(std::time::Duration::from_secs(6)) {
        Ok((maybe_next_key, maybe_value)) => {
            match (maybe_next_key, maybe_value) {
                (Some(next_key), Some(value)) => {
                    println!("Got Some(next_key), Some(value)");
                    let _ = view.write(30_000, &((next_key.len() as i32).to_le_bytes())).map_err(|err| RuntimeError::new("invalid_memory"));
                    let _ = view.write(30_004, &next_key).map_err(|err| RuntimeError::new("invalid_memory"));
                    let _ = view.write(30_000+4+(next_key.len() as u64), &((value.len() as i32).to_le_bytes())).map_err(|err| RuntimeError::new("invalid_memory"));
                    let _ = view.write(30_004+4+(next_key.len() as u64)+4, &value).map_err(|err| RuntimeError::new("invalid_memory"));
                    Ok(30_000)
                },
                _ => {
                    let _ = view.write(30_000, &(-1 as i32).to_le_bytes()).map_err(|err| RuntimeError::new("invalid_memory"));
                    Ok(30_000)
                }
            }
        },
        Err(_) => {
            let mut map = REQ_REGISTRY_STORAGE_KV_GET_PREV_NEXT.lock().unwrap();
            map.remove(&request_id);
            Err(RuntimeError::new("no_elixir_callback"))
        }
    }
}

//PUT
fn request_from_rust_storage_kv_put<'a>(reply_to_pid: LocalPid, key: Vec<u8>, val: Vec<u8>) -> (std::sync::mpsc::Receiver<Vec<u8>>, u64) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let request_id = rand::random::<u64>();
    {
        let mut map = REQ_REGISTRY_STORAGE.lock().unwrap();
        map.insert(request_id, tx);
    }

    std::thread::spawn(move || {
        let mut env = OwnedEnv::new();
        let _ = env.send_and_clear(&reply_to_pid, |cenv| {
            let mut owned_key = OwnedBinary::new(key.len()).unwrap();
            owned_key.as_mut_slice().copy_from_slice(&key);
            let mut owned_val = OwnedBinary::new(val.len()).unwrap();
            owned_val.as_mut_slice().copy_from_slice(&val);
            let payload = (
                atoms::rust_request_storage_kv_put(), 
                request_id, 
                Binary::from_owned(owned_key, cenv),
                Binary::from_owned(owned_val, cenv));
            payload.encode(cenv)
        });
    });

    (rx, request_id)
}
fn import_storage_kv_put_implementation(mut env: FunctionEnvMut<HostEnv>, key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    if data.readonly { return Err(RuntimeError::new("read_only")) }

    let instance_arc = data.instance.as_ref().ok_or_else(|| RuntimeError::new("invalid_instance"))?;
    //let instance_ref: &Instance = instance_arc.as_ref();
    //let Some(instance) = &data.instance else { return Err(RuntimeError::new("invalid_instance")) };
    let mut remaining_u64 = match get_remaining_points(&mut store, instance_arc.as_ref()) {
        MeteringPoints::Remaining(value) => value,
        MeteringPoints::Exhausted => { 0 }
    };

    let storage_cost = (48 + (key_len as u64) + (val_len as u64)) * 1000;
    remaining_u64 = remaining_u64 - storage_cost;
    if remaining_u64 <= 0 { return Err(RuntimeError::new("unreachable")) };
    set_remaining_points(&mut store, instance_arc.as_ref(), remaining_u64);

    let Some(memory) = &data.memory else { return Err(RuntimeError::new("invalid_memory")) };
    let view: MemoryView = memory.view(&store);

    let mut key_buffer_suffix = vec![0u8; key_len as usize];
    let Ok(_) = view.read(key_ptr as u64, &mut key_buffer_suffix) else { return Err(RuntimeError::new("invalid_memory")) };
    let mut key_buffer = data.current_account.clone();
    key_buffer.extend_from_slice(&key_buffer_suffix);

    let mut val_buffer = vec![0u8; val_len as usize];
    let Ok(_) = view.read(val_ptr as u64, &mut val_buffer) else { return Err(RuntimeError::new("invalid_memory")) };

    let (rx, request_id) = request_from_rust_storage_kv_put(data.rpc_pid, key_buffer, val_buffer);

    match rx.recv_timeout(std::time::Duration::from_secs(6)) {
        Ok(response) => { 
            println!("rpc OK");
            let _ = view.write(30_000, &((response.len() as i32).to_le_bytes())).map_err(|err| RuntimeError::new("invalid_memory"));
            let _ = view.write(30_004, &response).map_err(|err| RuntimeError::new("invalid_memory"));
            Ok(30_000)
        }
        Err(_) => {
            let mut map = REQ_REGISTRY_STORAGE.lock().unwrap();
            map.remove(&request_id);
            Err(RuntimeError::new("no_elixir_callback"))
        }
    }
}


//INCREMENT
fn request_from_rust_storage_kv_increment<'a>(reply_to_pid: LocalPid, key: Vec<u8>, val: Vec<u8>) -> (std::sync::mpsc::Receiver<Vec<u8>>, u64) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let request_id = rand::random::<u64>();
    {
        let mut map = REQ_REGISTRY_STORAGE.lock().unwrap();
        map.insert(request_id, tx);
    }

    std::thread::spawn(move || {
        let mut env = OwnedEnv::new();
        let _ = env.send_and_clear(&reply_to_pid, |cenv| {
            let mut owned_key = OwnedBinary::new(key.len()).unwrap();
            owned_key.as_mut_slice().copy_from_slice(&key);
            let mut owned_val = OwnedBinary::new(val.len()).unwrap();
            owned_val.as_mut_slice().copy_from_slice(&val);
            let payload = (
                atoms::rust_request_storage_kv_increment(), 
                request_id, 
                Binary::from_owned(owned_key, cenv),
                Binary::from_owned(owned_val, cenv));
            payload.encode(cenv)
        });
    });

    (rx, request_id)
}
fn import_storage_kv_increment_implementation(mut env: FunctionEnvMut<HostEnv>, key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    if data.readonly { return Err(RuntimeError::new("read_only")) }

    let instance_arc = data.instance.as_ref().ok_or_else(|| RuntimeError::new("invalid_instance"))?;
    let mut remaining_u64 = match get_remaining_points(&mut store, instance_arc.as_ref()) {
        MeteringPoints::Remaining(value) => value,
        MeteringPoints::Exhausted => { 0 }
    };

    let storage_cost = (48 + (key_len as u64) + (val_len as u64)) * 1000;
    remaining_u64 = remaining_u64 - storage_cost;
    if remaining_u64 <= 0 { return Err(RuntimeError::new("unreachable")) };
    set_remaining_points(&mut store, instance_arc.as_ref(), remaining_u64);

    let Some(memory) = &data.memory else { return Err(RuntimeError::new("invalid_memory")) };
    let view: MemoryView = memory.view(&store);

    let mut key_buffer_suffix = vec![0u8; key_len as usize];
    let Ok(_) = view.read(key_ptr as u64, &mut key_buffer_suffix) else { return Err(RuntimeError::new("invalid_memory")) };
    let mut key_buffer = data.current_account.clone();
    key_buffer.extend_from_slice(&key_buffer_suffix);

    let mut val_buffer = vec![0u8; val_len as usize];
    let Ok(_) = view.read(val_ptr as u64, &mut val_buffer) else { return Err(RuntimeError::new("invalid_memory")) };

    let (rx, request_id) = request_from_rust_storage_kv_increment(data.rpc_pid, key_buffer, val_buffer);

    match rx.recv_timeout(std::time::Duration::from_secs(6)) {
        Ok(response) => { 
            println!("rpc OK");
            let _ = view.write(30_000, &((response.len() as i32).to_le_bytes())).map_err(|err| RuntimeError::new("invalid_memory"));
            let _ = view.write(30_004, &response).map_err(|err| RuntimeError::new("invalid_memory"));
            Ok(30_000)
        }
        Err(_) => {
            let mut map = REQ_REGISTRY_STORAGE.lock().unwrap();
            map.remove(&request_id);
            Err(RuntimeError::new("no_elixir_callback"))
        }
    }
}

//DELETE
fn request_from_rust_storage_kv_delete<'a>(reply_to_pid: LocalPid, key: Vec<u8>) -> (std::sync::mpsc::Receiver<Vec<u8>>, u64) {
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let request_id = rand::random::<u64>();
    {
        let mut map = REQ_REGISTRY_STORAGE.lock().unwrap();
        map.insert(request_id, tx);
    }

    std::thread::spawn(move || {
        let mut env = OwnedEnv::new();
        let _ = env.send_and_clear(&reply_to_pid, |cenv| {
            let mut owned_key = OwnedBinary::new(key.len()).unwrap();
            owned_key.as_mut_slice().copy_from_slice(&key);
            let payload = (
                atoms::rust_request_storage_kv_delete(), 
                request_id, 
                Binary::from_owned(owned_key, cenv));
            payload.encode(cenv)
        });
    });

    (rx, request_id)
}
fn import_storage_kv_delete_implementation(mut env: FunctionEnvMut<HostEnv>, key_ptr: i32, key_len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    if data.readonly { return Err(RuntimeError::new("read_only")) }

    let instance_arc = data.instance.as_ref().ok_or_else(|| RuntimeError::new("invalid_instance"))?;
    let mut remaining_u64 = match get_remaining_points(&mut store, instance_arc.as_ref()) {
        MeteringPoints::Remaining(value) => value,
        MeteringPoints::Exhausted => { 0 }
    };

    let storage_cost = (48 + (key_len as u64)) * 1000;
    remaining_u64 = remaining_u64 - storage_cost;
    if remaining_u64 <= 0 { return Err(RuntimeError::new("unreachable")) };
    set_remaining_points(&mut store, instance_arc.as_ref(), remaining_u64);

    let Some(memory) = &data.memory else { return Err(RuntimeError::new("invalid_memory")) };
    let view: MemoryView = memory.view(&store);

    let mut key_buffer_suffix = vec![0u8; key_len as usize];
    let Ok(_) = view.read(key_ptr as u64, &mut key_buffer_suffix) else { return Err(RuntimeError::new("invalid_memory")) };
    let mut key_buffer = data.current_account.clone();
    key_buffer.extend_from_slice(&key_buffer_suffix);

    let (rx, request_id) = request_from_rust_storage_kv_delete(data.rpc_pid, key_buffer);

    match rx.recv_timeout(std::time::Duration::from_secs(6)) {
        Ok(response) => { 
            println!("rpc OK");
            let _ = view.write(30_000, &((response.len() as i32).to_le_bytes())).map_err(|err| RuntimeError::new("invalid_memory"));
            let _ = view.write(30_004, &response).map_err(|err| RuntimeError::new("invalid_memory"));
            Ok(30_000)
        }
        Err(_) => {
            let mut map = REQ_REGISTRY_STORAGE.lock().unwrap();
            map.remove(&request_id);
            Err(RuntimeError::new("no_elixir_callback"))
        }
    }
}

//CALL
fn request_from_rust_call<'a>(reply_to_pid: LocalPid, module: Vec<u8>, function: Vec<u8>, args: Vec<u8>) -> (std::sync::mpsc::Receiver< (Vec<u8>, Vec<u8>, Vec<Vec<u8>>, u64, Vec<u8>) >, u64) {
    let (tx, rx) = mpsc::channel::< (Vec<u8>, Vec<u8>, Vec<Vec<u8>>, u64, Vec<u8>) >();
    let request_id = rand::random::<u64>();
    {
        let mut map = REQ_REGISTRY_CALL.lock().unwrap();
        map.insert(request_id, tx);
    }

    std::thread::spawn(move || {
        let mut env = OwnedEnv::new();
        let _ = env.send_and_clear(&reply_to_pid, |cenv| {

            let mut owned_module = OwnedBinary::new(module.len()).unwrap();
            owned_module.as_mut_slice().copy_from_slice(&module);
            let mut owned_function = OwnedBinary::new(function.len()).unwrap();
            owned_function.as_mut_slice().copy_from_slice(&function);
            let mut owned_args = OwnedBinary::new(args.len()).unwrap();
            owned_args.as_mut_slice().copy_from_slice(&args);

            let payload = (
                atoms::rust_request_call(), 
                request_id, 
                Binary::from_owned(owned_module, cenv),
                Binary::from_owned(owned_function, cenv),
                Binary::from_owned(owned_args, cenv));
            payload.encode(cenv)
        });
    });

    (rx, request_id)
}
fn import_call_implementation(mut env: FunctionEnvMut<HostEnv>, module_ptr: i32, module_len: i32, 
    function_ptr: i32, function_len: i32, args_ptr: i32, args_len: i32) -> Result<i32, RuntimeError> {
  /*  let (data, store) = env.data_and_store_mut();
    let memory = match &data.memory {
        Some(mem) => mem,
        None => { return Err(RuntimeError::new("invalid_memory")) }
    };
    let view: MemoryView = memory.view(&store);

    let mut buffer = vec![0u8; module_len as usize];
    match view.read(module_ptr as u64, &mut buffer) {
        Ok(_) => {
            let lol = request_from_rust_call(data.rpc_pid, "hello".to_string());
            Ok(1)
        }
        Err(read_err) => { Err(RuntimeError::new("invalid_memory")) }
    }*/
    Ok(1)
}

fn cost_function(operator: &Operator) -> u64 {
    10
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
    /*
    let payload = (
        atoms::rust_request(),
        rpc_pid,
    );
    let _ = env.send(&rpc_pid, payload);
    */
    call_inner(env, rpc_pid, wasm_bytes, readonly, mapenv, function_name, function_args)
}

use std::time::{Duration, SystemTime};

/*
fn get_or_compile_module(wasm_bytes: &[u8]) -> Result<(Arc<Engine>, Arc<Module>), rustler::Error> {
    let cache_mutex = MODULE_CACHE.get_or_init(|| {
        Mutex::new(HashMap::new())
    });

    let mut hasher = Sha256::new();
    hasher.update(wasm_bytes);
    let hash = hasher.finalize().into();
    {
        let cache = cache_mutex.lock().unwrap();
        if let Some((cached_engine, cached_module)) = cache.get(&hash) {
            return Ok((Arc::clone(cached_engine), Arc::clone(cached_module)));
        }
    }

    let metering = Arc::new(Metering::new(10_000_000, cost_function));
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

    //let engine = EngineBuilder::new(compiler).set_features(Some(features));
    //let mut store = Store::new(engine);

    let engine = Arc::new(EngineBuilder::new(compiler).set_features(Some(features)));
    let store = Store::new(Arc::clone(&engine));

    let module = Module::new(&store, &wasm_bytes).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;

    let arc_module = Arc::new(module);
    {
        let mut cache = cache_mutex.lock().unwrap();
        cache.insert(hash, (Arc::clone(&engine), Arc::clone(&arc_module)));
    }

    Ok((engine, arc_module))
}
*/
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
    //TODO: caching
/*
    let module_arc = get_or_compile_module(wasm_bytes.as_slice());
    let module_ref: &Module = Arc::as_ref(&module_arc);  // Deref the Arc
    let mut store = Store::new(module_ref.engine().clone());
*/


    let metering = Arc::new(Metering::new(10_000_000, cost_function));
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



    //let mut duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    //println!("ns2 {}", duration_since_epoch.as_nanos());

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

    let host_env = FunctionEnv::new(&mut store, HostEnv { 
        memory: None, error: None, return_value: None, logs: vec![], 
        readonly: readonly, rpc_pid: rpc_pid, current_account: it7.to_vec(),
        instance: None});

    let import_log_func = Function::new_typed_with_env(&mut store, &host_env, import_log_implementation);
    let import_return_value_func = Function::new_typed_with_env(&mut store, &host_env, import_return_value_implementation);
    
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

            "import_call" => Function::new_typed_with_env(&mut store, &host_env, import_call_implementation),

            //storage
            //"import_storage_put" => Function::new_typed_with_env(&mut store, &host_env, import_storage_put_implementation),
            //"import_storage_get" => Function::new_typed_with_env(&mut store, &host_env, import_storage_get_implementation),

            "import_kv_put" => Function::new_typed_with_env(&mut store, &host_env, import_storage_kv_put_implementation),
            "import_kv_increment" => Function::new_typed_with_env(&mut store, &host_env, import_storage_kv_increment_implementation),
            "import_kv_delete" => Function::new_typed_with_env(&mut store, &host_env, import_storage_kv_delete_implementation),

            "import_kv_get" => Function::new_typed_with_env(&mut store, &host_env, import_storage_kv_get_implementation),
            "import_kv_exists" => Function::new_typed_with_env(&mut store, &host_env, import_storage_kv_exists_implementation),
            "import_kv_get_prev" => Function::new_typed_with_env(&mut store, &host_env, import_storage_kv_get_prev_implementation),
            "import_kv_get_next" => Function::new_typed_with_env(&mut store, &host_env, import_storage_kv_get_next_implementation),

            //"import_kv_put_int" => Function::new_typed(&mut store, || println!("called_kv_put_in_rust")),
            //"import_kv_get_prefix" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),
            //"import_kv_clear" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),

            //AssemblyScript specific
            "abort" => abort_func,
            //"seed" => abort_func,
        }
    };

    let instance = Instance::new(&mut store, &module, &import_object).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;

    host_env.as_mut(&mut store).instance = Some(Arc::new(instance.clone()));

    let instance_memory = instance.exports.get_memory("memory").map_err(|err| {
        rustler::Error::Term(Box::new(format!(
            "Failed to get 'memory' export from Wasm instance: {}",
            err
        )))
    })?;
    host_env.as_mut(&mut store).memory = Some(instance_memory.clone()); // Update env
    //let mut duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    //println!("ns3 {}", duration_since_epoch.as_nanos());

    let entry_to_call = instance.exports.get_function(&function_name).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let call_result = entry_to_call.call(&mut store, &wasm_args);
    //let mut duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    //println!("ns4 {}", duration_since_epoch.as_nanos());

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
}

rustler::init!("Elixir.WasmerEx");

