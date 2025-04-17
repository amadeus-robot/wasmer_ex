use rustler::types::{Binary, OwnedBinary};
use rustler::{Encoder, Error, Env, Term, NifResult, ResourceArc};

use wasmer::{
    imports,
    sys::{EngineBuilder, Features},
    Function, FunctionEnv, FunctionEnvMut, FunctionType, Global, Instance, Memory, MemoryType,
    MemoryView, Module, Pages, Store, Type, Value,
    RuntimeError
};
use wasmer_compiler_singlepass::Singlepass;

use std::collections::HashMap;

mod atoms {
    rustler::atoms! {
        ok,
        error
    }
}

#[derive(Debug, Clone, Copy)]
struct ExitCode(u32);

#[derive(Clone)]
struct HostEnv {
    memory: Option<Memory>,
  //  logs: Vec<Vec<u8>>,
}

//AssemblyScript specific
fn abort_implementation(mut env: FunctionEnvMut<HostEnv>, _message: i32, _fileName: i32, line: i32, column: i32) -> Result<(), RuntimeError> {
    let (data, store) = env.data_and_store_mut();
    let memory = match &data.memory {
        Some(mem) => mem,
        None => { return Err(RuntimeError::new("invalid_memory")) }
    };
    print!("abort>> line: {} column: {} \n", line, column);
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
            print!("log>> {} \n", String::from_utf8_lossy(&buffer));
            Ok(())
        }
        Err(read_err) => { Err(RuntimeError::new("invalid_memory")) }
    }
}

#[rustler::nif]
pub fn call<'a>(env: Env<'a>, wasm_bytes: Binary, mapenv: Term<'a>, function_name: String, function_args: Vec<Term<'a>>) -> Result<rustler::Term<'a>, rustler::Error> {

    let mut compiler = Singlepass::default();
    compiler.canonicalize_nans(true);

    let mut features = Features::new();
    features.bulk_memory(false);
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
    memory.view(&mut store).write(100, it1).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it2 = map.get("entry_signer").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(200, it2).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it3 = map.get("entry_prev_hash").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(300, it3).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it4 = map.get("entry_vr").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(400, it4).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it5 = map.get("entry_dr").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(500, it5).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it6 = map.get("tx_signer").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(1000, it6).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it7 = map.get("current_account").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(2000, it7).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    let it8 = map.get("caller_account").ok_or(Error::BadArg)?.decode::<Binary>()?.as_slice();
    memory.view(&mut store).write(2100, it8).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;

    let mut offset: u64 = 10_000;
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

    /*
    let signature = FunctionType::new(vec![Type::I32, Type::I32], vec![Type::I32]);
    let log_func = Function::new_typed(&mut store, &signature, |ptr, len| {
        let mut buffer = [0u8; 8];
        let _ = memory_view.read(ptr as u64, &mut buffer);
        println!(">> log from AssemblyScript: {}", String::from_utf8_lossy(&buffer));
        Ok(vec![Value::I32(ptr)])
    });
    */

    let host_env = FunctionEnv::new(&mut store, HostEnv { memory: None });
    let import_log_func = Function::new_typed_with_env(&mut store, &host_env, import_log_implementation);
    let abort_func = Function::new_typed_with_env(&mut store, &host_env, abort_implementation);

/*
    let host_function_signature = FunctionType::new(vec![Type::I32, Type::I32], vec![Type::I32]);
    let host_function = Function::new(&mut store, &host_function_signature, |args| {
        let memoryview = memory.view(&store);
        let mut buffer = [0u8; 8];
        //let _ = memory_view.read(args[0].unwrap_i32() as u64, &mut buffer);
        //println!(">> log from AssemblyScript: {}", String::from_utf8_lossy(&buffer));
        Ok(vec![Value::I32(42)])
    });
*/

    let import_object = imports! {
        "env" => {
            "memory" => memory,
            "seed_ptr" => Global::new(&mut store, Value::I32(100)),
            "entry_signer_ptr" => Global::new(&mut store, Value::I32(200)),
            "entry_prev_hash_ptr" => Global::new(&mut store, Value::I32(300)),
            "entry_slot" => Global::new(&mut store, Value::I64(map.get("entry_slot").ok_or(Error::BadArg)?.decode::<i64>()?)),
            "entry_prev_slot" => Global::new(&mut store, Value::I64(map.get("entry_prev_slot").ok_or(Error::BadArg)?.decode::<i64>()?)),
            "entry_height" => Global::new(&mut store, Value::I64(map.get("entry_height").ok_or(Error::BadArg)?.decode::<i64>()?)),
            "entry_epoch" => Global::new(&mut store, Value::I64(map.get("entry_epoch").ok_or(Error::BadArg)?.decode::<i64>()?)),
            "entry_vr_ptr" => Global::new(&mut store, Value::I32(400)),
            "entry_dr_ptr" => Global::new(&mut store, Value::I32(500)),

            "tx_signer_ptr" => Global::new(&mut store, Value::I32(1000)),
            "tx_nonce" => Global::new(&mut store, Value::I64(map.get("tx_nonce").ok_or(Error::BadArg)?.decode::<i64>()?)),

            "current_account_ptr" => Global::new(&mut store, Value::I32(2000)),
            "caller_account_ptr" => Global::new(&mut store, Value::I32(2100)),

            "import_log" => import_log_func,

            "import_call" => Function::new_typed(&mut store, || println!("called_kv_put_in_rust")),
            "import_kv_put" => Function::new_typed(&mut store, || println!("called_kv_put_in_rust")),
            "import_kv_put_int" => Function::new_typed(&mut store, || println!("called_kv_put_in_rust")),
            "import_kv_increment" => Function::new_typed(&mut store, || println!("called_kv_put_in_rust")),
            "import_kv_delete" => Function::new_typed(&mut store, || println!("called_kv_put_in_rust")),
            "import_kv_get" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),
            "import_kv_get_prev" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),
            "import_kv_get_prefix" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),
            "import_kv_exists" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),
            "import_kv_clear" => Function::new_typed(&mut store, || println!("called_kv_get_in_rust")),

            //AssemblyScript specific
            "abort" => abort_func,
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
    let result1 = entry_to_call.call(&mut store, &wasm_args).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    //println!("wtf {}", extract_i32_ref(&result1[0]));

    //let add_one = instance.exports.get_function("add_one").map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    //let result = add_one.call(&mut store, &[Value::I64(42)]).map_err(|err| rustler::Error::Term(Box::new(err.to_string())))?;
    //assert_eq!(result[0], Value::I64(43));


    //Result<rustler::Term<'a>, rustler::Error>

    Ok((atoms::error(), extract_i64_ref(&result1[0])).encode(env))
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

