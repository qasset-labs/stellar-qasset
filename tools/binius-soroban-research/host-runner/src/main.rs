use soroban_env_host::InvocationResourceLimits;
use std::io::Read;
// Actual Wasm host cost diagnostic; deliberately not transaction feasibility.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soroban_sdk::{
    Bytes, BytesN, Env, IntoVal, Symbol,
    testutils::{EnvTestConfig, cost_estimate::NetworkInvocationResourceLimits},
};
use std::{fs, panic::AssertUnwindSafe, path::Path, time::Instant};
const SCALAR: [u8; 32] = [
    48, 124, 131, 134, 79, 40, 51, 203, 66, 122, 46, 241, 192, 10, 1, 60, 253, 255, 39, 104, 217,
    128, 192, 163, 165, 32, 240, 6, 144, 77, 233, 79,
];
const ACTION: [u8; 64] = [
    255, 44, 210, 159, 4, 68, 214, 65, 255, 84, 87, 83, 209, 204, 191, 239, 221, 102, 225, 214,
    141, 237, 234, 32, 57, 231, 221, 100, 244, 218, 180, 73, 24, 108, 200, 187, 177, 179, 10, 130,
    101, 223, 172, 144, 165, 93, 46, 100, 28, 77, 60, 40, 6, 154, 168, 29, 108, 24, 216, 187, 157,
    93, 190, 100,
];
fn write(path: &Path, v: &Value) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}
fn bounded_file(path: &str, maximum: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take((maximum + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() > maximum {
        return Err("diagnostic input exceeds size bound".into());
    }
    Ok(out)
}
fn run(args: &[String], v: &mut Value) -> Result<(), String> {
    let wasm = bounded_file(&args[0], 1024 * 1024)?;
    let setup = bounded_file(&args[1], 3 * 1024 * 1024)?;
    let proof = bounded_file(&args[2], 1024 * 1024)?;
    let setup_hash = hex::encode(Sha256::digest(&setup));
    let original_setup = setup.len() == 2714051
        && setup_hash == "4d6fd19ea0092a261ed7041985b679ecad4b45f9cc6452a7a717979be7c35ef3";
    let compact_setup = setup.len() == 1286664
        && setup_hash == "0d1a3b775ce006e07df6af3aa1491d2d7c29202e11985fd6045ef398cb3be424";
    if !(original_setup || compact_setup)
        || proof.len() != 539888
        || hex::encode(Sha256::digest(&proof))
            != "e383a3cc44c30b0028b764e11130bdb27454221e0d67a5b82d90abe70047f461"
    {
        return Err("wrong public fixtures".into());
    }
    v["setup_format"] = json!(if compact_setup {
        "compact_v2"
    } else {
        "original_v1"
    });
    v["wasm_sha256"] = json!(hex::encode(Sha256::digest(&wasm)));
    v["wasm_bytes"] = json!(wasm.len());
    v["setup_sha256"] = json!(hex::encode(Sha256::digest(&setup)));
    v["proof_sha256"] = json!(hex::encode(Sha256::digest(&proof)));
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.cost_estimate().budget().reset_unlimited();
    let override_registration = args.iter().any(|arg| arg == "allow-oversize-registration");
    v["registration_limits_overridden"] = json!(override_registration);
    if override_registration {
        env.cost_estimate().disable_resource_limits();
    }
    let id = env.register(wasm.as_slice(), ());
    v["registration_succeeded"] = json!(true);

    let setup = Bytes::from_slice(&env, &setup);
    let proof = Bytes::from_slice(&env, &proof);
    let scalar = BytesN::from_array(&env, &SCALAR);
    let action = BytesN::from_array(&env, &ACTION);
    // These already-created input objects are outside the measured contract call.
    // A real staged operation would add ledger/storage/transport costs.
    let diagnostic = args.get(4).map(String::as_str) == Some("diagnostic");
    let (cpu, mem): (u64, u64) = if diagnostic {
        (12_000_000_000, 256 * 1024 * 1024)
    } else {
        (400_000_000, 40 * 1024 * 1024)
    };
    v["cpu_limit"] = json!(cpu);
    v["memory_limit"] = json!(mem);
    v["diagnostic_expanded_budget"] = json!(diagnostic);
    let mut invocation_limits = InvocationResourceLimits::mainnet();
    invocation_limits.instructions = cpu as i64;
    invocation_limits.mem_bytes = mem as i64;
    env.cost_estimate()
        .enforce_resource_limits(invocation_limits);
    env.cost_estimate().budget().reset_limits(cpu, mem);
    let start = Instant::now();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        env.try_invoke_contract::<bool, soroban_sdk::Error>(
            &id,
            &Symbol::new(&env, "verify_fixture"),
            soroban_sdk::vec![
                &env,
                setup.into_val(&env),
                proof.into_val(&env),
                scalar.into_val(&env),
                action.into_val(&env)
            ],
        )
    }));
    v["elapsed_seconds"] = json!(start.elapsed().as_secs_f64());
    v["cpu_instructions"] = json!(env.cost_estimate().budget().cpu_instruction_cost());
    v["metered_memory_bytes"] = json!(env.cost_estimate().budget().memory_bytes_cost());
    match result {
        Ok(Ok(Ok(value))) => {
            v["accepted"] = json!(value);
            v["status"] = json!(if value {
                "measured_actual_wasm_verification_only"
            } else {
                "measured_false_result_not_recovery_approval"
            });
        }
        other => {
            v["accepted"] = Value::Null;
            v["status"] = json!("measured_execution_failure_not_proof_rejection");
            v["execution_error"] = json!(format!("{other:?}"));
        }
    }
    Ok(())
}
fn main() {
    // SDK panic diagnostics can print entire multi-megabyte public input objects.
    // Preserve the first error line without dumping those byte arrays.
    std::panic::set_hook(Box::new(|info| {
        let text = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("host call panicked");
        eprintln!(
            "{}",
            text.lines()
                .next()
                .unwrap_or("host call panicked")
                .chars()
                .take(240)
                .collect::<String>()
        );
    }));
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        panic!("usage: host_probe WASM SETUP PROOF OUTPUT [diagnostic]")
    }
    let output = Path::new(&args[3]);
    let mut v = json!({"schema":"qasset-binius-soroban-host-diagnostic-v1","status":"in_progress","security_approved":false,"stellar_rpc_requests":0,"submitted_transactions":0,"registration_succeeded":false,
 "scope":"Actual Soroban ABI execution, oversized argument transport bypasses real transaction caps; default SDK cost model, no network admission or storage costs.","limits":["Contract registration and already-created host input objects are outside measured calls.","A host/VM budget failure is never classified as rejection of a cryptographic proof.","No account state, recovery authority, eligibility, replacement or asset integration is implemented.","Expanded diagnostic budgets are not admissible network settings."]});
    write(output, &v).unwrap();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| run(&args, &mut v)));
    match result {
        Ok(Ok(())) => {}
        other => {
            v["status"] = json!("failed_harness_or_registration");
            v["harness_error"] = json!(format!("{other:?}"));
        }
    }
    write(output, &v).unwrap();
    println!("{}", v);
}
