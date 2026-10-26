//! Local actual-Wasm transport probe. Authentication is mocked; no recovery is approved.
use recovery_proof_mailbox::{Error, RecoveryProofMailboxClient, UploadHeader, CHUNK_BYTES};
use serde_json::{json, Value};
use soroban_sdk::{
    testutils::{EnvTestConfig, Ledger as _},
    Address, Bytes, BytesN, Env,
};
use std::{fs, io::Read, panic::AssertUnwindSafe, path::Path, time::Instant};

const CPU_LIMIT: u64 = 400_000_000;
const MEMORY_LIMIT: u64 = 40 * 1024 * 1024;
const READ_BYTES: usize = 8192;

fn text<'a>(input: &'a Value, name: &str) -> Result<&'a str, String> {
    input[name]
        .as_str()
        .ok_or_else(|| format!("missing string {name}"))
}
fn number(input: &Value, name: &str) -> Result<u32, String> {
    input[name]
        .as_u64()
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| format!("invalid u32 {name}"))
}
fn decode<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("expected {N} bytes of hex"));
    }
    let mut result = [0u8; N];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).map_err(|_| "invalid hex")?;
    }
    Ok(result)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn write(path: &Path, report: &Value) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}
fn measured<T>(
    env: &Env,
    report: &mut Value,
    output: &Path,
    label: &str,
    call: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    env.cost_estimate()
        .budget()
        .reset_limits(CPU_LIMIT, MEMORY_LIMIT);
    let start = Instant::now();
    let result = std::panic::catch_unwind(AssertUnwindSafe(call))
        .map_err(|_| format!("{label}: Wasm/host call panicked"))
        .and_then(|r| r);
    report["measurements"].as_array_mut().unwrap().push(json!({
        "call":label,"passed":result.is_ok(),"cpu_instructions":env.cost_estimate().budget().cpu_instruction_cost(),
        "memory_bytes":env.cost_estimate().budget().memory_bytes_cost(),"wall_seconds":start.elapsed().as_secs_f64(),
        "error":result.as_ref().err()
    }));
    write(output, report)?;
    result
}
fn run(
    wasm_path: &Path,
    proof_path: &Path,
    input_path: &Path,
    output: &Path,
    report: &mut Value,
) -> Result<(), String> {
    let input_bytes = fs::read(input_path).map_err(|e| e.to_string())?;
    let input: Value = serde_json::from_slice(&input_bytes).map_err(|e| e.to_string())?;
    let wasm = fs::read(wasm_path).map_err(|e| e.to_string())?;
    if fs::metadata(proof_path).map_err(|e| e.to_string())?.len()
        > recovery_proof_mailbox::MAX_PROOF_BYTES as u64
    {
        return Err("proof exceeds mailbox size bound".into());
    }
    let mut proof = Vec::new();
    fs::File::open(proof_path)
        .map_err(|e| e.to_string())?
        .take(recovery_proof_mailbox::MAX_PROOF_BYTES as u64 + 1)
        .read_to_end(&mut proof)
        .map_err(|e| e.to_string())?;
    if proof.len() > recovery_proof_mailbox::MAX_PROOF_BYTES as usize {
        return Err("proof exceeds mailbox size bound".into());
    }
    if proof.len() != number(&input, "length")? as usize {
        return Err("input proof length mismatch".into());
    }
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.cost_estimate().budget().reset_unlimited();
    let network_id = decode::<32>(text(&input, "network_id_hex")?)?;
    let current_ledger = number(&input, "current_ledger")?;
    env.ledger().with_mut(|info| {
        info.network_id = network_id;
        info.sequence_number = current_ledger;
    });
    let proof_hash: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, &proof)).into();
    if proof_hash.to_array() != decode::<32>(text(&input, "proof_sha256")?)? {
        return Err("proof SHA256 mismatch".into());
    }
    let wasm_hash: BytesN<32> = env.crypto().sha256(&Bytes::from_slice(&env, &wasm)).into();
    let input_hash: BytesN<32> = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, &input_bytes))
        .into();
    let contract = Address::from_str(&env, text(&input, "parent")?);
    let uploader = Address::from_str(&env, text(&input, "uploader")?);
    env.register_at(&contract, wasm.as_slice(), ());
    env.mock_all_auths();
    let client = RecoveryProofMailboxClient::new(&env, &contract);
    let header = UploadHeader {
        uploader,
        nonce: BytesN::from_array(&env, &decode(text(&input, "nonce_hex")?)?),
        statement: BytesN::from_array(&env, &decode(text(&input, "statement_hex")?)?),
        verifier: BytesN::from_array(&env, &decode(text(&input, "verifier_hex")?)?),
        parameters: BytesN::from_array(&env, &decode(text(&input, "parameters_hex")?)?),
        length: number(&input, "length")?,
        expires: number(&input, "expires")?,
    };
    let expected = BytesN::from_array(&env, &decode(text(&input, "expected_chain_hex")?)?);
    let expected_id = BytesN::from_array(&env, &decode(text(&input, "session_id_hex")?)?);
    report["wasm_sha256"] = json!(hex(&wasm_hash.to_array()));
    report["input_sha256"] = json!(hex(&input_hash.to_array()));
    report["proof_sha256"] = json!(hex(&proof_hash.to_array()));
    report["proof_bytes"] = json!(proof.len());
    report["local_ledger_protocol"] = json!(env.ledger().get().protocol_version);
    let session = measured(&env, report, output, "open", || {
        Ok(client.open(&header, &expected))
    })?;
    if session != expected_id {
        return Err("session differs from independent Python XDR vector".into());
    }
    report["session_id_hex"] = json!(hex(&session.to_array()));
    report["expected_chain_hex"] = json!(hex(&expected.to_array()));
    let count = proof.len().div_ceil(CHUNK_BYTES as usize);
    for (index, chunk) in proof.chunks(CHUNK_BYTES as usize).enumerate() {
        let received = measured(&env, report, output, &format!("append_{index}"), || {
            Ok(client.append(&session, &(index as u32), &Bytes::from_slice(&env, chunk)))
        })?;
        if received != index as u32 + 1 {
            return Err("incorrect received chunk count".into());
        }
    }
    let sealed = measured(&env, report, output, "seal", || Ok(client.seal(&session)))?;
    if !sealed.sealed_unverified || sealed.received != count as u32 || sealed.rolling != expected {
        return Err("sealed transport metadata mismatch".into());
    }
    let mut recovered = Vec::with_capacity(proof.len());
    for (index, chunk) in proof.chunks(CHUNK_BYTES as usize).enumerate() {
        for offset in (0..chunk.len()).step_by(READ_BYTES) {
            let length = READ_BYTES.min(chunk.len() - offset);
            let bytes = measured(
                &env,
                report,
                output,
                &format!("read_slice_{index}_{offset}"),
                || {
                    Ok(client.read_slice(
                        &session,
                        &(index as u32),
                        &(offset as u32),
                        &(length as u32),
                    ))
                },
            )?;
            if bytes.len() != length as u32 {
                return Err("incorrect read slice length".into());
            }
            let mut part = vec![0u8; length];
            bytes.copy_into_slice(&mut part);
            recovered.extend(part);
        }
    }
    if recovered != proof {
        return Err("actual Wasm byte roundtrip mismatch".into());
    }
    measured(&env, report, output, "backend_available", || {
        if client.backend_available() {
            return Err("disabled backend unexpectedly available".into());
        }
        Ok(())
    })?;
    measured(&env, report, output, "require_verified_rejects", || {
        if client.try_require_verified(&session) != Err(Ok(Error::BackendUnavailable)) {
            return Err("transport unexpectedly granted proof approval".into());
        }
        Ok(())
    })?;
    env.cost_estimate().budget().reset_unlimited();
    let recovered_hash: BytesN<32> = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, &recovered))
        .into();
    if recovered_hash != proof_hash {
        return Err("roundtrip SHA256 mismatch".into());
    }
    report["status"] = json!("passed_actual_wasm_transport_only");
    report["chunk_count"] = json!(count);
    report["roundtrip_bytes_equal"] = json!(true);
    report["roundtrip_sha256_equal"] = json!(true);
    report["independent_session_id_matches"] = json!(true);
    report["sealed_unverified"] = json!(true);
    report["backend_available"] = json!(false);
    report["require_verified_rejected"] = json!(true);
    report["maximum_call_cpu_instructions"] = report["measurements"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["cpu_instructions"].as_u64())
        .max()
        .into();
    report["maximum_call_memory_bytes"] = report["measurements"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["memory_bytes"].as_u64())
        .max()
        .into();
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 {
        eprintln!("usage: mailbox_wasm_probe WASM PROOF INPUT_JSON OUTPUT_JSON");
        std::process::exit(1);
    }
    let output = Path::new(&args[4]);
    let mut report = json!({"schema":"qasset-mailbox-wasm-probe-v1","status":"in_progress", "security_approved":false,
        "actual_wasm_contract":true,"authentication":"mock_all_auths_transport_only_no_cryptographic_authentication", 
        "per_call_cpu_limit":CPU_LIMIT,"per_call_memory_limit":MEMORY_LIMIT,"chunk_bytes":CHUNK_BYTES,"read_slice_bytes":READ_BYTES,
        "submitted_transactions":0,"stellar_rpc_requests":0,"measurements":[],
        "limits":["Local SDK host and its default cost model; not a live network simulation, transaction, fee or RPC measurement.",
            "Budget resets before each contract call. Ledger/file parsing, contract registration and checksum preparation are outside measured calls.",
            "Authentication is mocked for transport. No signature security, seed proof, recovery eligibility, retirement, authority mutation or atomic recovery is established.",
            "SDK host calls omit signed transaction envelope, footprint validation and whole transaction/event/meta XDR limits. Read results are bounded to 8192 bytes; network feasibility still requires complete transaction simulation.",
            "The proof is transported unchanged and remains unverified by this mailbox."]});
    if let Err(error) = write(output, &report) {
        eprintln!("{error}");
        std::process::exit(1);
    }
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        run(
            Path::new(&args[1]),
            Path::new(&args[2]),
            Path::new(&args[3]),
            output,
            &mut report,
        )
    }));
    let error = match result {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e),
        Err(_) => Some("probe setup or host call panicked".into()),
    };
    if let Some(error) = error {
        report["status"] = json!("failed");
        report["error"] = json!(error);
        let _ = write(output, &report);
        eprintln!("{report}");
        std::process::exit(1);
    }
    if let Err(error) = write(output, &report) {
        eprintln!("{error}");
        std::process::exit(1);
    }
    println!("{report}");
}
