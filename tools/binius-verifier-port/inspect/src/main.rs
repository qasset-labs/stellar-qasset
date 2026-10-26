// SPDX-License-Identifier: MIT
//! Inspect a fully linked experimental Wasm module.
use wasmparser::{Parser, Payload, Validator, WasmFeatures};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("path")?;
    let raw = std::fs::read(path)?;
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut float_ops = Vec::new();
    let mut op_count = 0u64;
    let mut memories = Vec::new();
    for payload in Parser::new(0).parse_all(&raw) {
        match payload? {
            Payload::ImportSection(s) => {
                for i in s {
                    let i = i?;
                    imports.push(format!("{}::{} {:?}", i.module, i.name, i.ty));
                }
            }
            Payload::ExportSection(s) => {
                for e in s {
                    let e = e?;
                    exports.push(e.name.to_string());
                }
            }
            Payload::MemorySection(s) => {
                for m in s {
                    let m = m?;
                    memories.push(serde_json::json!({"initial_pages":m.initial,"maximum_pages":m.maximum,"memory64":m.memory64,"shared":m.shared}));
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut r = body.get_operators_reader()?;
                while !r.eof() {
                    let op = r.read()?;
                    op_count += 1;
                    let s = format!("{op:?}");
                    if s.contains("F32") || s.contains("F64") {
                        float_ops.push(s);
                    }
                }
            }
            _ => {}
        }
    }
    let mut features = WasmFeatures::default();
    features.floats = false;
    features.simd = false;
    features.threads = false;
    let validation = Validator::new_with_features(features)
        .validate_all(&raw)
        .map(|_| "passed".to_owned())
        .unwrap_or_else(|e| e.to_string());
    println!(
        "{}",
        serde_json::json!({"bytes":raw.len(),"imports":imports,"exports":exports,"memories":memories,"operator_count":op_count,"float_operator_count":float_ops.len(),"float_operators":float_ops,"no_float_simd_threads_validation":validation})
    );
    Ok(())
}
