//! Public credential verification only. No key generation or secret-key access.
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use serde_json::Value;
use std::io::{self, Read};

fn hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return Err("invalid hexadecimal input".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&s[i..i + 2], 16)?))
        .collect()
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let rows: Vec<Value> = serde_json::from_str(&input)?;
    let mut result = Vec::new();
    for row in rows {
        let text = |key| {
            row.get(key)
                .and_then(Value::as_str)
                .ok_or("missing credential field")
        };
        let public = hex(text("public_key")?)?;
        let payload = hex(text("payload")?)?;
        let raw = hex(text("signature")?)?;
        if payload.len() != 32 {
            return Err("authorization payload must be 32 bytes".into());
        }
        let key = VerifyingKey::<MlDsa65>::decode(&EncodedVerifyingKey::<MlDsa65>::try_from(
            public.as_slice(),
        )?);
        let signature =
            Signature::<MlDsa65>::decode(&EncodedSignature::<MlDsa65>::try_from(raw.as_slice())?);
        result.push(
            signature
                .map(|sig| key.verify_with_context(&payload, b"qasset-sac-admin-auth-v1", &sig))
                .unwrap_or(false),
        );
    }
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
