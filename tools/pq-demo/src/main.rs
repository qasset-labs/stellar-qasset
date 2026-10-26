//! Public-fixture, TESTNET-ONLY deterministic ML-DSA-65 helper.
//! RustCrypto ml-dsa 0.1.1 implements FIPS 204 (Apache-2.0/MIT, unaudited).
//! HKDF follows RFC 5869; no new cryptographic construction is claimed.
//! The SINGLE root below is PUBLIC, not anyone's wallet backup. All three
//! derived secret keys are known to everyone. Never use these keys with funds.

use hkdf::Hkdf;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Seed, Signature,
    VerifyingKey,
};
use sha2::{Digest, Sha256, Sha512};
use std::{env, fmt::Write as _, process::ExitCode};

const PUBLIC_ROOT: [u8; 64] = [0x42; 64];
const NETWORK: &str = "Test SDF Network ; September 2015";
const DEMO_CONTEXT: &[u8] = b"qasset-pq-recovery-public-fixture-v1";
const KDF_SALT: &[u8] = b"qasset-pq-demo-kdf-v1";
const AUTH_CONTEXT: &[u8] = b"qasset-pq-auth-v1";
const RECOVERY_CONTEXT: &[u8] = b"qasset-recover-v1";

fn key_for_role(role: &str) -> Result<ExpandedSigningKey<MlDsa65>, String> {
    if !matches!(role, "active" | "recovery" | "replacement") {
        return Err("role must be active, recovery, or replacement".into());
    }
    let mut info = b"qasset-pq-demo-key-v1".to_vec();
    // Each field is length-prefixed to avoid ambiguous concatenations.
    for field in [
        Sha256::digest(NETWORK.as_bytes()).as_slice(),
        DEMO_CONTEXT,
        b"ML-DSA-65",
        role.as_bytes(),
    ] {
        info.extend_from_slice(&(field.len() as u32).to_be_bytes());
        info.extend_from_slice(field);
    }
    let mut seed = [0u8; 32];
    Hkdf::<Sha512>::new(Some(KDF_SALT), &PUBLIC_ROOT)
        .expand(&info, &mut seed)
        .map_err(|_| "HKDF output length rejected".to_string())?;
    Ok(ExpandedSigningKey::<MlDsa65>::from_seed(&Seed::from(seed)))
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("String formatting cannot fail");
    }
    result
}

fn parse_digest(encoded: &str) -> Result<[u8; 32], String> {
    parse_hex_exact::<32>(encoded)
}

fn parse_hex_exact<const N: usize>(encoded: &str) -> Result<[u8; N], String> {
    if encoded.len() != 2 * N {
        return Err("hexadecimal input has the wrong length".into());
    }
    fn nibble(value: u8) -> Result<u8, String> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'A'..=b'F' => Ok(value - b'A' + 10),
            _ => Err("digest contains a non-hexadecimal character".into()),
        }
    }
    let mut digest = [0u8; N];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(digest)
}

fn context_for_mode(mode: &str) -> Result<&'static [u8], String> {
    match mode {
        "AUTH" => Ok(AUTH_CONTEXT),
        "RECOVERY" => Ok(RECOVERY_CONTEXT),
        _ => Err("signature mode must be AUTH or RECOVERY".into()),
    }
}

fn run(args: &[String]) -> Result<String, String> {
    match args {
        [command, role] if command == "public-key" => {
            Ok(hex(key_for_role(role)?.verifying_key().encode().as_slice()))
        }
        [command, role, digest, mode] if command == "sign" => {
            let context = context_for_mode(mode)?;
            let digest = parse_digest(digest)?;
            let signature = key_for_role(role)?
                .sign_deterministic(&digest, context)
                .map_err(|_| "ML-DSA signing failed".to_string())?;
            Ok(hex(signature.encode().as_slice()))
        }
        [command, public_key, digest, signature, mode] if command == "verify" => {
            let public_key = parse_hex_exact::<1952>(public_key)?;
            let signature = parse_hex_exact::<3309>(signature)?;
            let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(public_key.as_slice())
                .map_err(|_| "invalid ML-DSA public-key encoding".to_string())?;
            let encoded_signature = EncodedSignature::<MlDsa65>::try_from(signature.as_slice())
                .map_err(|_| "invalid ML-DSA signature encoding".to_string())?;
            let signature = Signature::<MlDsa65>::decode(&encoded_signature)
                .ok_or_else(|| "invalid ML-DSA signature encoding".to_string())?;
            if VerifyingKey::<MlDsa65>::decode(&encoded_key).verify_with_context(
                &parse_digest(digest)?,
                context_for_mode(mode)?,
                &signature,
            ) {
                Ok("valid".into())
            } else {
                Err("ML-DSA signature verification failed".into())
            }
        }
        _ => Err(concat!(
            "PUBLIC FIXTURE ONLY; NEVER USE WITH FUNDS. Usage: ",
            "qasset-pq-demo-tool public-key ROLE | sign ROLE DIGEST_HEX AUTH|RECOVERY | ",
            "verify PUBLIC_KEY_HEX DIGEST_HEX SIGNATURE_HEX AUTH|RECOVERY"
        )
        .into()),
    }
}

fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_root_derives_distinct_repeatable_roles() {
        let active = key_for_role("active").unwrap().verifying_key().encode();
        let recovery = key_for_role("recovery").unwrap().verifying_key().encode();
        let replacement = key_for_role("replacement")
            .unwrap()
            .verifying_key()
            .encode();
        assert_ne!(active, recovery);
        assert_ne!(recovery, replacement);
        assert_ne!(active, replacement);
        assert_eq!(
            active,
            key_for_role("active").unwrap().verifying_key().encode()
        );
    }

    #[test]
    fn signatures_are_real_and_domain_separated() {
        let key = key_for_role("recovery").unwrap();
        let digest = [7u8; 32];
        let signature = key.sign_deterministic(&digest, RECOVERY_CONTEXT).unwrap();
        assert!(key
            .verifying_key()
            .verify_with_context(&digest, RECOVERY_CONTEXT, &signature));
        assert!(!key
            .verifying_key()
            .verify_with_context(&digest, AUTH_CONTEXT, &signature));
    }

    #[test]
    fn malformed_inputs_and_unknown_roles_are_rejected() {
        assert!(parse_digest("abcd").is_err());
        assert!(parse_digest(&"z".repeat(64)).is_err());
        assert!(key_for_role("owner").is_err());
        assert_eq!(parse_digest(&"ab".repeat(32)).unwrap(), [0xab; 32]);
    }

    #[test]
    fn cli_verifier_checks_key_digest_context_and_canonical_signature() {
        let digest = "ab".repeat(32);
        let public = run(&["public-key".into(), "replacement".into()]).unwrap();
        let signature = run(&[
            "sign".into(),
            "replacement".into(),
            digest.clone(),
            "RECOVERY".into(),
        ])
        .unwrap();
        let valid = vec![
            "verify".into(),
            public.clone(),
            digest.clone(),
            signature.clone(),
            "RECOVERY".into(),
        ];
        assert_eq!(run(&valid).unwrap(), "valid");
        for (index, value) in [
            (1, run(&["public-key".into(), "active".into()]).unwrap()),
            (2, "ac".repeat(32)),
            (3, "00".repeat(3309)),
            (4, "AUTH".into()),
            (3, signature[..signature.len() - 2].to_string()),
            (1, public[..public.len() - 2].to_string()),
        ] {
            let mut invalid = valid.clone();
            invalid[index] = value;
            assert!(run(&invalid).is_err());
        }
    }
}
