//! Fresh-key ML-DSA-65 signer for the disposable SAC authority demonstration.
//! Matches the in-Wasm RustCrypto ml-dsa 0.1.1 verifier (unaudited).
use ml_dsa::{ExpandedSigningKey, MlDsa65, Seed};
use std::{
    env,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
};

const CONTEXT: &[u8] = b"qasset-sac-admin-auth-v1";
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("build repository must exist")
}

fn outside_repository(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let name = absolute
        .file_name()
        .ok_or("key path requires a file name")?;
    let resolved = absolute
        .parent()
        .ok_or("missing parent")?
        .canonicalize()?
        .join(name);
    if resolved.starts_with(repository()) {
        return Err(
            "key files must be outside the repository (including symlinked parents)".into(),
        );
    }
    Ok(resolved)
}

fn fresh_key(path: &Path) -> Result<ExpandedSigningKey<MlDsa65>> {
    let path = outside_repository(path)?;
    let mut seed = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut seed)?;
    // Exclusive creation also refuses existing files and symlinks. Never truncate a key.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&seed)?;
    file.sync_all()?;
    let key = ExpandedSigningKey::from_seed(&Seed::from(seed));
    seed.fill(0);
    Ok(key)
}

fn load_key(path: &Path) -> Result<ExpandedSigningKey<MlDsa65>> {
    let path = outside_repository(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
    {
        return Err(
            "key must be a private, singly linked, owner-held regular file with mode 0600".into(),
        );
    }
    if metadata.len() != 32 {
        return Err("key seed must contain exactly 32 bytes".into());
    }
    let mut seed = [0u8; 32];
    file.read_exact(&mut seed)?;
    let key = ExpandedSigningKey::from_seed(&Seed::from(seed));
    seed.fill(0);
    Ok(key)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
}

fn digest(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("payload must be exactly 64 hexadecimal characters".into());
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}

fn run() -> Result<String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = args.first().ok_or(
        "use keygen [--out PATH], public [--key PATH], or sign [--key PATH] --payload HEX",
    )?;
    if !matches!(command.as_str(), "keygen" | "public" | "sign") {
        return Err("unknown command".into());
    }
    let mut path = None;
    let mut payload = None;
    let mut i = 1;
    while i < args.len() {
        let value = args.get(i + 1).ok_or("missing option value")?;
        match args[i].as_str() {
            "--out" if command == "keygen" && path.is_none() => path = Some(PathBuf::from(value)),
            "--key" if command != "keygen" && path.is_none() => path = Some(PathBuf::from(value)),
            "--payload" if command == "sign" && payload.is_none() => payload = Some(digest(value)?),
            _ => return Err("unexpected or duplicate option".into()),
        }
        i += 2;
    }
    let path = match path {
        Some(p) => p,
        None => {
            let parent = PathBuf::from(env::var("HOME")?).join(".config/qasset-poc");
            if command == "keygen" {
                use std::os::unix::fs::DirBuilderExt;
                // Defaults create private directories; custom output parents must already exist.
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&parent)?;
            }
            parent.join("sac-operator.seed")
        }
    };
    if command == "sign" && payload.is_none() {
        return Err("sign requires --payload".into());
    }
    let key = if command == "keygen" {
        fresh_key(&path)?
    } else {
        load_key(&path)?
    };
    if let Some(payload) = payload {
        Ok(hex(key
            .sign_deterministic(&payload, CONTEXT)
            .map_err(|_| "signing failed")?
            .encode()
            .as_slice()))
    } else {
        Ok(hex(key.verifying_key().encode().as_slice()))
    }
}

fn main() -> ExitCode {
    match run() {
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
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey};
    fn directory() -> PathBuf {
        let mut random = [0; 16];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut random)
            .unwrap();
        let dir = env::temp_dir().join(format!("qasset-signer-test-{}", hex(&random)));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    #[test]
    fn generated_key_signs_for_the_exact_contract_verifier_and_context() {
        let dir = directory();
        let path = dir.join("operator.seed");
        let key = fresh_key(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let loaded = load_key(&path).unwrap();
        assert_eq!(
            key.verifying_key().encode(),
            loaded.verifying_key().encode()
        );
        let encoded = loaded
            .sign_deterministic(&[3; 32], CONTEXT)
            .unwrap()
            .encode();
        let sig = Signature::<MlDsa65>::decode(
            &EncodedSignature::<MlDsa65>::try_from(encoded.as_slice()).unwrap(),
        )
        .unwrap();
        let public = key.verifying_key().encode();
        let verifier = VerifyingKey::<MlDsa65>::decode(
            &EncodedVerifyingKey::<MlDsa65>::try_from(public.as_slice()).unwrap(),
        );
        assert!(verifier.verify_with_context(&[3; 32], CONTEXT, &sig));
        assert!(!verifier.verify_with_context(&[3; 32], b"qasset-pq-auth-v1", &sig));
        assert!(!verifier.verify_with_context(&[4; 32], CONTEXT, &sig));
        assert!(fresh_key(&path).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn rejects_repository_paths_and_parent_symlinks() {
        assert!(fresh_key(&repository().join("forbidden.seed")).is_err());
        let dir = directory();
        std::os::unix::fs::symlink(repository(), dir.join("repo")).unwrap();
        assert!(fresh_key(&dir.join("repo/forbidden.seed")).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn rejects_key_symlinks_hardlinks_and_open_permissions() {
        let dir = directory();
        let path = dir.join("operator.seed");
        fresh_key(&path).unwrap();
        std::os::unix::fs::symlink(&path, dir.join("link")).unwrap();
        assert!(load_key(&dir.join("link")).is_err());
        fs::hard_link(&path, dir.join("hardlink")).unwrap();
        assert!(load_key(&path).is_err());
        fs::remove_file(dir.join("hardlink")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_key(&path).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn payload_parser_is_strict() {
        assert_eq!(digest(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        for text in [
            "a".repeat(63),
            "a".repeat(65),
            "é".repeat(32),
            "gg".repeat(32),
        ] {
            assert!(digest(&text).is_err());
        }
    }
}
