// Copyright 2026 The Binius Developers
// Copyright 2024-2025 Irreducible Inc.

/// Read boolean flag from the environment variable.
pub fn boolean_env_flag_set(flag: &str) -> bool {
	#[cfg(target_os = "none")]
	{ let _ = flag; false }
	#[cfg(not(target_os = "none"))]
	match crate::qasset_nostd::env::var(flag) {
		Ok(val) => ["1", "on", "ON", "true", "TRUE", "yes", "YES"].contains(&val.as_str()),
		Err(_) => false,
	}
}
