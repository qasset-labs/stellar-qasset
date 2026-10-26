// Copyright 2026 The Binius Developers
//! Core and allocation imports for the experimental Wasm port.
#[cfg(not(target_os = "none"))]
pub use ::std::*;
#[cfg(target_os = "none")]
pub use core::*;
#[cfg(target_os = "none")]
pub use ::alloc::{borrow, boxed, format, string, vec, rc};
#[cfg(target_os = "none")]
pub mod collections {
    pub use ::alloc::collections::*;
    pub use hashbrown::{HashMap, HashSet};
}
#[cfg(target_os = "none")]
pub mod backtrace {
    /// No-OS diagnostic marker; never used in cryptographic verification.
    #[derive(Debug)]
    pub struct Backtrace;
    impl Backtrace { pub fn capture() -> Self { Self } }
}
