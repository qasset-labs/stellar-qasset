//! Trace-shape constants for the 16-bit range-check AIR.

/// $\log_2$ of the table height. The table covers all values
/// $0, 1, \ldots, 2^{16} - 1$, so the trace must have exactly $2^{16}$ rows.
pub const TABLE_LOG_HEIGHT: usize = 16;

/// Total number of rows in the range-check AIR's trace.
pub const TABLE_HEIGHT: usize = 1 << TABLE_LOG_HEIGHT;

/// Name of the global LogUp bus shared with sender AIRs (e.g. ed25519).
/// Sender AIRs must register a `Kind::Global(BUS_NAME.to_string())` lookup
/// with the same name; the LogUp gadget pairs them by name.
pub const BUS_NAME: &str = "u16_range";
