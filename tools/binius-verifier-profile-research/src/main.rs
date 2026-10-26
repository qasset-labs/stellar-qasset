// SPDX-License-Identifier: MIT
//! Research-only: times the pinned Binius64 verifier's own `tracing::info_span!`
//! instrumentation (already present in upstream source, unmodified here) to find
//! which verification phase dominates CPU cost. Reads the exact pinned fixture
//! files used throughout this project's Binius64 evidence; does not modify, vendor
//! again, or alter any pinned/frozen source. No account or asset authority; no
//! network access; read-only against existing fixture files.
#[path = "../../binius-verifier-port/host-runner/src/frozen.rs"]
#[allow(dead_code)]
mod frozen;
extern crate alloc;

use std::{
    collections::HashMap,
    fs,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tracing::{
    Event, Metadata,
    span::{Attributes, Id, Record},
    subscriber::Subscriber,
};

/// Minimal hand-rolled subscriber: no new crate dependency beyond `tracing`
/// itself (already a dependency of the pinned verifier). Tracks wall-clock
/// enter/exit per span, keyed by (name, nesting depth, occurrence ordinal).
/// The ordinal is required, not merely the depth: two call sites share the
/// span name "Verify" at the SAME depth (0) as direct, non-nested, sequential
/// siblings -- confirmed by direct trace (see below) and by reading
/// `crates/verifier/src/zk_config.rs:153-170`, `ZKVerifier::verify`:
///   1. `self.inner_iop_verifier.verify(public, &mut wrapped_channel)` --
///      the inner structural-IOP verify, run through a *recording* channel
///      (`ZKWrappedVerifierChannel`) that records values as outer public
///      inputs rather than performing the real BaseFold cryptographic check.
///      This is the first "Verify" occurrence, with 5 `[phase]` children.
///   2. `wrapped_channel.finish()` -- runs the real outer Spartan
///      verification (`verify_mulcheck` plus the real
///      `channel.verify_oracle_relations` BaseFold opening, batched over all
///      inner+outer oracles). This is the second "Verify" occurrence, with
///      no further span-level instrumentation upstream.
/// A plain (name, depth) key would silently merge these two unrelated costs.
struct TimingSubscriber {
    next_id: AtomicU64,
    names: Mutex<HashMap<u64, &'static str>>,
    opens: Mutex<HashMap<u64, (Instant, usize, u64)>>,
    depth: Mutex<usize>,
    occurrence_seen: Mutex<HashMap<(&'static str, usize), u64>>,
    totals: Mutex<HashMap<(&'static str, usize, u64), (std::time::Duration, u64)>>,
}

impl TimingSubscriber {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            names: Mutex::new(HashMap::new()),
            opens: Mutex::new(HashMap::new()),
            depth: Mutex::new(0),
            occurrence_seen: Mutex::new(HashMap::new()),
            totals: Mutex::new(HashMap::new()),
        }
    }

    fn report(&self) -> Vec<(String, usize, u64, f64, u64)> {
        let totals = self.totals.lock().unwrap();
        let mut rows: Vec<(String, usize, u64, f64, u64)> = totals
            .iter()
            .map(|((name, depth, ordinal), (dur, count))| {
                (name.to_string(), *depth, *ordinal, dur.as_secs_f64(), *count)
            })
            .collect();
        rows.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
        rows
    }
}

impl Subscriber for TimingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, span: &Attributes<'_>) -> Id {
        let raw = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.names
            .lock()
            .unwrap()
            .insert(raw, span.metadata().name());
        Id::from_u64(raw)
    }
    fn record(&self, _span: &Id, _values: &Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn event(&self, _event: &Event<'_>) {}
    fn enter(&self, span: &Id) {
        let mut depth = self.depth.lock().unwrap();
        let this_depth = *depth;
        *depth += 1;
        let name = *self
            .names
            .lock()
            .unwrap()
            .get(&span.into_u64())
            .unwrap_or(&"?");
        let ordinal = {
            let mut seen = self.occurrence_seen.lock().unwrap();
            let counter = seen.entry((name, this_depth)).or_insert(0);
            let ordinal = *counter;
            *counter += 1;
            ordinal
        };
        self.opens
            .lock()
            .unwrap()
            .insert(span.into_u64(), (Instant::now(), this_depth, ordinal));
    }
    fn exit(&self, span: &Id) {
        let raw = span.into_u64();
        let Some((start, this_depth, ordinal)) = self.opens.lock().unwrap().remove(&raw) else {
            return;
        };
        {
            let mut depth = self.depth.lock().unwrap();
            *depth = this_depth;
        }
        let elapsed = start.elapsed();
        let name = *self
            .names
            .lock()
            .unwrap()
            .get(&raw)
            .unwrap_or(&"<unknown>");
        let mut totals = self.totals.lock().unwrap();
        let entry = totals
            .entry((name, this_depth, ordinal))
            .or_insert((std::time::Duration::ZERO, 0));
        entry.0 += elapsed;
        entry.1 += 1;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    let setup_path = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("../binius-verifier-port/target/fixtures/fixed-setup.bin");
    let proof_path = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("../binius-verifier-port/target/fixtures/proof.bin");

    let setup = fs::read(setup_path)?;
    let proof = fs::read(proof_path)?;
    let verifier = frozen::load(&setup)?;

    const SCALAR: [u8; 32] = [
        48, 124, 131, 134, 79, 40, 51, 203, 66, 122, 46, 241, 192, 10, 1, 60, 253, 255, 39, 104,
        217, 128, 192, 163, 165, 32, 240, 6, 144, 77, 233, 79,
    ];
    const ACTION: [u8; 64] = [
        255, 44, 210, 159, 4, 68, 214, 65, 255, 84, 87, 83, 209, 204, 191, 239, 221, 102, 225,
        214, 141, 237, 234, 32, 57, 231, 221, 100, 244, 218, 180, 73, 24, 108, 200, 187, 177, 179,
        10, 130, 101, 223, 172, 144, 165, 93, 46, 100, 28, 77, 60, 40, 6, 154, 168, 29, 108, 24,
        216, 187, 157, 93, 190, 100,
    ];

    let dispatch = tracing::Dispatch::new(TimingSubscriber::new());
    let wall_start = Instant::now();
    let ok = tracing::dispatcher::with_default(&dispatch, || {
        qasset_binius_nostd_verifier::verify_preprocessed_detailed(
            &verifier, &proof, &SCALAR, &ACTION,
        )
    });
    let wall_total = wall_start.elapsed();
    let report_rows = dispatch
        .downcast_ref::<TimingSubscriber>()
        .expect("subscriber type")
        .report();

    // The two "Verify" spans are confirmed, by reading
    // `crates/verifier/src/zk_config.rs:153-170` (`ZKVerifier::verify`), to be
    // sequential siblings at depth 0, not nested -- the empirical trace
    // (ENTER id=1 depth=0 ... EXIT id=1, then ENTER id=7 depth=0 ... EXIT
    // id=7) matches the source exactly:
    //   ordinal 0 = `self.inner_iop_verifier.verify(public, &mut
    //     wrapped_channel)` (zk_config.rs:163) -- the inner structural-IOP
    //     verify, run through a *recording* channel that just records values
    //     as outer public inputs. Its 5 `[phase]` children (IntMul/BitAnd/
    //     Shift/PublicInput/"PCS Opening") are claim-bookkeeping here, NOT a
    //     real BaseFold cryptographic check.
    //   ordinal 1 = `wrapped_channel.finish()` (zk_config.rs:167) -- the real
    //     outer Spartan verification: `verify_mulcheck` plus the actual
    //     `channel.verify_oracle_relations` BaseFold opening, batched over
    //     all inner+outer oracles. No further span instrumentation exists
    //     upstream inside this call, so it cannot be decomposed further with
    //     the existing `info_span!` points alone.
    let layer_a_recording_pass_secs = report_rows
        .iter()
        .find(|(n, d, o, ..)| n == "Verify" && *d == 0 && *o == 0)
        .map(|(_, _, _, s, _)| *s)
        .unwrap_or(0.0);
    let layer_b_real_spartan_and_basefold_secs = report_rows
        .iter()
        .find(|(n, d, o, ..)| n == "Verify" && *d == 0 && *o == 1)
        .map(|(_, _, _, s, _)| *s)
        .unwrap_or(0.0);
    let phase_sum_depth1_ordinal0: f64 = report_rows
        .iter()
        .filter(|(n, d, ..)| *d == 1 && n.starts_with("[phase]"))
        .map(|(_, _, _, s, _)| s)
        .sum();

    let out = serde_json::json!({
        "scope": "research_only_phase_timing_not_soroban_instruction_count",
        "verifier_accepted": ok.is_ok(),
        "error": ok.err(),
        "wall_seconds_instrumented_run": wall_total.as_secs_f64(),
        "layer_breakdown": {
            "layer_a_inner_symbolic_recording_pass_seconds": layer_a_recording_pass_secs,
            "layer_a_pct_of_wall": if wall_total.as_secs_f64() > 0.0 { 100.0 * layer_a_recording_pass_secs / wall_total.as_secs_f64() } else { 0.0 },
            "layer_a_phase_subspan_sum_seconds": phase_sum_depth1_ordinal0,
            "layer_a_note": "zk_config.rs:163, self.inner_iop_verifier.verify(public, &mut wrapped_channel) -- the inner structural-IOP verify (IntMul/BitAnd/Shift/PublicInput reduction + a 'PCS Opening' phase), run through ZKWrappedVerifierChannel, which RECORDS values as outer public inputs rather than performing the real BaseFold cryptographic check. The 5 [phase] sub-spans measured here are this recording pass, not real verification cost.",
            "layer_b_outer_spartan_and_real_basefold_opening_seconds": layer_b_real_spartan_and_basefold_secs,
            "layer_b_pct_of_wall": if wall_total.as_secs_f64() > 0.0 { 100.0 * layer_b_real_spartan_and_basefold_secs / wall_total.as_secs_f64() } else { 0.0 },
            "layer_b_note": "zk_config.rs:167, wrapped_channel.finish() -- runs the real outer Spartan verification: verify_mulcheck (masked zerocheck for A*B=C) plus the actual channel.verify_oracle_relations BaseFold/FRI opening (Merkle-path + field-arithmetic checks), batched over ALL inner+outer oracles together. No further tracing::info_span! instrumentation exists upstream inside this call, so this tool cannot decompose it further without adding new spans (which would require patching pinned/frozen source, which this project's discipline avoids)."
        },
        "raw_span_timings_seconds": report_rows.iter().map(|(n,d,o,s,c)| serde_json::json!({"span": n, "nesting_depth": d, "occurrence_ordinal": o, "seconds": s, "entries": c})).collect::<Vec<_>>(),
        "note": "wall-clock phase timing via the pinned verifier's own existing tracing::info_span! instrumentation, unmodified source; native, single-threaded, release-build proxy for relative cost distribution across verification layers, not a Soroban metered-instruction count. occurrence_ordinal distinguishes the two call sites that both use the span name \"Verify\" at the same nesting depth (0) as sequential siblings, not nested -- confirmed directly against crates/verifier/src/zk_config.rs:153-170 -- which a plain by-name-and-depth sum would otherwise conflate."
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    if ok.is_err() {
        std::process::exit(2);
    }
    Ok(())
}
