// SPDX-License-Identifier: MIT
//! Research-only: a pure-userspace, signal-based sampling profile (via the `pprof`
//! crate, SIGPROF-based, no `perf_event_open`, no system package install, no
//! `sudo`) of the pinned Binius64 verifier's dominant "Layer B" cost (the real
//! Spartan mulcheck plus actual BaseFold/FRI opening -- see
//! verifier-profile-research.json for how that step was isolated by tracing
//! spans alone). This complements that tracing-span result with real
//! function-level attribution inside the step tracing could not subdivide,
//! without touching pinned/frozen source and without needing perf/valgrind.
#[path = "../../../binius-verifier-port/host-runner/src/frozen.rs"]
#[allow(dead_code)]
mod frozen;
extern crate alloc;

use std::{fs, time::Instant};

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
    let iterations: u32 = args
        .get(3)
        .map(|s| s.parse().expect("iterations must be a u32"))
        .unwrap_or(400);
    let hz: i32 = args
        .get(4)
        .map(|s| s.parse().expect("hz must be an i32"))
        .unwrap_or(1000);

    let setup = fs::read(setup_path)?;
    let proof = fs::read(proof_path)?;
    let verifier = frozen::load(&setup)?;

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(hz)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()?;

    let wall_start = Instant::now();
    let mut ok_count = 0u32;
    for _ in 0..iterations {
        let ok = qasset_binius_nostd_verifier::verify_preprocessed_detailed(
            &verifier, &proof, &SCALAR, &ACTION,
        );
        if ok.is_ok() {
            ok_count += 1;
        }
    }
    let wall_total = wall_start.elapsed();

    let report = guard.report().build()?;
    eprintln!(
        "ran {iterations} iterations ({ok_count} accepted) in {:.3}s ({:.2} ms/iter), sampling at {hz} Hz",
        wall_total.as_secs_f64(),
        wall_total.as_secs_f64() * 1000.0 / iterations as f64
    );

    let mut frame_counts: std::collections::HashMap<String, isize> = std::collections::HashMap::new();
    let mut module_counts: std::collections::HashMap<String, isize> = std::collections::HashMap::new();
    let total_samples: isize = report.data.values().sum();
    for (frames, count) in report.data.iter() {
        if let Some(top) = frames.frames.iter().flatten().next() {
            let name = top.name();
            // First two "::"-separated path segments, e.g. "binius_spartan_verifier::wiring".
            let module: String = name.split("::").take(2).collect::<Vec<_>>().join("::");
            *frame_counts.entry(name).or_insert(0) += count;
            *module_counts.entry(module).or_insert(0) += count;
        }
    }
    let mut rows: Vec<(String, isize)> = frame_counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1));
    let mut module_rows: Vec<(String, isize)> = module_counts.into_iter().collect();
    module_rows.sort_by(|a, b| b.1.cmp(&a.1));

    println!("total_samples={total_samples}");
    println!("module_path,samples,pct_of_total");
    for (name, count) in module_rows.iter().take(25) {
        let pct = 100.0 * (*count as f64) / (total_samples.max(1) as f64);
        println!("{name},{count},{pct:.2}");
    }
    println!();
    println!("leaf_frame,samples,pct_of_total");
    for (name, count) in rows.iter().take(40) {
        let pct = 100.0 * (*count as f64) / (total_samples.max(1) as f64);
        println!("{name},{count},{pct:.2}");
    }

    let svg_path = "target/flamegraph.svg";
    let mut file = fs::File::create(svg_path)?;
    report.flamegraph(&mut file)?;
    eprintln!("wrote {svg_path}");

    Ok(())
}
