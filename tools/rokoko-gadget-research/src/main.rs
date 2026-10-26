// SPDX-License-Identifier: MIT
//! Research-only: calibrates understanding of RoKoko's documented "binariness
//! of a region's coefficients" claim recipe (docs/snark.md in the pinned
//! clone) against the real library, before attempting the larger SEP-5
//! hash-preimage relation scoped in docs/ROKOKO_RELATION_WIRING_SCOPE.md.
//! Depends on the pristine, unmodified clone via a path dependency; adds no
//! code to it. Runs both a positive case (genuine 0/1 witness) and a
//! deliberately malicious negative case (a non-binary witness entry), to
//! confirm the claim actually rejects a bad witness rather than passing
//! vacuously.
use rokoko::common::init_common;
use rokoko::common::ring_arithmetic::{Representation, RingElement};
use rokoko::protocol::snark::{
    challenge_point, eq, table, witness_in, Claim, Region, Transcript, WitnessBuilder,
    WitnessShape,
};

/// Builds the documented binariness claim over the whole witness region:
/// `witness_in(r) * witness_in(r).conjugate() - table(ones) * witness_in(r)`,
/// summed, with the shipped value's constant coefficient checked to be zero
/// by the caller after proving (per docs/snark.md's "who computes the
/// value?" case 3: the prover ships the value; the front end only checks
/// ring-element equality, not the "is this coefficient zero" meaning).
fn binariness_value(
    witness: &rokoko::common::matrix::VerticallyAlignedMatrix<RingElement>,
    region: Region,
) -> RingElement {
    let ones = RingElement::all(1, Representation::IncompleteNTT);
    let expr = witness_in(region) * witness_in(region).conjugate()
        - table(vec![ones; region.len()]).on(region.vars()) * witness_in(region);
    expr.sum(witness)
}

fn run_case(name: &str, bits: Vec<u64>) {
    let n = bits.len();
    assert!(n.is_power_of_two());
    let values: Vec<RingElement> = bits
        .iter()
        .map(|&b| RingElement::constant(b, Representation::IncompleteNTT))
        .collect();

    let mut layout = WitnessBuilder::new(n, 1);
    let region = layout.push(&values);
    let witness = layout.finish();

    let energy = binariness_value(&witness, region);

    let build_claims = |_t: &mut Transcript| -> Vec<Claim> {
        vec![Claim::sums_to(
            {
                let ones = RingElement::all(1, Representation::IncompleteNTT);
                witness_in(region) * witness_in(region).conjugate()
                    - table(vec![ones; region.len()]).on(region.vars()) * witness_in(region)
            },
            energy.clone(),
        )]
    };

    let mut prover_transcript = Transcript::new();
    let prover_claims = build_claims(&mut prover_transcript);
    let (proof, _openings) =
        rokoko::protocol::snark::prove_claims(&witness, &prover_claims, &mut prover_transcript);

    let mut verifier_transcript = Transcript::new();
    let verifier_claims = build_claims(&mut verifier_transcript);
    let shape = WitnessShape::new(n, 1);
    let verify_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rokoko::protocol::snark::verify_claims(
            shape,
            &verifier_claims,
            &proof,
            &mut verifier_transcript,
        )
    }));

    let constant_coeff_zero = energy.constant_term_from_incomplete_ntt() == 0;

    match verify_result {
        Ok(_chain_inputs) => {
            println!(
                "{name}: verifier ACCEPTED the sumcheck; shipped-value constant coefficient zero = {constant_coeff_zero} (binariness holds iff this is true AND the sumcheck was accepted)"
            );
        }
        Err(_) => {
            println!("{name}: verifier REJECTED (panicked on a transcript/shape mismatch)");
        }
    }
}

/// Tests the degree-3-per-variable budget directly against the live library,
/// rather than only reading `validate_claims`/`expr_degree` in
/// `lowering.rs:1134-1182`. `w3` alone (three witness factors over the same
/// region, `w*w*w`) is the documented ceiling and should succeed. Multiplying
/// that same term by one more `eq(point)` weight factor should push it to
/// degree 4 and panic, if `expr_degree`'s treatment of `ClaimFactor::Public`
/// (contributing degree 1 to every variable in its support, added via
/// `Product` exactly like a witness factor) is right.
fn run_degree_budget_case(name: &str, add_eq_weight: bool) {
    let n = 4usize;
    let values: Vec<RingElement> = (0..n as u64)
        .map(|v| RingElement::constant(v + 1, Representation::IncompleteNTT))
        .collect();

    let mut layout = WitnessBuilder::new(n, 1);
    let region = layout.push(&values);
    let witness = layout.finish();

    let build_expr = |transcript: &mut Transcript| {
        let w3 = witness_in(region) * witness_in(region) * witness_in(region);
        if add_eq_weight {
            let point = challenge_point(transcript, region.vars().len());
            eq(&point).on(region.vars()) * w3
        } else {
            w3
        }
    };

    let value = {
        let mut t = Transcript::new();
        build_expr(&mut t).sum(&witness)
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut prover_transcript = Transcript::new();
        let claims = vec![Claim::sums_to(build_expr(&mut prover_transcript), value.clone())];
        let (proof, _openings) =
            rokoko::protocol::snark::prove_claims(&witness, &claims, &mut prover_transcript);

        let mut verifier_transcript = Transcript::new();
        let verifier_claims = vec![Claim::sums_to(build_expr(&mut verifier_transcript), value.clone())];
        let shape = WitnessShape::new(n, 1);
        rokoko::protocol::snark::verify_claims(shape, &verifier_claims, &proof, &mut verifier_transcript)
    }));

    match result {
        Ok(_) => println!("{name}: prove_claims/verify_claims SUCCEEDED (degree accepted)"),
        Err(_) => println!("{name}: prove_claims PANICKED (degree budget rejected this shape)"),
    }
}

/// A real "gate" shape, not just a degree probe: proves `r_i = a_i XOR b_i`
/// for every position in a region at once, via one eq-batched claim
/// (`r = a+b-2ab`, degree 3: eq(1) + a(1) + b(1) on the `a*b` branch, within
/// budget with no auxiliary wire needed since only two bits are multiplied).
/// Runs a positive case (genuine XOR) and a negative case (one output bit
/// deliberately wrong) to confirm the claim actually rejects a bad witness.
fn run_xor_gate_case(name: &str, a_bits: Vec<u64>, b_bits: Vec<u64>, r_bits: Vec<u64>) {
    let n = a_bits.len();
    assert_eq!(b_bits.len(), n);
    assert_eq!(r_bits.len(), n);
    assert!(n.is_power_of_two());

    let to_ring = |bits: &[u64]| -> Vec<RingElement> {
        bits.iter()
            .map(|&b| RingElement::constant(b, Representation::IncompleteNTT))
            .collect()
    };

    let mut layout = WitnessBuilder::new(4 * n, 1);
    let a_region = layout.push(&to_ring(&a_bits));
    let b_region = layout.push(&to_ring(&b_bits));
    let r_region = layout.push(&to_ring(&r_bits));
    let witness = layout.finish();

    let two = RingElement::constant(2, Representation::IncompleteNTT);
    let build_expr = |transcript: &mut Transcript| {
        let point = challenge_point(transcript, a_region.vars().len());
        eq(&point).on(a_region.vars())
            * (witness_in(r_region)
                - (witness_in(a_region) + witness_in(b_region)
                    - (witness_in(a_region) * witness_in(b_region)).scale(&two)))
    };

    let value = {
        let mut t = Transcript::new();
        build_expr(&mut t).sum(&witness)
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut prover_transcript = Transcript::new();
        let claims = vec![Claim::sums_to_zero(build_expr(&mut prover_transcript))];
        let _ = value.clone();
        let (proof, _openings) =
            rokoko::protocol::snark::prove_claims(&witness, &claims, &mut prover_transcript);

        let mut verifier_transcript = Transcript::new();
        let verifier_claims = vec![Claim::sums_to_zero(build_expr(&mut verifier_transcript))];
        let shape = WitnessShape::new(4 * n, 1);
        rokoko::protocol::snark::verify_claims(shape, &verifier_claims, &proof, &mut verifier_transcript)
    }));

    match result {
        Ok(_) => println!("{name}: ACCEPTED"),
        Err(_) => println!("{name}: REJECTED (panicked)"),
    }
}

/// Bisection probe: isolates whether a TRUE sub-region (one of several
/// regions sharing a larger witness, needing an actual offset selector) costs
/// more degree budget than a region that happens to cover the whole witness
/// (as in `run_degree_budget_case`, where region.len() == witness size, so no
/// selector is actually needed). Three widening cases: (1) eq times one
/// sub-region witness factor alone; (2) eq times two different sub-region
/// witness factors multiplied together; (3) same as (2) but without eq.
fn run_subregion_bisection() {
    let n = 4usize;
    let mut layout = WitnessBuilder::new(2 * n, 1);
    let a_region = layout.push(&vec![RingElement::constant(1, Representation::IncompleteNTT); n]);
    let b_region = layout.push(&vec![RingElement::constant(1, Representation::IncompleteNTT); n]);
    let witness = layout.finish();

    let try_build = |name: &str, build: &dyn Fn(&mut Transcript) -> rokoko::protocol::snark::ClaimExpr| {
        let value = {
            let mut t = Transcript::new();
            build(&mut t).sum(&witness)
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut pt = Transcript::new();
            let claims = vec![Claim::sums_to(build(&mut pt), value.clone())];
            rokoko::protocol::snark::prove_claims(&witness, &claims, &mut pt)
        }));
        match result {
            Ok(_) => println!("  {name}: OK"),
            Err(_) => println!("  {name}: PANIC"),
        }
    };

    println!("sub-region bisection (witness size {}):", 2 * n);
    try_build("1 sub-region witness factor alone (no eq)", &|_t| witness_in(a_region));
    try_build("eq * 1 sub-region witness factor", &|t| {
        let p = challenge_point(t, a_region.vars().len());
        eq(&p).on(a_region.vars()) * witness_in(a_region)
    });
    try_build("2 sub-region witness factors multiplied, no eq", &|_t| {
        witness_in(a_region) * witness_in(b_region)
    });
    try_build("eq * 2 sub-region witness factors multiplied", &|t| {
        let p = challenge_point(t, a_region.vars().len());
        eq(&p).on(a_region.vars()) * witness_in(a_region) * witness_in(b_region)
    });
}

/// Checks the ring's slot-pairing layout directly: does coefficient k pair
/// with k+NUM_SLOTS (a "strided" layout, which would make v[0] and v[1]
/// independent pure-scalar slots when their stride-paired partners are
/// zero), or k+1 (adjacent pairing, which would make v[0] and v[1] mix via
/// the slot's quadratic-extension multiplication, "5 mults + 2 adds" per
/// `slot_mult`)? This decides whether packing two different secret values
/// into v[0] and v[1] of one ring element and squaring it gives independent
/// v[0]^2 / v[1]^2 (useful) or a mixed cross-term (not what was assumed).
fn probe_slot_pairing() {
    let mut e = RingElement::zero(Representation::StridedCoefficients);
    e.v[0] = 3;
    e.v[1] = 5;
    e.to_representation(Representation::IncompleteNTT);
    let squared = {
        let mut r = RingElement::zero(Representation::IncompleteNTT);
        rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(&mut r, &e, &e);
        r
    };
    let mut back = squared;
    back.to_representation(Representation::StridedCoefficients);
    println!(
        "slot-pairing probe: v[0]^2={} (expect 9 if independent), v[1]^2={} (expect 25 if independent), v[64]={}, v[65]={}",
        back.v[0], back.v[1], back.v[64], back.v[65]
    );
}

/// Checks whether slot 0's omega=0 (dual numbers, confirmed by
/// `probe_slot_pairing`) is special, or whether every slot degenerates the
/// same way, by testing a different coefficient pair (v[2], v[3]) and
/// solving for omega algebraically from the observed result:
/// result0 = a0*b0 + omega*a1*b1, so for a self-product (a0,a1)^2, omega =
/// (result0 - a0^2) / a1^2 (mod q), computed here over plain u64/u128
/// arithmetic since MOD_Q fits in 50 bits and no value here approaches it.
fn probe_second_slot_and_omega() {
    const MOD_Q: u128 = 1125899906839937;
    let mut e = RingElement::zero(Representation::StridedCoefficients);
    e.v[2] = 7;
    e.v[3] = 11;
    e.to_representation(Representation::IncompleteNTT);
    let mut squared = RingElement::zero(Representation::IncompleteNTT);
    rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(&mut squared, &e, &e);
    squared.to_representation(Representation::StridedCoefficients);
    let r0 = squared.v[2] as u128;
    let r1 = squared.v[3] as u128;
    let a0 = 7u128;
    let a1 = 11u128;
    let a1_sq_inv = mod_inverse((a1 * a1) % MOD_Q, MOD_Q);
    let omega = ((r0 + MOD_Q - (a0 * a0) % MOD_Q) % MOD_Q) * a1_sq_inv % MOD_Q;
    println!(
        "slot 1 (v[2],v[3]) probe: r0={r0} (a0^2={}), r1={r1} (2*a0*a1={}), solved omega={omega}",
        a0 * a0,
        2 * a0 * a1
    );
}

fn mod_inverse(a: u128, m: u128) -> u128 {
    // Fermat's little theorem: a^(m-2) mod m, since m is intended to be prime.
    let mut result = 1u128;
    let mut base = a % m;
    let mut exp = m - 2;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % m;
        }
        base = (base * base) % m;
        exp >>= 1;
    }
    result
}

/// If a non-degenerate slot (omega != 0) is found, tests whether scaling the
/// squared self-product by the ring element X = (0,1) cleanly swaps which
/// coefficient holds the cross term 2*a*b, as the algebra
/// X*((a0^2+omega*a1^2) + 2a0a1*X) = 2*omega*a0*a1 + (a0^2+omega*a1^2)*X
/// (using X^2=omega) predicts.
fn probe_x_scaling_swap(coeff_pair: (usize, usize), a0: u64, a1: u64) {
    let mut e = RingElement::zero(Representation::StridedCoefficients);
    e.v[coeff_pair.0] = a0;
    e.v[coeff_pair.1] = a1;
    e.to_representation(Representation::IncompleteNTT);
    let mut squared = RingElement::zero(Representation::IncompleteNTT);
    rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(&mut squared, &e, &e);

    let mut x_elem = RingElement::zero(Representation::StridedCoefficients);
    x_elem.v[coeff_pair.1] = 1;
    x_elem.to_representation(Representation::IncompleteNTT);

    let mut scaled = RingElement::zero(Representation::IncompleteNTT);
    rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(&mut scaled, &squared, &x_elem);
    scaled.to_representation(Representation::StridedCoefficients);
    println!(
        "X-scaling probe on slot ({},{}) a0={a0} a1={a1}: scaled[{}]={} (expect omega*2ab), scaled[{}]={} (expect a0^2+omega*a1^2)",
        coeff_pair.0, coeff_pair.1, coeff_pair.0, scaled.v[coeff_pair.0], coeff_pair.1, scaled.v[coeff_pair.1]
    );
}

/// Decisive check: is the (v[0],v[1]) -> (a^2, 2ab) pattern from
/// `probe_slot_pairing` a real, controllable mechanism, or a coincidence of
/// that one small input? `from_strided_coefficients_to_incomplete_ntt_representation`
/// calls a genuine global NTT (`SLOT_RING.ntt_forward`), not a per-pair
/// relabeling, so the (v[0],v[1])-before-transform to "slot" mapping is not
/// guaranteed to be simple. Tests several different (a,b) pairs.
fn probe_pattern_generality() {
    for (a, b) in [(3u64, 5u64), (1, 2), (10, 1), (6, 6), (100, 7), (0, 1)] {
        let mut e = RingElement::zero(Representation::StridedCoefficients);
        e.v[0] = a;
        e.v[1] = b;
        e.to_representation(Representation::IncompleteNTT);
        let mut squared = RingElement::zero(Representation::IncompleteNTT);
        rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(&mut squared, &e, &e);
        squared.to_representation(Representation::StridedCoefficients);
        let expected0 = a * a;
        let expected1 = 2 * a * b;
        let matches = squared.v[0] == expected0 && squared.v[1] == expected1;
        println!(
            "pattern check a={a} b={b}: got v[0]={} v[1]={}, expected v[0]={expected0} v[1]={expected1} -> {}",
            squared.v[0],
            squared.v[1],
            if matches { "MATCH" } else { "MISMATCH" }
        );
    }
}

/// The real test: can a FRESH, separately-committed region `p_ab` be tied
/// to the validated `2*a_i*b_i` cross term from squaring an `ab_region`
/// (packed a_i in v[0], b_i in v[1]), via one eq-weighted claim? This is
/// the actual operation the addition/AND gadget needs -- p_ab must be its
/// own committed witness region (not just an ephemeral expression) so later
/// gates can read it. Tests both a direct attempt and, if that panics, a
/// fallback without the eq weight (to see whether dropping the eq -- and
/// accepting only an aggregate-sum, non-pointwise guarantee -- is what
/// would be needed, which would mean this construction is unsound for
/// pointwise claims regardless of degree).
fn run_tie_fresh_region_case(n: usize, a_vals: &[u64], b_vals: &[u64], corrupt_one: bool) {
    assert_eq!(a_vals.len(), n);
    assert_eq!(b_vals.len(), n);

    let ab_values: Vec<RingElement> = (0..n)
        .map(|i| {
            let mut e = RingElement::zero(Representation::StridedCoefficients);
            e.v[0] = a_vals[i];
            e.v[1] = b_vals[i];
            e.to_representation(Representation::IncompleteNTT);
            e
        })
        .collect();
    // p_ab must equal the FULL square (both coefficients), not just a_i*b_i
    // in v[0] alone -- the earlier panic was this exact bug, not a degree
    // or system limitation.
    let p_ab_values: Vec<RingElement> = (0..n)
        .map(|i| {
            let mut squared = RingElement::zero(Representation::IncompleteNTT);
            rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(
                &mut squared,
                &ab_values[i],
                &ab_values[i],
            );
            if corrupt_one && i == 0 {
                // Malicious witness: claim a wrong product for position 0.
                squared.to_representation(Representation::StridedCoefficients);
                squared.v[1] = squared.v[1].wrapping_add(1);
                squared.to_representation(Representation::IncompleteNTT);
            }
            squared
        })
        .collect();

    let mut layout = WitnessBuilder::new(2 * n, 1);
    let ab_region = layout.push(&ab_values);
    let p_ab_region = layout.push(&p_ab_values);
    let witness = layout.finish();

    let try_with_eq = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let build = |t: &mut Transcript| {
            let point = challenge_point(t, ab_region.vars().len());
            eq(&point).on(ab_region.vars())
                * (witness_in(p_ab_region) - witness_in(ab_region) * witness_in(ab_region))
        };
        let mut pt = Transcript::new();
        let claims = vec![Claim::sums_to_zero(build(&mut pt))];
        let (proof, _o) = rokoko::protocol::snark::prove_claims(&witness, &claims, &mut pt);
        let mut vt = Transcript::new();
        let vclaims = vec![Claim::sums_to_zero(build(&mut vt))];
        let shape = WitnessShape::new(2 * n, 1);
        rokoko::protocol::snark::verify_claims(shape, &vclaims, &proof, &mut vt)
    }));
    match &try_with_eq {
        Ok(_) => println!("tie fresh region WITH eq: ACCEPTED (sound pointwise tie achieved)"),
        Err(_) => println!("tie fresh region WITH eq: PANICKED (degree budget exceeded or rejected)"),
    }

    let try_without_eq = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let build = |_t: &mut Transcript| {
            witness_in(p_ab_region) - witness_in(ab_region) * witness_in(ab_region)
        };
        let mut pt = Transcript::new();
        let claims = vec![Claim::sums_to_zero(build(&mut pt))];
        let (proof, _o) = rokoko::protocol::snark::prove_claims(&witness, &claims, &mut pt);
        let mut vt = Transcript::new();
        let vclaims = vec![Claim::sums_to_zero(build(&mut vt))];
        let shape = WitnessShape::new(2 * n, 1);
        rokoko::protocol::snark::verify_claims(shape, &vclaims, &proof, &mut vt)
    }));
    match &try_without_eq {
        Ok(_) => println!("tie fresh region WITHOUT eq: ACCEPTED (degree ok, but is it pointwise-sound?)"),
        Err(_) => println!("tie fresh region WITHOUT eq: PANICKED (degree budget exceeded or rejected)"),
    }
}

/// The capstone test: a full AND+XOR gate between two independently-secret
/// bit streams a, b, using the validated pattern (pack a_i,b_i into one
/// region's two coefficients, tie a fresh p_ab region to that region's
/// self-product, extract AND from p_ab's v[1], then tie a fresh xor_result
/// region to a+b-2*AND via a second eq-weighted claim). Tests honest bits,
/// and two separate malicious witnesses (wrong AND claim; wrong XOR claim)
/// to confirm both ties are independently enforced, not just one.
fn run_and_xor_gate_case(name: &str, a_bits: Vec<u64>, b_bits: Vec<u64>, corrupt: Corrupt) {
    let n = a_bits.len();
    assert_eq!(b_bits.len(), n);

    let ab_values: Vec<RingElement> = (0..n)
        .map(|i| {
            let mut e = RingElement::zero(Representation::StridedCoefficients);
            e.v[0] = a_bits[i];
            e.v[1] = b_bits[i];
            e.to_representation(Representation::IncompleteNTT);
            e
        })
        .collect();
    let p_ab_values: Vec<RingElement> = (0..n)
        .map(|i| {
            let mut squared = RingElement::zero(Representation::IncompleteNTT);
            rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(
                &mut squared,
                &ab_values[i],
                &ab_values[i],
            );
            if matches!(corrupt, Corrupt::And) && i == 0 {
                squared.to_representation(Representation::StridedCoefficients);
                squared.v[1] = squared.v[1].wrapping_add(1);
                squared.to_representation(Representation::IncompleteNTT);
            }
            squared
        })
        .collect();
    let xor_values: Vec<RingElement> = (0..n)
        .map(|i| {
            let and_i = a_bits[i] * b_bits[i];
            let mut xor_i = a_bits[i] + b_bits[i] - 2 * and_i;
            if matches!(corrupt, Corrupt::Xor) && i == 0 {
                xor_i ^= 1;
            }
            // xor_i lands in v[1] of the combination below (confirmed by
            // direct computation: ab+ab*X-p_ab = (a,b)+(0,a)-(a,2ab) =
            // (0, a+b-2ab) using X^2=0 for this slot), so xor_region must
            // be committed with v[1]=xor_i, not v[0].
            let mut e = RingElement::zero(Representation::StridedCoefficients);
            e.v[1] = xor_i;
            e.to_representation(Representation::IncompleteNTT);
            e
        })
        .collect();

    let mut layout = WitnessBuilder::new(4 * n, 1);
    let ab_region = layout.push(&ab_values);
    let p_ab_region = layout.push(&p_ab_values);
    let xor_region = layout.push(&xor_values);
    layout.push(&vec![RingElement::zero(Representation::IncompleteNTT); n]); // padding
    let witness = layout.finish();

    let x_elem = {
        let mut e = RingElement::zero(Representation::StridedCoefficients);
        e.v[1] = 1;
        e.to_representation(Representation::IncompleteNTT);
        e
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let build_and_tie = |t: &mut Transcript| {
            let point = challenge_point(t, ab_region.vars().len());
            eq(&point).on(ab_region.vars())
                * (witness_in(p_ab_region) - witness_in(ab_region) * witness_in(ab_region))
        };
        // p_ab's v[1] coefficient holds 2*AND; scaling by X swaps it into
        // v[0] alongside a scaled copy of p_ab's v[0] into v[1] -- but since
        // we only need the VALUE (not a clean single-coefficient read) for
        // a further linear tie, we instead tie xor directly against
        // witness_in(ab_region)'s own v[0]+v[1] (a,b individually, degree 1
        // each, cheap) combined with p_ab's v[1] via the x_elem swap trick,
        // all still within one eq-weighted claim.
        let build_xor_tie = |t: &mut Transcript| {
            let point = challenge_point(t, ab_region.vars().len());
            // (a,b) + (a,b)*X - (a,2ab) = (a,b)+(0,a)-(a,2ab) = (0,a+b-2ab)
            // using X^2=0 in this slot (confirmed empirically earlier).
            eq(&point).on(ab_region.vars())
                * (witness_in(xor_region)
                    - (witness_in(ab_region) + witness_in(ab_region).scale(&x_elem)
                        - witness_in(p_ab_region)))
        };
        let mut pt = Transcript::new();
        let claims = vec![
            Claim::sums_to_zero(build_and_tie(&mut pt)),
            Claim::sums_to_zero(build_xor_tie(&mut pt)),
        ];
        let (proof, _o) = rokoko::protocol::snark::prove_claims(&witness, &claims, &mut pt);
        let mut vt = Transcript::new();
        let vclaims = vec![
            Claim::sums_to_zero(build_and_tie(&mut vt)),
            Claim::sums_to_zero(build_xor_tie(&mut vt)),
        ];
        let shape = WitnessShape::new(4 * n, 1);
        rokoko::protocol::snark::verify_claims(shape, &vclaims, &proof, &mut vt)
    }));
    match result {
        Ok(_) => println!("{name}: ACCEPTED"),
        Err(_) => println!("{name}: REJECTED (panicked)"),
    }
}

#[derive(Clone, Copy)]
enum Corrupt {
    None,
    And,
    Xor,
}

/// Computes (p_ab, xor) committed regions tied to a and b, exactly as
/// `run_and_xor_gate_case` validates, but as a reusable building block:
/// returns the two regions plus the witness data needed, and pushes the two
/// tie claims into `claims`. `witness_data` accumulates the actual
/// RingElement values (the caller finishes the WitnessBuilder once all
/// gates are laid out).
struct AndXorGate {
    ab_region: Region,
    p_ab_region: Region,
    xor_region: Region,
}

fn lay_out_and_xor_gate(
    layout: &mut WitnessBuilder,
    a: &[u64],
    b: &[u64],
    corrupt_and: bool,
    corrupt_xor: bool,
) -> AndXorGate {
    let n = a.len();
    let ab_values: Vec<RingElement> = (0..n)
        .map(|i| {
            let mut e = RingElement::zero(Representation::StridedCoefficients);
            e.v[0] = a[i];
            e.v[1] = b[i];
            e.to_representation(Representation::IncompleteNTT);
            e
        })
        .collect();
    let p_ab_values: Vec<RingElement> = (0..n)
        .map(|i| {
            let mut squared = RingElement::zero(Representation::IncompleteNTT);
            rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(
                &mut squared,
                &ab_values[i],
                &ab_values[i],
            );
            if corrupt_and && i == 0 {
                squared.to_representation(Representation::StridedCoefficients);
                squared.v[1] ^= 1;
                squared.to_representation(Representation::IncompleteNTT);
            }
            squared
        })
        .collect();
    let xor_values: Vec<RingElement> = (0..n)
        .map(|i| {
            let mut xor_i = a[i] ^ b[i];
            if corrupt_xor && i == 0 {
                xor_i ^= 1;
            }
            let mut e = RingElement::zero(Representation::StridedCoefficients);
            e.v[1] = xor_i;
            e.to_representation(Representation::IncompleteNTT);
            e
        })
        .collect();
    let ab_region = layout.push(&ab_values);
    let p_ab_region = layout.push(&p_ab_values);
    let xor_region = layout.push(&xor_values);
    AndXorGate {
        ab_region,
        p_ab_region,
        xor_region,
    }
}

fn and_xor_tie_claims(t: &mut Transcript, gate: &AndXorGate, x_elem: &RingElement) -> Vec<rokoko::protocol::snark::ClaimExpr> {
    let point_and = challenge_point(t, gate.ab_region.vars().len());
    let and_tie = eq(&point_and).on(gate.ab_region.vars())
        * (witness_in(gate.p_ab_region) - witness_in(gate.ab_region) * witness_in(gate.ab_region));
    let point_xor = challenge_point(t, gate.ab_region.vars().len());
    let xor_tie = eq(&point_xor).on(gate.ab_region.vars())
        * (witness_in(gate.xor_region)
            - (witness_in(gate.ab_region) + witness_in(gate.ab_region).scale(x_elem)
                - witness_in(gate.p_ab_region)));
    vec![and_tie, xor_tie]
}

/// A full 1-bit adder (a, b, carry-in -> sum, carry-out), built from NOTHING
/// but the already-validated AND+XOR gate, applied twice:
///   s1 = a xor b;  c1 = a and b          (gate 1, on a,b)
///   sum = s1 xor cin;  c2 = s1 and cin    (gate 2, on s1,cin)
///   carry_out = c1 xor c2                 (gate 3, on c1,c2; = OR since
///     c1,c2 are mutually exclusive in a valid full adder, confirmed by
///     brute-force truth table below, not assumed)
/// No decompose_bits, no shipped value, no MOD_Q limb-splitting -- this
/// avoids the "ship the value" secrecy problem the digit-recomposition
/// recipe would otherwise require for a SECRET running sum.
fn run_full_adder_case(name: &str, a_bits: Vec<u64>, b_bits: Vec<u64>, cin_bits: Vec<u64>, corrupt: Corrupt2) {
    let n = a_bits.len();
    assert_eq!(b_bits.len(), n);
    assert_eq!(cin_bits.len(), n);

    let x_elem = {
        let mut e = RingElement::zero(Representation::StridedCoefficients);
        e.v[1] = 1;
        e.to_representation(Representation::IncompleteNTT);
        e
    };

    let mut layout = WitnessBuilder::new(512, 1);
    let gate1 = lay_out_and_xor_gate(&mut layout, &a_bits, &b_bits, matches!(corrupt, Corrupt2::Gate1And), matches!(corrupt, Corrupt2::Gate1Xor));
    // s1 (the xor_region of gate1) feeds gate 2 together with cin.
    let s1_values: Vec<u64> = (0..n).map(|i| a_bits[i] ^ b_bits[i]).collect();
    let gate2 = lay_out_and_xor_gate(&mut layout, &s1_values, &cin_bits, matches!(corrupt, Corrupt2::Gate2And), matches!(corrupt, Corrupt2::Gate2Xor));
    // c1 (gate1's AND, in p_ab's v[1]) and c2 (gate2's AND) feed gate 3.
    let c1_values: Vec<u64> = (0..n).map(|i| a_bits[i] & b_bits[i]).collect();
    let c2_values: Vec<u64> = (0..n).map(|i| s1_values[i] & cin_bits[i]).collect();
    let gate3 = lay_out_and_xor_gate(&mut layout, &c1_values, &c2_values, matches!(corrupt, Corrupt2::Gate3And), matches!(corrupt, Corrupt2::Gate3Xor));
    let witness = layout.finish();

    // Truth-table sanity check (off-circuit, not part of the proof): c1 and
    // c2 are never both 1, so carry_out = c1 xor c2 really does equal OR,
    // i.e. the true majority(a,b,cin).
    for i in 0..n {
        let expected_carry = (a_bits[i] & b_bits[i]) | (a_bits[i] & cin_bits[i]) | (b_bits[i] & cin_bits[i]);
        let c1 = c1_values[i];
        let c2 = c2_values[i];
        assert_eq!(c1 & c2, 0, "c1,c2 not mutually exclusive at position {i}");
        assert_eq!(c1 ^ c2, expected_carry, "carry_out mismatch at position {i}");
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let build = |t: &mut Transcript| {
            let mut claims = and_xor_tie_claims(t, &gate1, &x_elem);
            claims.extend(and_xor_tie_claims(t, &gate2, &x_elem));
            claims.extend(and_xor_tie_claims(t, &gate3, &x_elem));
            claims
                .into_iter()
                .map(Claim::sums_to_zero)
                .collect::<Vec<_>>()
        };
        let mut pt = Transcript::new();
        let claims = build(&mut pt);
        let (proof, _o) = rokoko::protocol::snark::prove_claims(&witness, &claims, &mut pt);
        let mut vt = Transcript::new();
        let vclaims = build(&mut vt);
        let shape = WitnessShape::new(512, 1);
        rokoko::protocol::snark::verify_claims(shape, &vclaims, &proof, &mut vt)
    }));
    match result {
        Ok(_) => println!("{name}: ACCEPTED"),
        Err(_) => println!("{name}: REJECTED (panicked)"),
    }
}

#[derive(Clone, Copy)]
enum Corrupt2 {
    None,
    Gate1And,
    Gate1Xor,
    Gate2And,
    Gate2Xor,
    Gate3And,
    Gate3Xor,
}

/// Tests whether a "shift by one position" relationship between two
/// regions (B[i] = A[i-1]) is expressible via the documented "tie two
/// regions together" recipe as literally written (`witness_in(original) -
/// witness_in(mirror)`, same index on both sides) -- or whether, as the
/// recipe's text suggests ("original.vars()" used for both reads, not a
/// shifted index), that recipe only ties two SAME-INDEX regions, and a
/// genuine shift needs individual length-1 region ties instead (no
/// alignment constraint for length 1, and no eq needed since a 1-point
/// "cube" has nothing to average over).
fn probe_shift_via_batched_eq() {
    // A region of length 4, and a "mirror" also of length 4, where mirror
    // is constructed to be A shifted by one (mirror[i] = A[(i+3)%4]).
    let a_vals = [10u64, 20, 30, 40];
    let mirror_vals = [a_vals[3], a_vals[0], a_vals[1], a_vals[2]]; // shift by 1
    let a_region_vals: Vec<RingElement> = a_vals
        .iter()
        .map(|&v| RingElement::constant(v, Representation::IncompleteNTT))
        .collect();
    let mirror_region_vals: Vec<RingElement> = mirror_vals
        .iter()
        .map(|&v| RingElement::constant(v, Representation::IncompleteNTT))
        .collect();
    let mut layout = WitnessBuilder::new(8, 1);
    let a_region = layout.push(&a_region_vals);
    let mirror_region = layout.push(&mirror_region_vals);
    let witness = layout.finish();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let build = |t: &mut Transcript| {
            let point = challenge_point(t, a_region.vars().len());
            eq(&point).on(a_region.vars()) * (witness_in(a_region) - witness_in(mirror_region))
        };
        let mut pt = Transcript::new();
        let claims = vec![Claim::sums_to_zero(build(&mut pt))];
        let (proof, _o) = rokoko::protocol::snark::prove_claims(&witness, &claims, &mut pt);
        let mut vt = Transcript::new();
        let vclaims = vec![Claim::sums_to_zero(build(&mut vt))];
        let shape = WitnessShape::new(8, 1);
        rokoko::protocol::snark::verify_claims(shape, &vclaims, &proof, &mut vt)
    }));
    match result {
        Ok(_) => println!(
            "shift-via-batched-eq probe: ACCEPTED (the recipe as literally written treats \
             mirror as already-shifted data, i.e. same-index comparison works for pre-shifted data)"
        ),
        Err(_) => println!(
            "shift-via-batched-eq probe: REJECTED (the recipe compares same-index entries; \
             mirror's pre-shifted DATA still needs tying back to the true source some other way)"
        ),
    }
}

/// Tests the individual-length-1-region alternative for a genuine shift: no
/// eq weight, no alignment constraint (length 1 divides everything), one
/// claim per position, tying position i of region B directly to position
/// i-1 of region A.
fn probe_shift_via_individual_length1_ties(corrupt: bool) {
    let a_vals = [10u64, 20, 30, 40];
    let a_region_vals: Vec<RingElement> = a_vals
        .iter()
        .map(|&v| RingElement::constant(v, Representation::IncompleteNTT))
        .collect();
    // b[i] should equal a[i-1] for i=1..3 (b[0] is unconstrained here).
    let mut b_vals = [0u64, a_vals[0], a_vals[1], a_vals[2]];
    if corrupt {
        b_vals[2] = 999;
    }
    let b_region_vals: Vec<RingElement> = b_vals
        .iter()
        .map(|&v| RingElement::constant(v, Representation::IncompleteNTT))
        .collect();
    let mut layout = WitnessBuilder::new(8, 1);
    let a_region = layout.push(&a_region_vals);
    let b_region = layout.push(&b_region_vals);
    let witness = layout.finish();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let build = |_t: &mut Transcript| {
            let mut claims = vec![];
            for i in 1..4usize {
                let a_i = Region::new(a_region.start() + i - 1, 1, 8);
                let b_i = Region::new(b_region.start() + i, 1, 8);
                claims.push(Claim::sums_to_zero(witness_in(b_i) - witness_in(a_i)));
            }
            claims
        };
        let mut pt = Transcript::new();
        let claims = build(&mut pt);
        let (proof, _o) = rokoko::protocol::snark::prove_claims(&witness, &claims, &mut pt);
        let mut vt = Transcript::new();
        let vclaims = build(&mut vt);
        let shape = WitnessShape::new(8, 1);
        rokoko::protocol::snark::verify_claims(shape, &vclaims, &proof, &mut vt)
    }));
    match result {
        Ok(_) => println!(
            "individual-length1-shift-ties ({}): ACCEPTED",
            if corrupt { "malicious" } else { "honest" }
        ),
        Err(_) => println!(
            "individual-length1-shift-ties ({}): REJECTED (panicked)",
            if corrupt { "malicious" } else { "honest" }
        ),
    }
}

/// The monomial `coeff * X^k` in `Z_q[X]/(X^128 + 1)`. `StridedCoefficients`
/// is a permutation of the true coefficient basis
/// (`strided[i + part*NUM_SLOTS] = coeff[SLOT_DEGREE*i + part]`,
/// `ring_arithmetic.rs` `from_coefficients_to_strided_coefficients`), so
/// coefficient index k lives at strided index `k/2 + (k%2)*64`.
fn monomial(k: usize, coeff: u64) -> RingElement {
    assert!(k < 128);
    let mut e = RingElement::zero(Representation::StridedCoefficients);
    e.v[k / 2 + (k % 2) * 64] = coeff;
    e.to_representation(Representation::IncompleteNTT);
    e
}

/// Reads true polynomial coefficients `X^0..X^count` of a ring element.
fn true_coeffs(e: &RingElement, count: usize) -> Vec<u64> {
    let mut s = e.clone();
    s.to_representation(Representation::StridedCoefficients);
    (0..count).map(|k| s.v[k / 2 + (k % 2) * 64]).collect()
}

/// Confirms the negacyclic polynomial model directly, which replaces the
/// earlier "omega=0 quadratic slot" explanation: (a + b*X^2)^2 should put
/// a^2 at X^0, 2ab at X^2 and b^2 at X^4; X^127 * X should be -1.
fn probe_ring_model() {
    let (a, b) = (3u64, 5u64);
    let mut e = RingElement::zero(Representation::StridedCoefficients);
    e.v[0] = a;
    e.v[1] = b;
    e.to_representation(Representation::IncompleteNTT);
    let mut sq = RingElement::zero(Representation::IncompleteNTT);
    rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(&mut sq, &e, &e);
    println!("ring model: strided (v0=3,v1=5) as true coeffs X^0..X^5 = {:?}", true_coeffs(&e, 6));
    println!("ring model: its square, true coeffs X^0..X^5 = {:?} (expect [9,0,30,0,25,0])", true_coeffs(&sq, 6));
    let mut wrap = RingElement::zero(Representation::IncompleteNTT);
    rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(&mut wrap, &monomial(127, 1), &monomial(1, 1));
    println!("ring model: X^127 * X, X^0 coeff = {} (expect q-1 = 1125899906839936)", true_coeffs(&wrap, 1)[0]);
    let u = {
        let mut u = RingElement::zero(Representation::StridedCoefficients);
        u.v[0] = 2;
        u.v[64] = 3; // X^1
        u.v[1] = 4; // X^2
        u.to_representation(Representation::IncompleteNTT);
        u
    };
    let mut uu = RingElement::zero(Representation::IncompleteNTT);
    rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(&mut uu, &u, &u.conjugate());
    println!("ring model: ct(u*conj(u)) for u=2+3X+4X^2 = {} (expect 4+9+16=29)", uu.constant_term_from_incomplete_ntt());
}

const SQRT2_MOD_Q: u64 = 1063640708289491;

fn ring_add(x: &RingElement, y: &RingElement) -> RingElement {
    let mut r = RingElement::zero(Representation::IncompleteNTT);
    rokoko::common::ring_arithmetic::addition(&mut r, x, y);
    r
}

fn ring_sub(x: &RingElement, y: &RingElement) -> RingElement {
    let mut r = RingElement::zero(Representation::IncompleteNTT);
    rokoko::common::ring_arithmetic::subtraction(&mut r, x, y);
    r
}

fn ring_mul(x: &RingElement, y: &RingElement) -> RingElement {
    let mut r = RingElement::zero(Representation::IncompleteNTT);
    rokoko::common::ring_arithmetic::incomplete_ntt_multiplication(&mut r, x, y);
    r
}

/// Attacks the earlier AND/XOR gate (`and_xor_tie_claims`) with an adversary
/// the earlier malicious tests never tried: junk in a coefficient the gate
/// gives no meaning to. Inputs a=1, b=0 (true AND=0). The prover packs
/// ab = 1 + sqrt(2)*X (junk at X^1, inputs at X^0 and X^2 untouched), so
/// ab^2 = 1 + 2*sqrt(2)*X + 2*X^2: the X^2 coefficient the gate reads as
/// "2*AND" is 2, i.e. AND reads as 1. The prover sets p_ab and xor_region to
/// exactly what the ties demand, so every tie holds.
fn probe_old_gate_junk_attack() {
    let n = 4usize;
    let a = [1u64, 0, 1, 1];
    let b = [0u64, 1, 0, 1];
    let x_elem = monomial(2, 1);
    let mut ab_vals = vec![];
    let mut p_vals = vec![];
    let mut xor_vals = vec![];
    for i in 0..n {
        let mut ab = RingElement::zero(Representation::StridedCoefficients);
        ab.v[0] = a[i];
        ab.v[1] = b[i];
        if i == 0 {
            ab.v[64] = SQRT2_MOD_Q; // junk at X^1
        }
        ab.to_representation(Representation::IncompleteNTT);
        let p = ring_mul(&ab, &ab);
        let xor = if i == 0 {
            // exactly what the old XOR tie demands: ab + ab*X^2 - p
            ring_sub(&ring_add(&ab, &ring_mul(&ab, &x_elem)), &p)
        } else {
            monomial(2, a[i] ^ b[i])
        };
        ab_vals.push(ab);
        p_vals.push(p);
        xor_vals.push(xor);
    }
    let and_read = true_coeffs(&p_vals[0], 3)[2];
    let mut layout = WitnessBuilder::new(4 * n, 1);
    let gate = AndXorGate {
        ab_region: layout.push(&ab_vals),
        p_ab_region: layout.push(&p_vals),
        xor_region: layout.push(&xor_vals),
    };
    let witness = layout.finish();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let build = |t: &mut Transcript| {
            and_xor_tie_claims(t, &gate, &x_elem)
                .into_iter()
                .map(Claim::sums_to_zero)
                .collect::<Vec<_>>()
        };
        let mut pt = Transcript::new();
        let claims = build(&mut pt);
        let (proof, _o) = rokoko::protocol::snark::prove_claims(&witness, &claims, &mut pt);
        let mut vt = Transcript::new();
        let vclaims = build(&mut vt);
        rokoko::protocol::snark::verify_claims(WitnessShape::new(4 * n, 1), &vclaims, &proof, &mut vt)
    }));
    println!(
        "OLD gate under junk-coefficient attack (a=1,b=0, true AND=0): X^2 coeff of p_ab = {and_read} \
         (reads as AND={}), proof {}",
        if and_read == 2 { 1 } else { 0 },
        if result.is_ok() { "ACCEPTED -> soundness gap confirmed" } else { "REJECTED" }
    );
}

// ---------------------------------------------------------------------------
// Canonical design: every wire is a pure scalar bit (constant polynomial in
// {0,1}). Only primary inputs need an explicit canonicality check; gate
// outputs are forced canonical by the gate's ties.
// ---------------------------------------------------------------------------

/// A region of 2n entries [c_0..c_{n-1}, 1-c_0..1-c_{n-1}]. The complement
/// half makes the shipped values of the binariness/scalar checks equal to
/// public constants (n * ...), so they leak nothing about the bits -- the
/// documented binariness recipe applied to the bits alone would ship a value
/// revealing their Hamming weight.
struct CanonBits {
    full: Region,
    bits: Region,
    comp: Region,
}

fn push_canonical_bits(
    layout: &mut WitnessBuilder,
    bits: &[u64],
    witness_len: usize,
    tamper: Option<(usize, RingElement, RingElement)>,
) -> CanonBits {
    let n = bits.len();
    let mut vals: Vec<RingElement> = bits
        .iter()
        .map(|&c| RingElement::constant(c, Representation::IncompleteNTT))
        .collect();
    vals.extend(bits.iter().map(|&c| RingElement::constant(1 - c, Representation::IncompleteNTT)));
    if let Some((i, bit_val, comp_val)) = tamper {
        vals[i] = bit_val;
        vals[n + i] = comp_val;
    }
    let full = layout.push(&vals);
    CanonBits {
        full,
        bits: Region::new(full.start(), n, witness_len),
        comp: Region::new(full.start() + n, n, witness_len),
    }
}

fn conj_ones() -> RingElement {
    RingElement::all(1, Representation::IncompleteNTT).conjugate()
}

/// The two shipped-value expressions: binariness (constant term =
/// sum over all coefficients of x(x-1), zero iff all coefficients are bits,
/// given no wraparound mod q) and scalar-ness (constant term = sum of all
/// non-constant coefficients, zero iff they are all zero, given they are
/// bits). Their constant terms must be checked by the caller.
fn canonical_shipped_exprs(cb: &CanonBits) -> Vec<rokoko::protocol::snark::ClaimExpr> {
    let len = cb.full.len();
    let co = conj_ones();
    let co_minus_one = ring_sub(&co, &RingElement::constant(1, Representation::IncompleteNTT));
    vec![
        witness_in(cb.full) * witness_in(cb.full).conjugate()
            - table(vec![co; len]).on(cb.full.vars()) * witness_in(cb.full),
        table(vec![co_minus_one; len]).on(cb.full.vars()) * witness_in(cb.full),
    ]
}

/// The complement tie: bits_k + comp_k = 1 for every k, via a random eq
/// point; the target value is computed from public data only.
fn canonical_complement_claim(t: &mut Transcript, cb: &CanonBits) -> Claim {
    let n = cb.bits.len();
    let pt = challenge_point(t, cb.bits.vars().len());
    let target = rokoko::protocol::snark::eq_weighted_sum(
        &pt,
        &vec![RingElement::constant(1, Representation::IncompleteNTT); n],
    );
    Claim::sums_to(eq(&pt).on(cb.bits.vars()) * (witness_in(cb.bits) + witness_in(cb.comp)), target)
}

/// A gate over canonical scalar-bit input regions A, B: AND output C and
/// XOR output D, using one auxiliary packed region ab and three ties:
///   t1: ab = A + B*X^2                       (packing, forced exactly)
///   t2: ab*ab = A + B*X^4 + 2*C*X^2          (forces C = A*B, since
///        (A+BX^2)^2 = A^2 + 2AB X^2 + B^2 X^4 and A^2=A, B^2=B for bits,
///        and 2*X^2 is invertible in Z_q[X]/(X^128+1))
///   t3: D = A + B - 2C                       (XOR, linear)
/// C and D are therefore forced to be canonical bits without any check of
/// their own; junk in ab is impossible because t1 pins ab exactly.
struct Gate {
    ab: Region,
    c: Region,
    d: Region,
}

#[derive(Clone, Copy, PartialEq)]
enum GateTamper {
    None,
    JunkAb(usize),
    WrongAnd(usize),
    WrongXor(usize),
}

fn push_gate(layout: &mut WitnessBuilder, a: &[u64], b: &[u64], tamper: GateTamper) -> Gate {
    let n = a.len();
    let ab_vals: Vec<RingElement> = (0..n)
        .map(|i| {
            let mut e = RingElement::zero(Representation::StridedCoefficients);
            e.v[0] = a[i];
            e.v[1] = b[i];
            if tamper == GateTamper::JunkAb(i) {
                e.v[64] = SQRT2_MOD_Q;
            }
            e.to_representation(Representation::IncompleteNTT);
            e
        })
        .collect();
    let c_vals: Vec<RingElement> = (0..n)
        .map(|i| {
            let mut v = a[i] & b[i];
            if tamper == GateTamper::WrongAnd(i) {
                v ^= 1;
            }
            RingElement::constant(v, Representation::IncompleteNTT)
        })
        .collect();
    let d_vals: Vec<RingElement> = (0..n)
        .map(|i| {
            let mut v = a[i] ^ b[i];
            if tamper == GateTamper::WrongXor(i) {
                v ^= 1;
            }
            RingElement::constant(v, Representation::IncompleteNTT)
        })
        .collect();
    Gate {
        ab: layout.push(&ab_vals),
        c: layout.push(&c_vals),
        d: layout.push(&d_vals),
    }
}

fn gate_claims(t: &mut Transcript, a: Region, b: Region, g: &Gate) -> Vec<Claim> {
    let x2 = monomial(2, 1);
    let x4 = monomial(4, 1);
    let two_x2 = monomial(2, 2);
    let two = RingElement::constant(2, Representation::IncompleteNTT);
    let v = g.ab.vars();
    let p1 = challenge_point(t, v.len());
    let t1 = eq(&p1).on(v) * (witness_in(g.ab) - witness_in(a) - witness_in(b).scale(&x2));
    let p2 = challenge_point(t, v.len());
    let t2 = eq(&p2).on(v)
        * (witness_in(g.ab) * witness_in(g.ab)
            - witness_in(a)
            - witness_in(b).scale(&x4)
            - witness_in(g.c).scale(&two_x2));
    let p3 = challenge_point(t, v.len());
    let t3 = eq(&p3).on(v)
        * (witness_in(g.d) - witness_in(a) - witness_in(b) + witness_in(g.c).scale(&two));
    vec![Claim::sums_to_zero(t1), Claim::sums_to_zero(t2), Claim::sums_to_zero(t3)]
}

/// Runs prove+verify for claims built by `build`, then checks that every
/// shipped value's constant term is zero. Returns (accepted, prove_ms,
/// verify_ms, claim_count, proof_bits).
fn prove_verify_with_checks(
    witness: &rokoko::common::matrix::VerticallyAlignedMatrix<RingElement>,
    witness_len: usize,
    build: &dyn Fn(&mut Transcript) -> Vec<Claim>,
    shipped: &[RingElement],
) -> (bool, f64, f64, usize, usize) {
    use rokoko::protocol::config::SizeableProof;
    let mut claim_count = 0;
    let mut timings = (0.0, 0.0);
    let mut proof_bits = 0;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut pt = Transcript::new();
        let claims = build(&mut pt);
        claim_count = claims.len();
        let start = std::time::Instant::now();
        let (proof, _o) = rokoko::protocol::snark::prove_claims(witness, &claims, &mut pt);
        timings.0 = start.elapsed().as_secs_f64() * 1000.0;
        proof_bits = proof.size_in_bits();
        let mut vt = Transcript::new();
        let vclaims = build(&mut vt);
        let start = std::time::Instant::now();
        rokoko::protocol::snark::verify_claims(WitnessShape::new(witness_len, 1), &vclaims, &proof, &mut vt);
        timings.1 = start.elapsed().as_secs_f64() * 1000.0;
    }));
    let structure_ok = shipped.iter().all(|v| v.constant_term_from_incomplete_ntt() == 0);
    (result.is_ok() && structure_ok, timings.0, timings.1, claim_count, proof_bits)
}

fn run_canonical_bits_case(name: &str, tamper: Option<(usize, RingElement, RingElement)>) {
    let bits = [1u64, 0, 1, 1, 0, 0, 1, 0];
    let witness_len = 16;
    let mut layout = WitnessBuilder::new(witness_len, 1);
    let cb = push_canonical_bits(&mut layout, &bits, witness_len, tamper);
    let witness = layout.finish();
    let exprs = canonical_shipped_exprs(&cb);
    let shipped: Vec<RingElement> = exprs.iter().map(|e| e.sum(&witness)).collect();
    let build = |t: &mut Transcript| {
        let mut claims: Vec<Claim> = canonical_shipped_exprs(&cb)
            .into_iter()
            .zip(shipped.iter())
            .map(|(e, v)| Claim::sums_to(e, v.clone()))
            .collect();
        claims.push(canonical_complement_claim(t, &cb));
        claims
    };
    let (ok, ..) = prove_verify_with_checks(&witness, witness_len, &build, &shipped);
    println!(
        "canonical-bits check, {name}: {} (shipped constant terms: {:?})",
        if ok { "ACCEPTED" } else { "REJECTED" },
        shipped.iter().map(|v| v.constant_term_from_incomplete_ntt()).collect::<Vec<_>>()
    );
}

/// Checks the leakage claim directly: with complement padding, the shipped
/// values must be identical for two different bit patterns of the same
/// length; without it (the documented recipe applied to the bits alone),
/// they must differ whenever the Hamming weights differ.
fn probe_shipped_value_leakage() {
    let shipped_for = |bits: &[u64], padded: bool| -> Vec<RingElement> {
        let witness_len = 16;
        let mut layout = WitnessBuilder::new(witness_len, 1);
        let cb = push_canonical_bits(&mut layout, bits, witness_len, None);
        let witness = layout.finish();
        let region = if padded { cb.full } else { cb.bits };
        let co = conj_ones();
        let len = region.len();
        let expr = witness_in(region) * witness_in(region).conjugate()
            - table(vec![co; len]).on(region.vars()) * witness_in(region);
        vec![expr.sum(&witness)]
    };
    let p1 = [1u64, 0, 1, 1, 0, 0, 1, 0]; // weight 4
    let p2 = [1u64, 1, 1, 1, 1, 1, 1, 0]; // weight 7
    let same = |x: &[RingElement], y: &[RingElement]| x.iter().zip(y).all(|(a, b)| a.v == b.v);
    println!(
        "shipped-value leakage: with complement padding, weight-4 vs weight-7 patterns ship identical values: {}",
        same(&shipped_for(&p1, true), &shipped_for(&p2, true))
    );
    println!(
        "shipped-value leakage: documented recipe on the bits alone, same two patterns ship identical values: {} \
         (false = Hamming weight leaks)",
        same(&shipped_for(&p1, false), &shipped_for(&p2, false))
    );
}

#[derive(Clone, Copy, PartialEq)]
enum AdderTamper {
    None,
    CarryLink(usize),
    Gate1(GateTamper),
    Gate2(GateTamper),
    CoutTie(usize),
}

/// A full 64-bit ripple-carry adder over canonical input bits, built only
/// from the canonical gate (twice per bit position), a linear carry-out tie
/// (Cout = C1 + C2, valid because C1, C2 are mutually exclusive), and one
/// individual length-1 tie per carry-chain link.
fn run_ripple_adder(name: &str, x: u64, y: u64, tamper: AdderTamper) {
    let n = 64usize;
    let witness_len = 1024usize;
    let a: Vec<u64> = (0..n).map(|i| (x >> i) & 1).collect();
    let b: Vec<u64> = (0..n).map(|i| (y >> i) & 1).collect();
    let s1: Vec<u64> = (0..n).map(|i| a[i] ^ b[i]).collect();
    let c1: Vec<u64> = (0..n).map(|i| a[i] & b[i]).collect();
    let mut cin = vec![0u64; n];
    let mut c2 = vec![0u64; n];
    let mut sum = vec![0u64; n];
    let mut cout = vec![0u64; n];
    for i in 0..n {
        if i > 0 {
            cin[i] = cout[i - 1];
        }
        if tamper == AdderTamper::CarryLink(i) {
            cin[i] ^= 1;
        }
        c2[i] = s1[i] & cin[i];
        sum[i] = s1[i] ^ cin[i];
        assert_eq!(c1[i] & c2[i], 0, "c1, c2 not mutually exclusive");
        cout[i] = c1[i] + c2[i];
        if tamper == AdderTamper::CoutTie(i) {
            cout[i] ^= 1;
        }
    }
    let honest_value: u64 = (0..n).map(|i| sum[i] << i).sum();
    if tamper == AdderTamper::None {
        assert_eq!(honest_value, x.wrapping_add(y), "off-circuit adder disagrees with native u64 add");
    }

    let mut layout = WitnessBuilder::new(witness_len, 1);
    let ca = push_canonical_bits(&mut layout, &a, witness_len, None);
    let cb = push_canonical_bits(&mut layout, &b, witness_len, None);
    let g1t = if let AdderTamper::Gate1(t) = tamper { t } else { GateTamper::None };
    let g2t = if let AdderTamper::Gate2(t) = tamper { t } else { GateTamper::None };
    let gate1 = push_gate(&mut layout, &a, &b, g1t);
    let cin_region = layout.push(
        &cin.iter()
            .map(|&v| RingElement::constant(v, Representation::IncompleteNTT))
            .collect::<Vec<_>>(),
    );
    let gate2 = push_gate(&mut layout, &s1, &cin, g2t);
    let cout_region = layout.push(
        &cout.iter()
            .map(|&v| RingElement::constant(v, Representation::IncompleteNTT))
            .collect::<Vec<_>>(),
    );
    let witness = layout.finish();

    let mut exprs = canonical_shipped_exprs(&ca);
    exprs.extend(canonical_shipped_exprs(&cb));
    let shipped: Vec<RingElement> = exprs.iter().map(|e| e.sum(&witness)).collect();

    let build = |t: &mut Transcript| {
        let mut ex = canonical_shipped_exprs(&ca);
        ex.extend(canonical_shipped_exprs(&cb));
        let mut claims: Vec<Claim> = ex
            .into_iter()
            .zip(shipped.iter())
            .map(|(e, v)| Claim::sums_to(e, v.clone()))
            .collect();
        claims.push(canonical_complement_claim(t, &ca));
        claims.push(canonical_complement_claim(t, &cb));
        claims.extend(gate_claims(t, ca.bits, cb.bits, &gate1));
        claims.extend(gate_claims(t, gate1.d, cin_region, &gate2));
        let pc = challenge_point(t, cout_region.vars().len());
        claims.push(Claim::sums_to_zero(
            eq(&pc).on(cout_region.vars())
                * (witness_in(cout_region) - witness_in(gate1.c) - witness_in(gate2.c)),
        ));
        claims.push(Claim::sums_to_zero(witness_in(Region::new(cin_region.start(), 1, witness_len))));
        for i in 1..n {
            claims.push(Claim::sums_to_zero(
                witness_in(Region::new(cin_region.start() + i, 1, witness_len))
                    - witness_in(Region::new(cout_region.start() + i - 1, 1, witness_len)),
            ));
        }
        claims
    };
    let (ok, prove_ms, verify_ms, claims, bits) =
        prove_verify_with_checks(&witness, witness_len, &build, &shipped);
    if tamper == AdderTamper::None {
        println!(
            "64-bit adder {name}: {:#018x} + {:#018x} = {:#018x}: {} ({claims} claims, prove {prove_ms:.1} ms, \
             verify {verify_ms:.1} ms, claims-proof {} bytes)",
            x,
            y,
            honest_value,
            if ok { "ACCEPTED" } else { "REJECTED" },
            bits / 8
        );
    } else {
        println!("64-bit adder {name}: {}", if ok { "ACCEPTED (unsound!)" } else { "REJECTED" });
    }
}

fn main() {
    init_common();

    // Positive case: a genuine 0/1 witness. Expect: accepted, and the
    // shipped value's constant coefficient is zero (binariness holds).
    run_case("positive (real bits 0,1,1,0)", vec![0, 1, 1, 0]);

    // Negative case: a malicious witness with one non-binary entry (2
    // instead of 0 or 1). The claim's arithmetic (x*(x-1)) is nonzero at
    // x=2 (2*1=2), so the shipped "energy" value's constant coefficient
    // should come out nonzero, which is what a verifier checking that
    // coefficient (the documented "two duties stay yours" step) would
    // catch -- NOT a failure of prove_claims/verify_claims themselves,
    // which only check the sumcheck's internal consistency, not the
    // shipped value's meaning.
    run_case("negative (malicious entry 2 instead of a bit)", vec![0, 1, 2, 0]);

    // Degree-budget empirical test: w*w*w alone (documented ceiling) should
    // succeed; w*w*w with one more eq(point) weight factor should exceed the
    // degree-3-per-variable cap and panic, confirming the addition gadget's
    // sketched cubic XOR/majority formulas cannot be eq-batched into one
    // claim over a whole region as originally planned.
    run_degree_budget_case("degree-3 witness cube alone (w*w*w)", false);
    run_degree_budget_case("degree-3 witness cube times one eq() weight", true);

    // XOR gate, eq-batched over a 4-wide region: a=[0,1,0,1], b=[0,0,1,1],
    // correct r = a XOR b = [0,1,1,0].
    run_xor_gate_case(
        "XOR gate positive (correct a^b)",
        vec![0, 1, 0, 1],
        vec![0, 0, 1, 1],
        vec![0, 1, 1, 0],
    );
    // Negative: flip position 2's output bit (should be 1, claim says 0).
    run_xor_gate_case(
        "XOR gate negative (wrong output bit at position 2)",
        vec![0, 1, 0, 1],
        vec![0, 0, 1, 1],
        vec![0, 1, 0, 0],
    );

    run_subregion_bisection();
    probe_slot_pairing();
    probe_second_slot_and_omega();
    probe_x_scaling_swap((0, 1), 3, 5);
    probe_x_scaling_swap((2, 3), 7, 11);
    probe_pattern_generality();
    println!("-- honest witness --");
    run_tie_fresh_region_case(4, &[1, 0, 1, 1], &[1, 1, 0, 1], false);
    println!("-- malicious witness (position 0's claimed product is wrong) --");
    run_tie_fresh_region_case(4, &[1, 0, 1, 1], &[1, 1, 0, 1], true);

    println!("-- AND+XOR capstone gate --");
    run_and_xor_gate_case(
        "honest AND+XOR",
        vec![0, 1, 0, 1],
        vec![0, 0, 1, 1],
        Corrupt::None,
    );
    run_and_xor_gate_case(
        "malicious AND tie wrong",
        vec![0, 1, 0, 1],
        vec![0, 0, 1, 1],
        Corrupt::And,
    );
    run_and_xor_gate_case(
        "malicious XOR tie wrong",
        vec![0, 1, 0, 1],
        vec![0, 0, 1, 1],
        Corrupt::Xor,
    );
    run_and_xor_gate_case(
        "honest AND+XOR, different/larger bit pattern",
        vec![1, 1, 1, 1, 0, 0, 0, 0],
        vec![1, 0, 1, 0, 1, 0, 1, 0],
        Corrupt::None,
    );
    run_and_xor_gate_case(
        "honest AND+XOR, all-zero bits",
        vec![0, 0, 0, 0],
        vec![0, 0, 0, 0],
        Corrupt::None,
    );
    run_and_xor_gate_case(
        "honest AND+XOR, all-one bits",
        vec![1, 1, 1, 1],
        vec![1, 1, 1, 1],
        Corrupt::None,
    );

    println!("-- full adder, all 8 input combinations, honest --");
    let mut all_a = vec![];
    let mut all_b = vec![];
    let mut all_cin = vec![];
    for a in [0u64, 1] {
        for b in [0u64, 1] {
            for cin in [0u64, 1] {
                all_a.push(a);
                all_b.push(b);
                all_cin.push(cin);
            }
        }
    }
    run_full_adder_case(
        "full adder, all 8 (a,b,cin) combinations batched",
        all_a,
        all_b,
        all_cin,
        Corrupt2::None,
    );

    println!("-- full adder, malicious variants --");
    for (name, c) in [
        ("malicious gate1 AND", Corrupt2::Gate1And),
        ("malicious gate1 XOR", Corrupt2::Gate1Xor),
        ("malicious gate2 AND", Corrupt2::Gate2And),
        ("malicious gate2 XOR", Corrupt2::Gate2Xor),
        ("malicious gate3 AND", Corrupt2::Gate3And),
        ("malicious gate3 XOR", Corrupt2::Gate3Xor),
    ] {
        run_full_adder_case(name, vec![1, 0, 1, 1], vec![1, 1, 0, 1], vec![0, 1, 1, 1], c);
    }

    println!("-- shift/chain probes (needed for carry propagation) --");
    probe_shift_via_batched_eq();
    probe_shift_via_individual_length1_ties(false);
    probe_shift_via_individual_length1_ties(true);

    println!("-- ring model --");
    probe_ring_model();

    println!("-- junk-coefficient attack on the earlier gate --");
    probe_old_gate_junk_attack();

    println!("-- canonical-bits check (primary inputs) --");
    run_canonical_bits_case("honest", None);
    let q = 1125899906839937u64;
    let one_plus_x2 = {
        let mut e = RingElement::zero(Representation::StridedCoefficients);
        e.v[0] = 1;
        e.v[1] = 1;
        e.to_representation(Representation::IncompleteNTT);
        e
    };
    run_canonical_bits_case(
        "malicious bit=1+X^2, comp=-X^2 (complement tie still holds)",
        Some((3, one_plus_x2.clone(), monomial(2, q - 1))),
    );
    run_canonical_bits_case(
        "malicious bit=2, comp=-1 (complement tie still holds)",
        Some((3, RingElement::constant(2, Representation::IncompleteNTT), RingElement::constant(q - 1, Representation::IncompleteNTT))),
    );
    run_canonical_bits_case(
        "malicious bit=1+X^2, comp=0 (breaks complement tie)",
        Some((3, one_plus_x2, RingElement::zero(Representation::IncompleteNTT))),
    );

    probe_shipped_value_leakage();

    println!("-- canonical 64-bit ripple-carry adder --");
    for (name, x, y) in [
        ("mixed", 0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210u64),
        ("full carry chain, wraps to 0", u64::MAX, 1),
        ("top-bit overflow", 0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
        ("small", 12_345, 67_890),
        ("zero", 0, 0),
    ] {
        run_ripple_adder(name, x, y, AdderTamper::None);
    }
    for (name, t) in [
        ("malicious carry link at bit 33", AdderTamper::CarryLink(33)),
        ("malicious carry-out at bit 12", AdderTamper::CoutTie(12)),
        ("malicious junk X^1 coeff in gate1 packing at bit 5", AdderTamper::Gate1(GateTamper::JunkAb(5))),
        ("malicious wrong AND in gate1 at bit 7", AdderTamper::Gate1(GateTamper::WrongAnd(7))),
        ("malicious wrong XOR in gate1 at bit 9", AdderTamper::Gate1(GateTamper::WrongXor(9))),
        ("malicious wrong AND in gate2 at bit 40", AdderTamper::Gate2(GateTamper::WrongAnd(40))),
        ("malicious wrong sum bit (gate2 XOR) at bit 63", AdderTamper::Gate2(GateTamper::WrongXor(63))),
        ("malicious junk X^1 coeff in gate2 packing at bit 20", AdderTamper::Gate2(GateTamper::JunkAb(20))),
    ] {
        run_ripple_adder(name, u64::MAX, 1, t);
    }
}
