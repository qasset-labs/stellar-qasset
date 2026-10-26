// SPDX-License-Identifier: MIT
//! Print the architecture-independent transcript regression vector.
fn main() {
    println!(
        "{:?}",
        qasset_binius_nostd_verifier::regression::transcript_vector()
    );
}
