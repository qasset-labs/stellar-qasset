//! Enum wrapper that lets the ed25519 AIR and the 16-bit range-check AIR
//! sit in the same `&[A]` slice for [`p3_batch_stark::prove_batch`].
//!
//! `prove_batch` requires a homogeneous AIR slice; this enum delegates
//! every `BaseAir`, `Air`, and `LookupAir` method to the active variant.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::Lookup;
use p3_lookup::LookupAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::ed25519_air::air::Ed25519Air;
use crate::range_check_u16_air::air::RangeCheckU16Air;

/// One of the AIRs in our batched proof.
#[derive(Clone)]
pub enum BatchedAir {
    Ed25519(Ed25519Air),
    RangeCheckU16(RangeCheckU16Air),
}

impl<F: PrimeCharacteristicRing + Clone + Send + Sync> BaseAir<F> for BatchedAir {
    fn width(&self) -> usize {
        match self {
            Self::Ed25519(inner) => <Ed25519Air as BaseAir<F>>::width(inner),
            Self::RangeCheckU16(inner) => <RangeCheckU16Air as BaseAir<F>>::width(inner),
        }
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Ed25519(inner) => <Ed25519Air as BaseAir<F>>::max_constraint_degree(inner),
            Self::RangeCheckU16(inner) => {
                <RangeCheckU16Air as BaseAir<F>>::max_constraint_degree(inner)
            }
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Ed25519(inner) => <Ed25519Air as BaseAir<F>>::preprocessed_trace(inner),
            Self::RangeCheckU16(inner) => {
                <RangeCheckU16Air as BaseAir<F>>::preprocessed_trace(inner)
            }
        }
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Ed25519(inner) => {
                <Ed25519Air as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
            Self::RangeCheckU16(inner) => {
                <RangeCheckU16Air as BaseAir<F>>::preprocessed_next_row_columns(inner)
            }
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Ed25519(inner) => <Ed25519Air as BaseAir<F>>::num_public_values(inner),
            Self::RangeCheckU16(inner) => {
                <RangeCheckU16Air as BaseAir<F>>::num_public_values(inner)
            }
        }
    }
}

impl<AB: AirBuilder> Air<AB> for BatchedAir
where
    AB::F: Clone + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Ed25519(inner) => <Ed25519Air as Air<AB>>::eval(inner, builder),
            Self::RangeCheckU16(inner) => <RangeCheckU16Air as Air<AB>>::eval(inner, builder),
        }
    }
}

impl<F: Field> LookupAir<F> for BatchedAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Ed25519(inner) => LookupAir::<F>::add_lookup_columns(inner),
            Self::RangeCheckU16(inner) => LookupAir::<F>::add_lookup_columns(inner),
        }
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Ed25519(inner) => LookupAir::<F>::get_lookups(inner),
            Self::RangeCheckU16(inner) => LookupAir::<F>::get_lookups(inner),
        }
    }
}
