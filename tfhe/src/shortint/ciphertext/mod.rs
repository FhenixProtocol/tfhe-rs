//! Module with the definition of the Ciphertext.
use crate::conformance::ParameterSetConformant;
pub use crate::core_crypto::commons::parameters::PBSOrder;
use crate::core_crypto::entities::*;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use std::cmp;
use std::fmt::Debug;

use super::parameters::{CiphertextConformanceParams, CiphertextListConformanceParams};

/// This tracks the max degree that can be in a Ciphertext.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct Degree(pub usize);

/// This tracks the amount of noise in a ciphertext.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct NoiseLevel(usize);

impl NoiseLevel {
    pub const NOMINAL: Self = Self(1);
    pub const ZERO: Self = Self(0);
}

impl std::ops::Add for NoiseLevel {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self {
        self += rhs;
        self
    }
}

impl std::ops::AddAssign for NoiseLevel {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl std::ops::MulAssign<usize> for NoiseLevel {
    fn mul_assign(&mut self, rhs: usize) {
        self.0 *= rhs
    }
}

impl std::ops::Mul<usize> for NoiseLevel {
    type Output = Self;

    fn mul(mut self, rhs: usize) -> Self::Output {
        self *= rhs;

        self
    }
}

impl Degree {
    pub(crate) fn after_bitxor(&self, other: Degree) -> Degree {
        let max = cmp::max(self.0, other.0);
        let min = cmp::min(self.0, other.0);
        let mut result = max;

        //Try every possibility to find the worst case
        for i in 0..min + 1 {
            if max ^ i > result {
                result = max ^ i;
            }
        }

        Degree(result)
    }

    pub(crate) fn after_bitor(&self, other: Degree) -> Degree {
        let max = cmp::max(self.0, other.0);
        let min = cmp::min(self.0, other.0);
        let mut result = max;

        for i in 0..min + 1 {
            if max | i > result {
                result = max | i;
            }
        }

        Degree(result)
    }

    pub(crate) fn after_bitand(&self, other: Degree) -> Degree {
        Degree(cmp::min(self.0, other.0))
    }

    pub(crate) fn after_left_shift(&self, shift: u8, modulus: usize) -> Degree {
        let mut result = 0;

        for i in 0..self.0 + 1 {
            let tmp = (i << shift) % modulus;
            if tmp > result {
                result = tmp;
            }
        }

        Degree(result)
    }

    #[allow(dead_code)]
    pub(crate) fn after_pbs<F>(&self, f: F) -> Degree
    where
        F: Fn(usize) -> usize,
    {
        let mut result = 0;

        for i in 0..self.0 + 1 {
            let tmp = f(i);
            if tmp > result {
                result = tmp;
            }
        }

        Degree(result)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
pub struct Ciphertext {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    noise_level: NoiseLevel,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
}

impl crate::named::Named for Ciphertext {
    const NAME: &'static str = "shortint::Ciphertext";
}

impl ParameterSetConformant for Ciphertext {
    type ParameterSet = CiphertextConformanceParams;

    fn is_conformant(&self, param: &CiphertextConformanceParams) -> bool {
        self.ct.is_conformant(&param.ct_params)
            && self.message_modulus == param.message_modulus
            && self.carry_modulus == param.carry_modulus
            && self.pbs_order == param.pbs_order
            && self.degree == param.degree
            && self.noise_level == param.noise_level
    }
}

// Use destructuring to also have a compile error
// if ever a new member is added to Ciphertext
// and is not handled here.
//
// And a warning if a member is destructured but not used.
impl Clone for Ciphertext {
    fn clone(&self) -> Self {
        let Ciphertext {
            ct: src_ct,
            degree: src_degree,
            message_modulus: src_message_modulus,
            carry_modulus: src_carry_modulus,
            pbs_order: src_pbs_order,
            noise_level: src_noise_level,
        } = self;

        Self {
            ct: src_ct.clone(),
            degree: *src_degree,
            message_modulus: *src_message_modulus,
            carry_modulus: *src_carry_modulus,
            pbs_order: *src_pbs_order,
            noise_level: *src_noise_level,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        let Ciphertext {
            ct: dst_ct,
            degree: dst_degree,
            message_modulus: dst_message_modulus,
            carry_modulus: dst_carry_modulus,
            pbs_order: dst_pbs_order,
            noise_level: dst_noise_level,
        } = self;

        let Ciphertext {
            ct: src_ct,
            degree: src_degree,
            message_modulus: src_message_modulus,
            carry_modulus: src_carry_modulus,
            pbs_order: src_pbs_order,
            noise_level: src_noise_level,
        } = source;

        if dst_ct.ciphertext_modulus() != src_ct.ciphertext_modulus()
            || dst_ct.lwe_size() != src_ct.lwe_size()
        {
            *dst_ct = src_ct.clone();
        } else {
            dst_ct.as_mut().copy_from_slice(src_ct.as_ref());
        }
        *dst_degree = *src_degree;
        *dst_message_modulus = *src_message_modulus;
        *dst_carry_modulus = *src_carry_modulus;
        *dst_pbs_order = *src_pbs_order;
        *dst_noise_level = *src_noise_level;
    }
}

impl Ciphertext {
    pub fn new(
        ct: LweCiphertextOwned<u64>,
        degree: Degree,
        noise_level: NoiseLevel,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        pbs_order: PBSOrder,
    ) -> Ciphertext {
        Ciphertext {
            ct,
            degree,
            noise_level,
            message_modulus,
            carry_modulus,
            pbs_order,
        }
    }
    pub fn carry_is_empty(&self) -> bool {
        self.degree.0 < self.message_modulus.0
    }
}

/// A structure representing a compressed shortint ciphertext.
/// It is used to homomorphically evaluate a shortint circuits.
/// Internally, it uses a LWE ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct CompressedCiphertext {
    pub ct: SeededLweCiphertext<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub noise_level: NoiseLevel,
}

impl ParameterSetConformant for CompressedCiphertext {
    type ParameterSet = CiphertextConformanceParams;

    fn is_conformant(&self, param: &CiphertextConformanceParams) -> bool {
        self.ct.is_conformant(&param.ct_params)
            && self.message_modulus == param.message_modulus
            && self.carry_modulus == param.carry_modulus
            && self.pbs_order == param.pbs_order
            && self.degree == param.degree
            && self.noise_level == param.noise_level
    }
}

impl CompressedCiphertext {
    pub fn decompress(self) -> Ciphertext {
        let CompressedCiphertext {
            ct,
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        } = self;

        Ciphertext {
            ct: ct.decompress_into_lwe_ciphertext(),
            degree,
            message_modulus,
            carry_modulus,
            pbs_order,
            noise_level,
        }
    }
}

impl From<CompressedCiphertext> for Ciphertext {
    fn from(value: CompressedCiphertext) -> Self {
        value.decompress()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompactCiphertextList {
    pub ct_list: LweCompactCiphertextListOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub pbs_order: PBSOrder,
    pub noise_level: NoiseLevel,
}

impl ParameterSetConformant for CompactCiphertextList {
    type ParameterSet = CiphertextListConformanceParams;

    fn is_conformant(&self, param: &CiphertextListConformanceParams) -> bool {
        self.ct_list.is_conformant(&param.ct_list_params)
            && self.message_modulus == param.message_modulus
            && self.carry_modulus == param.carry_modulus
            && self.pbs_order == param.pbs_order
            && self.degree == param.degree
            && self.noise_level == param.noise_level
    }
}

impl CompactCiphertextList {
    pub fn expand(&self) -> Vec<Ciphertext> {
        let mut output_lwe_ciphertext_list = LweCiphertextList::new(
            0u64,
            self.ct_list.lwe_size(),
            self.ct_list.lwe_ciphertext_count(),
            self.ct_list.ciphertext_modulus(),
        );

        // No parallelism allowed
        #[cfg(all(feature = "__wasm_api", not(feature = "parallel-wasm-api")))]
        {
            use crate::core_crypto::prelude::expand_lwe_compact_ciphertext_list;
            expand_lwe_compact_ciphertext_list(&mut output_lwe_ciphertext_list, &self.ct_list);
        }

        // Parallelism allowed
        #[cfg(any(not(feature = "__wasm_api"), feature = "parallel-wasm-api"))]
        {
            use crate::core_crypto::prelude::par_expand_lwe_compact_ciphertext_list;
            par_expand_lwe_compact_ciphertext_list(&mut output_lwe_ciphertext_list, &self.ct_list);
        }

        output_lwe_ciphertext_list
            .as_ref()
            .chunks_exact(self.ct_list.lwe_size().0)
            .map(|lwe_data| {
                let ct = LweCiphertext::from_container(
                    lwe_data.to_vec(),
                    self.ct_list.ciphertext_modulus(),
                );
                Ciphertext {
                    ct,
                    degree: self.degree,
                    message_modulus: self.message_modulus,
                    carry_modulus: self.carry_modulus,
                    pbs_order: self.pbs_order,
                    noise_level: self.noise_level,
                }
            })
            .collect::<Vec<_>>()
    }

    pub fn size_elements(&self) -> usize {
        self.ct_list.size_elements()
    }

    pub fn size_bytes(&self) -> usize {
        self.ct_list.size_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortint::CiphertextModulus;

    #[test]
    fn test_clone_from_same_lwe_size_and_modulus() {
        let mut c1 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![1u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree(1),
            message_modulus: MessageModulus(1),
            carry_modulus: CarryModulus(1),
            pbs_order: PBSOrder::KeyswitchBootstrap,
            noise_level: NoiseLevel::NOMINAL,
        };

        let c2 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![2323858949u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree(42),
            message_modulus: MessageModulus(2),
            carry_modulus: CarryModulus(2),
            pbs_order: PBSOrder::BootstrapKeyswitch,
            noise_level: NoiseLevel::NOMINAL,
        };

        assert_ne!(c1, c2);

        c1.clone_from(&c2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_clone_from_same_lwe_size_different_modulus() {
        let mut c1 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![1u64; 256],
                CiphertextModulus::try_new_power_of_2(32).unwrap(),
            ),
            degree: Degree(1),
            message_modulus: MessageModulus(1),
            carry_modulus: CarryModulus(1),
            pbs_order: PBSOrder::KeyswitchBootstrap,
            noise_level: NoiseLevel::NOMINAL,
        };

        let c2 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![2323858949u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree(42),
            message_modulus: MessageModulus(2),
            carry_modulus: CarryModulus(2),
            pbs_order: PBSOrder::BootstrapKeyswitch,
            noise_level: NoiseLevel::NOMINAL,
        };

        assert_ne!(c1, c2);

        c1.clone_from(&c2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_clone_from_different_lwe_size_same_modulus() {
        let mut c1 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![1u64; 512],
                CiphertextModulus::new_native(),
            ),
            degree: Degree(1),
            message_modulus: MessageModulus(1),
            carry_modulus: CarryModulus(1),
            pbs_order: PBSOrder::KeyswitchBootstrap,
            noise_level: NoiseLevel::NOMINAL,
        };

        let c2 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![2323858949u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree(42),
            message_modulus: MessageModulus(2),
            carry_modulus: CarryModulus(2),
            pbs_order: PBSOrder::BootstrapKeyswitch,
            noise_level: NoiseLevel::NOMINAL,
        };

        assert_ne!(c1, c2);

        c1.clone_from(&c2);
        assert_eq!(c1, c2);
    }
}
