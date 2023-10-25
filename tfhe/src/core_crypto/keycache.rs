use crate::core_crypto::prelude::*;
use crate::keycache::*;
use lazy_static::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MultiBitParams<Scalar: UnsignedInteger> {
    pub input_lwe_dimension: LweDimension,
    pub lwe_modular_std_dev: StandardDev,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub glwe_modular_std_dev: StandardDev,
    pub message_modulus_log: CiphertextModulusLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
    pub grouping_factor: LweBskGroupingFactor,
    pub thread_count: ThreadCount,
}

impl<Scalar: UnsignedInteger> NamedParam for MultiBitParams<Scalar> {
    fn name(&self) -> String {
        format!(
            "PARAM_LWE_MULTI_BIT_BOOTSTRAP_glwe_{}_poly_{}_decomp_base_log_{}_decomp_level_{}_input_dim_{}_group_fact_{}_ct_modulus_{}_group_factor_{}_thread_count_{}",
            self.glwe_dimension.0, self.polynomial_size.0, self.decomp_base_log.0,
            self.decomp_level_count.0, self.input_lwe_dimension.0, self.grouping_factor.0,
            self.ciphertext_modulus, self.grouping_factor.0, self.thread_count.0,
        )
    }
}

pub struct KeyCacheCoreImpl<Scalar: UnsignedInteger> {
    inner: ImplKeyCache<MultiBitParams<Scalar>, MultiBitBootstrapKeys<Scalar>, FileStorage>,
}

impl<Scalar: UnsignedInteger> Default for KeyCacheCoreImpl<Scalar> {
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new(
                "../keys/core_crypto/bootstrap".to_string(),
            )),
        }
    }
}

pub type MultiBitBootstrapKeys<Scalar> = (
    LweMultiBitBootstrapKeyOwned<Scalar>,
    LweSecretKey<Vec<Scalar>>,
    LweSecretKey<Vec<Scalar>>,
    FourierLweMultiBitBootstrapKeyOwned,
);

pub struct SharedMultiBitBootstrapKey<Scalar: UnsignedInteger> {
    inner: GenericSharedKey<MultiBitBootstrapKeys<Scalar>>,
}

impl<Scalar: UnsignedInteger> SharedMultiBitBootstrapKey<Scalar> {
    pub fn bootstrap_key(&self) -> &LweMultiBitBootstrapKeyOwned<Scalar> {
        &self.inner.0
    }
    pub fn input_key(&self) -> &LweSecretKey<Vec<Scalar>> {
        &self.inner.1
    }
    pub fn output_key(&self) -> &LweSecretKey<Vec<Scalar>> {
        &self.inner.2
    }
    pub fn fourier_bootstrap_key(&self) -> &FourierLweMultiBitBootstrapKeyOwned {
        &self.inner.3
    }
}

impl<Scalar: UnsignedInteger + UnsignedTorus + CastFrom<usize> + Serialize + DeserializeOwned>
    KeyCacheCoreImpl<Scalar>
{
    pub fn get_multi_bit_key_with_closure<C>(
        &self,
        params: MultiBitParams<Scalar>,
        mut c: C,
    ) -> SharedMultiBitBootstrapKey<Scalar>
    where
        C: FnMut(MultiBitParams<Scalar>) -> MultiBitBootstrapKeys<Scalar>,
    {
        SharedMultiBitBootstrapKey {
            inner: self.inner.get_with_closure(params, &mut c),
        }
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

#[derive(Default)]
pub struct KeyCache {
    u32_cache: KeyCacheCoreImpl<u32>,
    u64_cache: KeyCacheCoreImpl<u64>,
}

impl KeyCache {
    pub fn get_multi_bit_key_with_closure<C, P, Scalar>(
        &self,
        params: MultiBitParams<Scalar>,
        c: C,
    ) -> SharedMultiBitBootstrapKey<Scalar>
    where
        C: FnMut(MultiBitParams<Scalar>) -> MultiBitBootstrapKeys<Scalar>,
        Scalar: UnsignedInteger
            + UnsignedTorus
            + CastFrom<usize>
            + KeyCacheAccess
            + Serialize
            + DeserializeOwned,
    {
        Scalar::access(self).get_multi_bit_key_with_closure(params, c)
    }
}

pub trait KeyCacheAccess: Sized + UnsignedInteger {
    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self>;
}

impl KeyCacheAccess for u32 {
    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self> {
        &keycache.u32_cache
    }
}

impl KeyCacheAccess for u64 {
    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self> {
        &keycache.u64_cache
    }
}

lazy_static! {
    pub static ref KEY_CACHE: KeyCache = Default::default();
}
