use crate::core_crypto::prelude::*;
use crate::keycache::*;
use lazy_static::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClassicTestParams<Scalar: UnsignedInteger> {
    pub lwe_dimension: LweDimension,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
    pub lwe_modular_std_dev: StandardDev,
    pub glwe_modular_std_dev: StandardDev,
    pub pbs_base_log: DecompositionBaseLog,
    pub pbs_level: DecompositionLevelCount,
    pub ks_base_log: DecompositionBaseLog,
    pub ks_level: DecompositionLevelCount,
    pub pfks_level: DecompositionLevelCount,
    pub pfks_base_log: DecompositionBaseLog,
    pub pfks_modular_std_dev: StandardDev,
    pub cbs_level: DecompositionLevelCount,
    pub cbs_base_log: DecompositionBaseLog,
    pub message_modulus_log: CiphertextModulusLog,
    pub ciphertext_modulus: CiphertextModulus<Scalar>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct MultiBitTestParams<Scalar: UnsignedInteger> {
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

#[derive(Clone, Copy, PartialEq)]
enum TestParams<Scalar: UnsignedInteger> {
    Classical(ClassicTestParams<Scalar>),
    MultiBit(MultiBitTestParams<Scalar>),
}

impl<Scalar: UnsignedInteger> NamedParam for ClassicTestParams<Scalar> {
    fn name(&self) -> String {
        format!(
            "PARAM_LWE_BOOTSTRAP_glwe_{}_poly_{}_decomp_base_log_{}_decomp_level_{}_lwe_dim_{}_ct_modulus_{}_msg_modulus_{}",
            self.glwe_dimension.0, self.polynomial_size.0, self.pbs_base_log.0, self.pbs_level.0,
            self.lwe_dimension.0, self.ciphertext_modulus, self.message_modulus_log.0
        )
    }
}

impl<Scalar: UnsignedInteger> NamedParam for MultiBitTestParams<Scalar> {
    fn name(&self) -> String {
        format!(
            "PARAM_LWE_MULTI_BIT_BOOTSTRAP_glwe_{}_poly_{}_decomp_base_log_{}_decomp_level_{}_input_dim_{}_ct_modulus_{}_group_factor_{}_thread_count_{}",
            self.glwe_dimension.0, self.polynomial_size.0, self.decomp_base_log.0,
            self.decomp_level_count.0, self.input_lwe_dimension.0, self.ciphertext_modulus,
            self.grouping_factor.0, self.thread_count.0,
        )
    }
}

impl<Scalar: UnsignedInteger> NamedParam for TestParams<Scalar> {
    fn name(&self) -> String {
        match self {
            Self::Classical(param) => param.name(),
            Self::MultiBit(param) => param.name(),
        }
    }
}

pub struct KeyCacheCoreImpl<P, K>
where
    P: Copy + NamedParam + DeserializeOwned + Serialize + PartialEq,
    K: DeserializeOwned + Serialize,
{
    inner: ImplKeyCache<P, K, FileStorage>,
}

impl<
        P: Copy + NamedParam + DeserializeOwned + Serialize + PartialEq,
        K: DeserializeOwned + Serialize,
    > Default for KeyCacheCoreImpl<P, K>
{
    fn default() -> Self {
        Self {
            inner: ImplKeyCache::new(FileStorage::new(
                "../keys/core_crypto/bootstrap".to_string(),
            )),
        }
    }
}

pub type ClassicalBootstrapKeys<Scalar> = (
    LweMultiBitBootstrapKeyOwned<Scalar>,
    LweSecretKey<Vec<Scalar>>,
    LweSecretKey<Vec<Scalar>>,
    FourierLweMultiBitBootstrapKeyOwned,
);

pub type MultiBitBootstrapKeys<Scalar> = (
    LweMultiBitBootstrapKeyOwned<Scalar>,
    LweSecretKey<Vec<Scalar>>,
    LweSecretKey<Vec<Scalar>>,
    FourierLweMultiBitBootstrapKeyOwned,
);

#[derive(Serialize, Deserialize)]
enum BootstrapKeys<Scalar: UnsignedInteger> {
    Classical(ClassicalBootstrapKeys<Scalar>),
    MultiBit(MultiBitBootstrapKeys<Scalar>),
}

// TODO Est-ce que je peux rendre le Keycache générique sur P(arams) et K(eys)
// Cela signifie de laisser faire la closure pour déterminer les types à manipuler.
// Essayer de le faire avec le multi-bit pour voir si l'approche est viable.
impl<P, K> KeyCacheCoreImpl<P, K>
where
    P: Copy + NamedParam + DeserializeOwned + Serialize + PartialEq,
    K: DeserializeOwned + Serialize + Clone,
{
    pub fn get_key_with_closure<C>(&self, params: P, mut c: C) -> K
    where
        C: FnMut(P) -> K,
    {
        (*self.inner.get_with_closure(params, &mut c)).clone()
    }

    pub fn clear_in_memory_cache(&self) {
        self.inner.clear_in_memory_cache();
    }
}

#[derive(Default)]
pub struct KeyCache {
    u32_multi_bit_cache: KeyCacheCoreImpl<MultiBitTestParams<u32>, MultiBitBootstrapKeys<u32>>,
    u64_multi_bit_cache: KeyCacheCoreImpl<MultiBitTestParams<u64>, MultiBitBootstrapKeys<u64>>,
}

impl KeyCache {
    pub fn get_key_with_closure<C, P, K>(&self, params: P, c: C) -> K
    where
        C: FnMut(P) -> K,
        P: KeyCacheAccess<Keys = K> + Serialize + DeserializeOwned + Copy + PartialEq + NamedParam,
        K: DeserializeOwned + Serialize + Clone,
    {
        P::access(self).get_key_with_closure(params, c)
    }
}

pub trait KeyCacheAccess: Serialize + DeserializeOwned + Copy + PartialEq + NamedParam {
    type Keys: DeserializeOwned + Serialize;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys>;
}

impl<Scalar: UnsignedInteger + Serialize + DeserializeOwned> KeyCacheAccess
    for MultiBitTestParams<Scalar>
{
    type Keys = MultiBitBootstrapKeys<Scalar>;

    fn access(keycache: &KeyCache) -> &KeyCacheCoreImpl<Self, Self::Keys> {
        use std::any::TypeId;

        let scalar_type_id = TypeId::of::<Scalar>();

        if scalar_type_id == TypeId::of::<u32>() {
            unsafe { std::mem::transmute(&keycache.u32_multi_bit_cache) }
        } else if scalar_type_id == TypeId::of::<u64>() {
            unsafe { std::mem::transmute(&keycache.u64_multi_bit_cache) }
        } else {
            panic!("No keycache for given Scalar type")
        }
    }
}

lazy_static! {
    pub static ref KEY_CACHE: KeyCache = Default::default();
}
