use crate::core_crypto::prelude::*;
use crate::keycache::*;
use lazy_static::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LweMultiBitBootstrapParameters<Scalar: UnsignedInteger> {
    fill_with: Scalar,
    glwe_size: GlweSize,
    glwe_modular_std_dev: StandardDev,
    polynomial_size: PolynomialSize,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    input_lwe_dimension: LweDimension,
    grouping_factor: LweBskGroupingFactor,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    input_lwe_secret_key: &LweSecretKeyOwned<Scalar>,
    output_glwe_secret_key: &GlweSecretKeyOwned<Scalar>,
    encryption_random_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
}

impl<Scalar: UnsignedInteger> NamedParam for LweMultiBitBootstrapParameters<Scalar> {
    fn name(&self) -> String {
        format!(
            "PARAM_LWE_MULTI_BIT_BOOTSTRAP_glwe_{}_poly_{}_decomp_base_log_{}_decomp_level_{}_input_dim_{}_group_fact_{}_ct_modulus_{}",
            self.glwe_size.0, self.polynomial_size.0, self.decomp_base_log.0,
            self.decomp_level_count.0, self.input_lwe_dimension.0, self.grouping_factor.0,
            self.ciphertext_modulus
        )
    }
}

pub struct KeyCacheCoreImpl<Scalar: UnsignedInteger> {
    inner: ImplKeyCache<
        LweMultiBitBootstrapParameters<Scalar>,
        LweMultiBitBootstrapKeyOwned<Scalar>,
        FileStorage,
    >,
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

pub struct SharedMultiBitBootstrapKey<Scalar: UnsignedInteger> {
    inner: GenericSharedKey<LweMultiBitBootstrapKeyOwned<Scalar>>,
}

impl<Scalar: UnsignedInteger> SharedMultiBitBootstrapKey<Scalar> {
    pub fn key(&self) -> &LweMultiBitBootstrapKeyOwned<Scalar> {
        &self.inner
    }
}

impl<Scalar: UnsignedInteger> From<LweMultiBitBootstrapParameters<Scalar>>
    for LweMultiBitBootstrapKeyOwned<Scalar>
{
    fn from(param: LweMultiBitBootstrapParameters<Scalar>) -> Self {
        let mut bsk = LweMultiBitBootstrapKey::new(
            param.fill_with,
            param.glwe_size,
            param.polynomial_size,
            param.decomp_base_log,
            param.decomp_level_count,
            param.input_lwe_dimension,
            param.grouping_factor,
            param.ciphertext_modulus,
        );

        par_generate_lwe_multi_bit_bootstrap_key(
            param.input_lwe_secret_key,
            param.output_glwe_secret_key,
            &mut bsk,
            param.glwe_modular_std_dev,
            param.encryption_random_generator,
        );

        bsk
    }
}

impl<Scalar: UnsignedInteger + UnsignedTorus + CastFrom<usize> + Serialize + DeserializeOwned> KeyCacheCoreImpl<Scalar> {
    pub fn get_multi_bit_key(
        &self,
        fill_with: Scalar,
        glwe_size: GlweSize,
        glwe_modular_std_dev: StandardDev,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        grouping_factor: LweBskGroupingFactor,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        input_lwe_secret_key: &LweSecretKeyOwned<Scalar>,
        output_glwe_secret_key: &GlweSecretKeyOwned<Scalar>,
        encryption_random_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    ) -> SharedMultiBitBootstrapKey<Scalar> {
        let param = LweMultiBitBootstrapParameters {
            fill_with,
            glwe_size,
            glwe_modular_std_dev,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            grouping_factor,
            ciphertext_modulus,
            input_lwe_secret_key,
            output_glwe_secret_key,
            encryption_random_generator,
        };

        SharedMultiBitBootstrapKey {
            inner: self.inner.get(param),
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
    pub fn get_multi_bit_key<
        Scalar: UnsignedInteger + UnsignedTorus + CastFrom<usize> + KeyCacheAccess + Serialize + DeserializeOwned,
    >(
        &self,
        fill_with: Scalar,
        glwe_size: GlweSize,
        glwe_modular_std_dev: StandardDev,
        polynomial_size: PolynomialSize,
        decomp_base_log: DecompositionBaseLog,
        decomp_level_count: DecompositionLevelCount,
        input_lwe_dimension: LweDimension,
        grouping_factor: LweBskGroupingFactor,
        ciphertext_modulus: CiphertextModulus<Scalar>,
        input_lwe_secret_key: &LweSecretKeyOwned<Scalar>,
        output_glwe_secret_key: &GlweSecretKeyOwned<Scalar>,
        encryption_random_generator: &mut EncryptionRandomGenerator<ActivatedRandomGenerator>,
    ) -> SharedMultiBitBootstrapKey<Scalar> {
        Scalar::access(self).get_multi_bit_key(
            fill_with,
            glwe_size,
            glwe_modular_std_dev,
            polynomial_size,
            decomp_base_log,
            decomp_level_count,
            input_lwe_dimension,
            grouping_factor,
            ciphertext_modulus,
            input_lwe_secret_key,
            output_glwe_secret_key,
            encryption_random_generator
        )
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
