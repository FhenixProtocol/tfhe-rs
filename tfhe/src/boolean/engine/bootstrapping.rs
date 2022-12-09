use crate::boolean::ciphertext::Ciphertext;
use crate::boolean::{ClientKey, PLAINTEXT_TRUE};
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seeder};
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::math::fft::Fft;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::error::Error;

/// Memory used as buffer for the bootstrap
///
/// It contains contiguous chunk which is then sliced and converted
/// into core's View types.
#[derive(Default)]
struct Memory {
    buffer: Vec<u32>,
}

impl Memory {
    /// Return a tuple with buffers that matches the server key.
    ///
    /// - The first element is the accumulator for bootstrap step.
    /// - The second element is a lwe buffer where the result of the of the bootstrap should be
    ///   written
    fn as_buffers(
        &mut self,
        server_key: &ServerKey,
    ) -> (GlweCiphertextView<'_, u32>, LweCiphertextMutView<'_, u32>) {
        let num_elem_in_accumulator = server_key.bootstrapping_key.glwe_size().0
            * server_key.bootstrapping_key.polynomial_size().0;
        let num_elem_in_lwe = server_key
            .bootstrapping_key
            .output_lwe_dimension()
            .to_lwe_size()
            .0;
        let total_elem_needed = num_elem_in_accumulator + num_elem_in_lwe;

        let all_elements = if self.buffer.len() < total_elem_needed {
            self.buffer.resize(total_elem_needed, 0u32);
            self.buffer.as_mut_slice()
        } else {
            &mut self.buffer[..total_elem_needed]
        };

        let (accumulator_elements, lwe_elements) =
            all_elements.split_at_mut(num_elem_in_accumulator);

        {
            let mut accumulator = GlweCiphertextMutView::from_container(
                accumulator_elements,
                server_key.bootstrapping_key.polynomial_size(),
            );

            accumulator.get_mut_mask().as_mut().fill(0u32);
            accumulator.get_mut_body().as_mut().fill(PLAINTEXT_TRUE);
        }

        let accumulator = GlweCiphertextView::from_container(
            accumulator_elements,
            server_key.bootstrapping_key.polynomial_size(),
        );

        let lwe = LweCiphertextMutView::from_container(lwe_elements);

        (accumulator, lwe)
    }
}

/// A structure containing the server public key.
///
/// This server key data lives on the CPU.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic Boolean circuits.
///
/// In more details, it contains:
/// * `bootstrapping_key` - a public key, used to perform the bootstrapping operation.
/// * `key_switching_key` - a public key, used to perform the key-switching operation.
#[derive(Clone)]
pub struct ServerKey {
    pub(crate) bootstrapping_key: FourierLweBootstrapKeyOwned,
    pub(crate) key_switching_key: LweKeyswitchKeyOwned<u32>,
}

/// Perform ciphertext bootstraps on the CPU
pub(crate) struct Bootstrapper {
    memory: Memory,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    pub(crate) computation_buffers: ComputationBuffers,
}

impl Bootstrapper {
    pub fn new(seeder: &mut dyn Seeder) -> Self {
        Bootstrapper {
            memory: Default::default(),
            encryption_generator: EncryptionRandomGenerator::<_>::new(seeder.seed(), seeder),
            computation_buffers: Default::default(),
        }
    }

    pub(crate) fn new_server_key(
        &mut self,
        cks: &ClientKey,
    ) -> Result<ServerKey, Box<dyn std::error::Error>> {
        let standard_bootstraping_key: LweBootstrapKeyOwned<u32> =
            par_allocate_and_generate_new_lwe_bootstrap_key(
                &cks.lwe_secret_key,
                &cks.glwe_secret_key,
                cks.parameters.pbs_base_log,
                cks.parameters.pbs_level,
                cks.parameters.glwe_modular_std_dev,
                &mut self.encryption_generator,
            );

        // creation of the bootstrapping key in the Fourier domain
        let mut fourier_bsk = FourierLweBootstrapKey::new(
            standard_bootstraping_key.input_lwe_dimension(),
            standard_bootstraping_key.glwe_size(),
            standard_bootstraping_key.polynomial_size(),
            standard_bootstraping_key.decomposition_base_log(),
            standard_bootstraping_key.decomposition_level_count(),
        );

        let fft = Fft::new(standard_bootstraping_key.polynomial_size());
        let fft = fft.as_view();
        self.computation_buffers.resize(
            convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized_scratch(fft)
                .unwrap()
                .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Conversion to fourier domain
        convert_standard_lwe_bootstrap_key_to_fourier_mem_optimized(
            &standard_bootstraping_key,
            &mut fourier_bsk,
            fft,
            stack,
        );

        // Convert the GLWE secret key into an LWE secret key:
        let big_lwe_secret_key = cks.glwe_secret_key.clone().into_lwe_secret_key();

        // creation of the key switching key
        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &big_lwe_secret_key,
            &cks.lwe_secret_key,
            cks.parameters.ks_base_log,
            cks.parameters.ks_level,
            cks.parameters.lwe_modular_std_dev,
            &mut self.encryption_generator,
        );

        Ok(ServerKey {
            bootstrapping_key: fourier_bsk,
            key_switching_key: ksk,
        })
    }

    pub(crate) fn bootstrap(
        &mut self,
        input: &LweCiphertextOwned<u32>,
        server_key: &ServerKey,
    ) -> Result<LweCiphertextOwned<u32>, Box<dyn Error>> {
        let (accumulator, mut buffer_after_pbs) = self.memory.as_buffers(server_key);

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_scratch::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            input,
            &mut buffer_after_pbs,
            &accumulator,
            fourier_bsk,
            fft,
            stack,
        );

        Ok(LweCiphertext::from_container(
            buffer_after_pbs.as_ref().to_owned(),
        ))
    }

    pub(crate) fn keyswitch(
        &mut self,
        input: &LweCiphertextOwned<u32>,
        server_key: &ServerKey,
    ) -> Result<LweCiphertextOwned<u32>, Box<dyn Error>> {
        // Allocate the output of the KS
        let mut output = LweCiphertext::new(
            0u32,
            server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        );

        keyswitch_lwe_ciphertext(&server_key.key_switching_key, input, &mut output);

        Ok(output)
    }

    pub(crate) fn bootstrap_keyswitch(
        &mut self,
        mut ciphertext: LweCiphertextOwned<u32>,
        server_key: &ServerKey,
    ) -> Result<Ciphertext, Box<dyn Error>> {
        let (accumulator, mut buffer_lwe_after_pbs) = self.memory.as_buffers(server_key);

        let fourier_bsk = &server_key.bootstrapping_key;

        let fft = Fft::new(fourier_bsk.polynomial_size());
        let fft = fft.as_view();

        self.computation_buffers.resize(
            programmable_bootstrap_lwe_ciphertext_mem_optimized_scratch::<u64>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft,
            )
            .unwrap()
            .unaligned_bytes_required(),
        );
        let stack = self.computation_buffers.stack();

        // Compute a bootstrap
        programmable_bootstrap_lwe_ciphertext_mem_optimized(
            &ciphertext,
            &mut buffer_lwe_after_pbs,
            &accumulator,
            fourier_bsk,
            fft,
            stack,
        );

        // Compute a key switch to get back to input key
        keyswitch_lwe_ciphertext(
            &server_key.key_switching_key,
            &buffer_lwe_after_pbs,
            &mut ciphertext,
        );

        Ok(Ciphertext::Encrypted(ciphertext))
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableServerKey {
    pub bootstrapping_key: Vec<u8>,
    pub key_switching_key: Vec<u8>,
}

impl Serialize for ServerKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key_switching_key =
            bincode::serialize(&self.key_switching_key).map_err(serde::ser::Error::custom)?;
        let bootstrapping_key =
            bincode::serialize(&self.bootstrapping_key).map_err(serde::ser::Error::custom)?;

        SerializableServerKey {
            key_switching_key,
            bootstrapping_key,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let thing =
            SerializableServerKey::deserialize(deserializer).map_err(serde::de::Error::custom)?;

        let key_switching_key = bincode::deserialize(thing.key_switching_key.as_slice())
            .map_err(serde::de::Error::custom)?;
        let bootstrapping_key = bincode::deserialize(thing.bootstrapping_key.as_slice())
            .map_err(serde::de::Error::custom)?;

        Ok(Self {
            bootstrapping_key,
            key_switching_key,
        })
    }
}
