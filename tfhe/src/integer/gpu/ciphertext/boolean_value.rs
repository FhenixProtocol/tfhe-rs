use crate::core_crypto::entities::{LweCiphertextList, LweCiphertextOwned};
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::CudaStream;
use crate::core_crypto::prelude::{CiphertextModulus, LweSize};
use crate::integer::gpu::ciphertext::info::{CudaBlockInfo, CudaRadixCiphertextInfo};
use crate::integer::gpu::ciphertext::CudaRadixCiphertext;
use crate::integer::{BooleanBlock, RadixCiphertext};
use crate::shortint::Ciphertext;

/// Wrapper type used to signal that the inner value encrypts 0 or 1
///
/// Since values ares encrypted, it is not possible to know whether a
/// ciphertext encrypts a boolean value (0 or 1). However, some algorithms
/// require that the ciphertext does indeed encrypt a boolean value.
///
/// This wrapper serves as making it explicit that it is known that the value
/// encrypted is 0 or 1. And that if a function taking a CudaBooleanBlock as input
/// returns incorrect value, it may be due to the value not really being 0 or 1.
///
/// Also, some function such as comparisons are known to return an encrypted value
/// that is either 0 or 1, and thus return a CudaCiphertext wrapped in a [CudaBooleanBlock].
pub struct CudaBooleanBlock {
    pub ciphertext: CudaRadixCiphertext,
}

impl CudaBooleanBlock {
    /// Creates a new CudaBooleanBlock without checks.
    ///
    /// You have to be sure the ciphertext has only one block and encrypts 0 or 1 otherwise
    /// functions expecting a CudaBooleanBlock could result in wrong computation
    pub fn new_unchecked(
        d_blocks: CudaLweCiphertextList<u64>,
        info: CudaRadixCiphertextInfo,
    ) -> Self {
        Self {
            ciphertext: CudaRadixCiphertext { d_blocks, info },
        }
    }

    pub fn from_boolean_block(boolean_block: &BooleanBlock, stream: &CudaStream) -> Self {
        let mut h_boolean_block = boolean_block.clone();

        let lwe_size = boolean_block.0.ct.as_ref().len();

        let h_ct = LweCiphertextList::from_container(
            h_boolean_block.0.ct.as_mut(),
            LweSize(lwe_size),
            CiphertextModulus::new_native(),
        );
        let d_blocks = CudaLweCiphertextList::from_lwe_ciphertext_list(&h_ct, stream);

        let info = CudaBlockInfo {
            degree: boolean_block.0.degree,
            message_modulus: boolean_block.0.message_modulus,
            carry_modulus: boolean_block.0.carry_modulus,
            pbs_order: boolean_block.0.pbs_order,
            noise_level: boolean_block.0.noise_level(),
        };
        let radix_info = vec![info];
        let info = CudaRadixCiphertextInfo { blocks: radix_info };

        Self {
            ciphertext: CudaRadixCiphertext { d_blocks, info },
        }
    }

    pub fn copy_from_boolean_block(&mut self, boolean_block: &BooleanBlock, stream: &CudaStream) {
        unsafe {
            self.ciphertext
                .d_blocks
                .0
                .d_vec
                .copy_from_cpu_async(boolean_block.0.ct.as_ref(), stream);
        }
        stream.synchronize();

        let info = CudaBlockInfo {
            degree: boolean_block.0.degree,
            message_modulus: boolean_block.0.message_modulus,
            carry_modulus: boolean_block.0.carry_modulus,
            pbs_order: boolean_block.0.pbs_order,
            noise_level: boolean_block.0.noise_level(),
        };
        let radix_info = vec![info];
        self.ciphertext.info = CudaRadixCiphertextInfo { blocks: radix_info };
    }

    /// ```rust
    /// use tfhe::core_crypto::gpu::{CudaDevice, CudaStream};
    /// use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
    /// use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    /// use tfhe::integer::gpu::gen_keys_radix_gpu;
    /// use tfhe::integer::BooleanBlock;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// let gpu_index = 0;
    /// let device = CudaDevice::new(gpu_index);
    /// let mut stream = CudaStream::new_unchecked(device);
    ///
    /// // Generate the client key and the server key:
    /// let num_blocks = 1;
    /// let (cks, sks) = gen_keys_radix_gpu(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks, &mut stream);
    ///
    /// let msg1 = 1u32;
    /// let ct1 = BooleanBlock::try_new(&cks.encrypt(msg1)).unwrap();
    ///
    /// // Copy to GPU
    /// let d_ct1 = CudaBooleanBlock::from_boolean_block(&ct1, &mut stream);
    /// let ct2 = d_ct1.to_boolean_block(&mut stream);
    /// let res = cks.decrypt_bool(&ct2);
    ///
    /// assert_eq!(msg1, res);
    /// ```
    pub fn to_boolean_block(&self, stream: &CudaStream) -> BooleanBlock {
        let h_lwe_ciphertext_list = self.ciphertext.d_blocks.to_lwe_ciphertext_list(stream);
        let ciphertext_modulus = h_lwe_ciphertext_list.ciphertext_modulus();

        let block = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                h_lwe_ciphertext_list.into_container(),
                ciphertext_modulus,
            ),
            degree: self.ciphertext.info.blocks[0].degree,
            noise_level: self.ciphertext.info.blocks[0].noise_level,
            message_modulus: self.ciphertext.info.blocks[0].message_modulus,
            carry_modulus: self.ciphertext.info.blocks[0].carry_modulus,
            pbs_order: self.ciphertext.info.blocks[0].pbs_order,
        };
        let block_vec = vec![block];
        let h_blocks = RadixCiphertext { blocks: block_vec };

        BooleanBlock::try_new(&h_blocks).unwrap()
    }
}

impl AsRef<CudaRadixCiphertext> for CudaBooleanBlock {
    fn as_ref(&self) -> &CudaRadixCiphertext {
        &self.ciphertext
    }
}
impl AsMut<CudaRadixCiphertext> for CudaBooleanBlock {
    fn as_mut(&mut self) -> &mut CudaRadixCiphertext {
        &mut self.ciphertext
    }
}
