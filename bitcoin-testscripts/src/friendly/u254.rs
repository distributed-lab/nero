//! This module contains the test script
//! for performing the multiplication of two large integers
//! (exceeding standard Bitcoin 31-bit integers)

use bitcoin_splitter::split::{
    core::{form_states_from_shards, SplitType},
    script::{IOPair, SplitResult, SplitableScript},
};
use bitcoin_utils::{pseudo::OP_2K_MUL, treepp::*};
use bitcoin_window_mul::{
    bigint::{
        implementation::NonNativeBigIntImpl,
        window::{binary_to_windowed_form, precompute::WindowedPrecomputeTable},
    },
    traits::integer::NonNativeLimbInteger,
};

use num_bigint::{BigUint, RandomBits};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

// Type aliases for some commonly used integers
pub type U64 = NonNativeBigIntImpl<64, 30>;
pub type U128 = NonNativeBigIntImpl<128, 30>;
pub type U254 = NonNativeBigIntImpl<254, 30>;
pub type U508 = NonNativeBigIntImpl<508, 30>;

/// BitVM-friendly script for multiplying two U254 scripts
pub type FriendlyU254MulScript = FriendlyMulScript<U254, U508, 3>;

/// BitVM-friendly script for multiplying two U64 scripts
pub type FriendlyU64MulScript = FriendlyMulScript<U64, U128, 3>;

/// Script that performs the multiplication of
/// two big integers with the width parameter of `W`.
///
/// As the generic parameters, it takes the `BaseInt` as
/// the basic `BigInt` type and `WideInt` as type of the
/// returned value (which must be with the twice the bitsize of `BaseInt`).
pub struct FriendlyMulScript<BaseInt, WideInt, const W: usize>
where
    BaseInt: NonNativeLimbInteger,
    WideInt: NonNativeLimbInteger,
{
    _marker: std::marker::PhantomData<(BaseInt, WideInt)>,
}

#[allow(non_snake_case)]
impl<BaseInt, WideInt, const W: usize> FriendlyMulScript<BaseInt, WideInt, W>
where
    BaseInt: NonNativeLimbInteger,
    WideInt: NonNativeLimbInteger,
{
    /// The size of the decomposition
    const DECOMPOSITION_SIZE: usize = usize::div_ceil(BaseInt::N_BITS, W);

    /// Recovery chunk size that is used to restore the original number
    const RECOVERY_CHUNK_SIZE: usize = BaseInt::LIMB_SIZE / W;

    /// Given a chunk `{ l[chunk_size-1], l[chunk_size-2], ..., l[1], l[0] }`,
    /// the function outputs the recovered limb `l = \sum_{i=0}^{n-1} l[i]*2^(W*i)`.
    pub fn OP_RECOVERLIMB(chunk_size: usize) -> Script {
        script! {
            for i in 0..chunk_size {
                // Multiplying by 2^(i*W)
                { OP_2K_MUL(i*W) }
                if i < chunk_size - 1 {
                    OP_TOALTSTACK
                }
            }

            // Adding remaining limbs together
            for _ in 0..chunk_size-1 {
                OP_FROMALTSTACK
                OP_ADD
            }
        }
    }

    /// Given the lookup table ` {0*x}, {1*x}, {2*x}, ..., {(1<<W-1)*x}`,
    /// returns the single element of `x`. Moreover, this `x` gets
    /// compressed back to the lower-bit integer.
    pub fn OP_RECOVER_FROM_PRECOMPUTETABLE() -> Script {
        script! {
            for _ in 0..(1<<W)-2 {
                { WideInt::OP_DROP() }
            }
            // At this point, we have { y_decomposition } { 0 } { x }
            { WideInt::OP_SWAP() } // { y_decomposition } { x } { 0 }
            { WideInt::OP_DROP() } // { y_decomposition } { x }

            // Compress x back to the original form
            { WideInt::OP_COMPRESS::<BaseInt>() }
        }
    }

    /// Restores the original number from the w-width form which lies
    /// in the stack.
    ///
    /// NOTE: Only works when the limb bitsize is divisible by `W`
    pub fn OP_RECOVER() -> Script {
        assert_eq!(BaseInt::LIMB_SIZE % W, 0, "N_LIMBS must be divisible by W",);

        script! {
            // Reverse the decomposition
            for i in (0..Self::DECOMPOSITION_SIZE).rev() {
                { i } OP_ROLL OP_TOALTSTACK
            }
            for _ in 0..Self::DECOMPOSITION_SIZE {
                OP_FROMALTSTACK
            }

            for i in 0..BaseInt::N_LIMBS {
                // Convering the batch of decomposition limbs to the regular limb
                if i != BaseInt::N_LIMBS - 1 {
                    { Self::OP_RECOVERLIMB(Self::RECOVERY_CHUNK_SIZE) }
                    OP_TOALTSTACK // Pushing the limb to the altstack
                } else {
                    { Self::OP_RECOVERLIMB(Self::DECOMPOSITION_SIZE % Self::RECOVERY_CHUNK_SIZE) }
                }
            }

            // Picking all the limbs from the altstack
            for _ in 0..BaseInt::N_LIMBS-1 {
                OP_FROMALTSTACK
            }
        }
    }

    /// Given an integer, decomposes it into the windowed form
    /// and pushes the result to the mainstack.
    pub fn OP_TOWINDOWFORM() -> Script {
        script! {
            { BaseInt::OP_TOBEBITS_TOALTSTACK() }
            { binary_to_windowed_form::<W>(BaseInt::N_BITS) }
        }
    }

    /// Given `{ decomposition } { lookup_table } { r }` in the stack,
    /// this function converts it to the form `{ y } { x } { r }`.
    ///
    /// This function is used as the part of the large multiplication
    /// script to reduce the cost of intermediate states. Further, this state
    /// is decompressed using the [`Self::OP_DECOMPRESS`] function.
    pub fn OP_COMPRESS() -> Script {
        script! {
            { WideInt::OP_TOALTSTACK() }                // { decomposition } { lookup_table }
            { Self::OP_RECOVER_FROM_PRECOMPUTETABLE() } // { decomposition } { x }
            { BaseInt::OP_TOALTSTACK() }                // { decomposition }
            { Self::OP_RECOVER() }                      // { y }
            { BaseInt::OP_FROMALTSTACK() }              // { y } { x }
            { WideInt::OP_FROMALTSTACK() }              // { y } { x } { r }
        }
    }

    /// Given { y } { x } { r }, it converts it to
    /// { y } { x } { r }
    pub fn OP_DECOMPRESS() -> Script {
        script! {
            { WideInt::OP_TOALTSTACK() }     // { y } { x_compressed }
            { BaseInt::OP_EXTEND::<WideInt>() } // { y } { x }
            { WideInt::OP_TOALTSTACK() }     // { y }
            { Self::OP_TOWINDOWFORM() }   // { y_decomposition }
            { WideInt::OP_FROMALTSTACK() }   // { y_decomposition } { x }
            { WindowedPrecomputeTable::<WideInt, W, false>::initialize() } // { y_decomposition } { lookup_table }
            { WideInt::OP_FROMALTSTACK() }   // { y_decomposition } { lookup_table } { r }
        }
    }
}

impl<BaseInt, WideInt, const W: usize> SplitableScript for FriendlyMulScript<BaseInt, WideInt, W>
where
    BaseInt: NonNativeLimbInteger,
    WideInt: NonNativeLimbInteger,
{
    /// Input is simply two 254-bit numbers
    const INPUT_SIZE: usize = 2 * BaseInt::N_LIMBS;

    /// Output is a 508-bit number
    const OUTPUT_SIZE: usize = WideInt::N_LIMBS;

    fn script() -> Script {
        script! {
            // Convert to w-width form. This way, our stack looks like
            // { x } { y_decomposition }
            { BaseInt::OP_TOBEBITS_TOALTSTACK() }
            { binary_to_windowed_form::<W>(BaseInt::N_BITS) }

            // Picking { x } to the top to get
            // { y_decomposition } { x }
            for _ in (0..BaseInt::N_LIMBS).rev() {
                { Self::DECOMPOSITION_SIZE + BaseInt::N_LIMBS - 1 } OP_ROLL
            }

            // Extend to larger integer to get
            // { y_decomposition } { x_extended }
            { BaseInt::OP_EXTEND::<WideInt>() }

            // Precomputing {0*z, 1*z, ..., ((1<<WIDTH)-1)*z} to get
            // { y_decomposition } { lookup_table }
            { WindowedPrecomputeTable::<WideInt, W, false>::initialize() }

            // We initialize the result
            // Note that we can simply pick the precomputed value
            // since 0*16 is still 0, so we omit the doubling :)
            { (1<<W) * WideInt::N_LIMBS } OP_PICK 1 OP_ADD
            { 1<<W }
            OP_SWAP
            OP_SUB
            { WideInt::OP_PICKSTACK() }

            // At this point, our stack looks as follows:
            // { y_decomposition } { lookup_table } { r }

            { Self::OP_COMPRESS() }

            for i in 1..Self::DECOMPOSITION_SIZE {
                // We decompress the compressed state to make the loop interation
                { Self::OP_DECOMPRESS() }

                // Double the result WIDTH times
                for _ in 0..W {
                    { WideInt::OP_2MUL_NOOVERFLOW(0) }
                }

                // Picking di from the stack
                { ((1<<W) + 1) * WideInt::N_LIMBS + i } OP_PICK

                // Add the precomputed value to the result.
                // Since currently stack looks like:
                // {0*z, 1*z, ..., ((1<<WIDTH)-1)*z, r, di} with
                // r being the result, we need to copy
                // (1<<WIDTH - di)th element to the top of the stack.
                { 1<<W }
                OP_SWAP
                OP_SUB
                { WideInt::OP_PICKSTACK() }
                { WideInt::OP_ADD_NOOVERFLOW(0, 1) }

                // After the loop iteration is completed, we compress the state
                // to reduce the cost of the intermediate states.
                { Self::OP_COMPRESS() }
            }

            // Clearing the precomputed values from the stack.
            { WideInt::OP_TOALTSTACK() }
            { BaseInt::OP_DROP() }
            { BaseInt::OP_DROP() }
            { WideInt::OP_FROMALTSTACK() }
        }
    }

    fn generate_valid_io_pair() -> IOPair {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // Generate two random 254-bit numbers and calculate their sum
        let num_1: BigUint = prng.sample(RandomBits::new(BaseInt::N_BITS as u64));
        let num_2: BigUint = prng.sample(RandomBits::new(BaseInt::N_BITS as u64));
        let product: BigUint = num_1.clone() * num_2.clone();

        IOPair {
            input: script! {
                { BaseInt::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
                { BaseInt::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            },
            output: WideInt::OP_PUSH_U32LESLICE(&product.to_u32_digits()),
        }
    }

    fn generate_invalid_io_pair() -> IOPair {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // Generate two random 254-bit numbers and calculate their sum
        let num_1: BigUint = prng.sample(RandomBits::new(BaseInt::N_BITS as u64));
        let num_2: BigUint = prng.sample(RandomBits::new(BaseInt::N_BITS as u64));
        let mut product: BigUint = num_1.clone() * num_2.clone();

        // Flip a random bit in the product
        let bit_to_flip = prng.gen_range(0..product.bits());
        product.set_bit(bit_to_flip, !product.bit(bit_to_flip));

        IOPair {
            input: script! {
                { BaseInt::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
                { BaseInt::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            },
            output: WideInt::OP_PUSH_U32LESLICE(&product.to_u32_digits()),
        }
    }

    fn default_split(input: Script, _split_type: SplitType) -> SplitResult {
        // First, we need to form the script
        let mut shards: Vec<Script> = vec![];
        shards.push(script! {
            // Convert to w-width form. This way, our stack looks like
            // { x } { y_decomposition }
            { BaseInt::OP_TOBEBITS_TOALTSTACK() }
            { binary_to_windowed_form::<W>(BaseInt::N_BITS) }

            // Picking { x } to the top to get
            // { y_decomposition } { x }
            for _ in (0..BaseInt::N_LIMBS).rev() {
                { Self::DECOMPOSITION_SIZE + BaseInt::N_LIMBS - 1 } OP_ROLL
            }

            // Extend to larger integer to get
            // { y_decomposition } { x_extended }
            { BaseInt::OP_EXTEND::<WideInt>() }

            // Precomputing {0*z, 1*z, ..., ((1<<WIDTH)-1)*z} to get
            // { y_decomposition } { lookup_table }
            { WindowedPrecomputeTable::<WideInt, W, false>::initialize() }

            // We initialize the result
            // Note that we can simply pick the precomputed value
            // since 0*16 is still 0, so we omit the doubling :)
            { (1<<W) * WideInt::N_LIMBS } OP_PICK 1 OP_ADD
            { 1<<W }
            OP_SWAP
            OP_SUB
            { WideInt::OP_PICKSTACK() }

            // At this point, our stack looks as follows:
            // { y_decomposition } { lookup_table } { r }

            // Dropping stage
            { Self::OP_COMPRESS() }
        });

        for i in 1..Self::DECOMPOSITION_SIZE {
            shards.push(script! {
                { Self::OP_DECOMPRESS() }

                // Double the result WIDTH times
                for _ in 0..W {
                    { WideInt::OP_2MUL_NOOVERFLOW(0) }
                }

                // Picking di from the stack
                { ((1<<W) + 1) * WideInt::N_LIMBS + i } OP_PICK

                // Add the precomputed value to the result.
                // Since currently stack looks like:
                // {0*z, 1*z, ..., ((1<<WIDTH)-1)*z, r, di} with
                // r being the result, we need to copy
                // (1<<WIDTH - di)th element to the top of the stack.
                { 1<<W }
                OP_SWAP
                OP_SUB
                { WideInt::OP_PICKSTACK() }
                { WideInt::OP_ADD_NOOVERFLOW(0, 1) }

                { Self::OP_COMPRESS() }
            })
        }

        shards.push(script! {
            // Clearing the precomputed values from the stack.
            { WideInt::OP_TOALTSTACK() }
            { BaseInt::OP_DROP() }
            { BaseInt::OP_DROP() }
            { WideInt::OP_FROMALTSTACK() }
        });

        // Now, we need to form the intermediate states
        let intermediate_states = form_states_from_shards(shards.clone(), input);

        SplitResult {
            shards,
            intermediate_states,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_splitter::split::core::SplitType;
    use bitcoin_utils::{comparison::OP_LONGEQUALVERIFY, stack_to_script};
    use bitcoin_window_mul::{
        bigint::{window::NonNativeWindowedBigIntImpl, U254Windowed},
        traits::{comparable::Comparable, integer::NonNativeInteger},
    };

    #[test]
    fn test_u254_verify() {
        assert!(FriendlyU254MulScript::verify_random());
    }

    #[test]
    fn test_u64_verify() {
        assert!(FriendlyU64MulScript::verify_random());
    }

    #[test]
    fn test_chunk_to_limb() {
        const DECOMPOSITION: [u32; 10] = [2, 4, 2, 6, 3, 4, 1, 3, 4, 1];

        let verification_script = script! {
            for element in DECOMPOSITION.into_iter().rev() {
                { element }
            }
            { FriendlyU254MulScript::OP_RECOVERLIMB(DECOMPOSITION.len()) }
            { 208026786 }
            OP_EQUAL
        };

        let result = execute_script(verification_script);
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_u254_recovery() {
        // Picking a random integer
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let x: BigUint = prng.sample(RandomBits::new(U254::N_BITS as u64));

        // In the verification script, we do the following:
        // 1. Push x to the stack
        // 2. Convert x to the windowed form
        // 3. Convert the windowed form to the limb form
        // 4. Verify that the result is equal to x
        let verification_script = script! {
            { U254::OP_PUSH_U32LESLICE(&x.to_u32_digits()) }
            { U254::OP_PICK(0) }
            { FriendlyU254MulScript::OP_TOWINDOWFORM() }
            { FriendlyU254MulScript::OP_RECOVER() }
            { U254::OP_EQUAL(0, 1) }
        };

        let result = execute_script(verification_script);
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_u254_invalid_generate() {
        let IOPair { input, output } = FriendlyU254MulScript::generate_invalid_io_pair();
        assert!(
            !FriendlyU254MulScript::verify(input.clone(), output.clone()),
            "input/output is correct"
        );
    }

    #[test]
    fn test_u254_naive_split_correctness() {
        // Generating a random valid input for the script and the script itself
        let IOPair { input, output } = FriendlyU254MulScript::generate_valid_io_pair();
        assert!(
            FriendlyU254MulScript::verify(input.clone(), output.clone()),
            "input/output is not correct"
        );

        // Splitting the script into shards
        let split_result =
            FriendlyU254MulScript::default_split(input.clone(), SplitType::ByInstructions);

        // Now, we are going to concatenate all the shards and verify that the script is also correct
        let verification_script = script! {
            { input }
            for shard in split_result.shards {
                { shard }
            }
            { output }

            // Now, we need to verify that the output is correct.
            { OP_LONGEQUALVERIFY(FriendlyU254MulScript::OUTPUT_SIZE) }
            OP_TRUE
        };

        let result = execute_script(verification_script);
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_u254_naive_split() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = FriendlyU254MulScript::generate_valid_io_pair();

        // Debugging the whole script size:
        println!(
            "Old algorithm costed {} bytes",
            U254Windowed::OP_WIDENINGMUL::<U508>().len()
        );
        println!(
            "New script size is {} bytes",
            FriendlyU254MulScript::script().len()
        );

        // Splitting the script into shards
        let split_result = FriendlyU254MulScript::default_split(input, SplitType::ByInstructions);

        for (i, shard) in split_result.shards.iter().enumerate() {
            println!("Shard {i} length: {} bytes", shard.len());
        }

        // Checking the last state (which must be equal to the result of the multiplication)
        let last_state = split_result.must_last_state();

        // Altstack must be empty
        assert!(last_state.altstack.is_empty(), "altstack is not empty!");

        // The element of the mainstack must be equal to the actual output
        let verification_script = script! {
            { stack_to_script(&last_state.stack) }
            { output }
            { U508::OP_EQUAL(0, 1) }
        };

        let result = execute_script(verification_script);
        assert!(result.success, "verification has failed");

        // Printing
        for (i, state) in split_result.intermediate_states.iter().enumerate() {
            println!(
                "Intermediate state {} is {:?} bytes",
                i,
                state.stack.len() + state.altstack.len()
            );
        }
    }

    #[test]
    fn test_u64_naive_split() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = FriendlyU64MulScript::generate_valid_io_pair();

        // Next, we try the old version of mul to compare the sizes
        type U64Windowed = NonNativeWindowedBigIntImpl<U64, 4>;

        // Debugging the whole script size:
        println!(
            "Old algorithm costed {} bytes",
            U64Windowed::OP_WIDENINGMUL::<U128>().len()
        );
        println!(
            "New script size is {} bytes",
            FriendlyU64MulScript::script().len()
        );

        // Splitting the script into shards
        let split_result = FriendlyU64MulScript::default_split(input, SplitType::ByInstructions);

        for (i, shard) in split_result.shards.iter().enumerate() {
            println!("Shard {i} length: {} bytes", shard.len());
        }

        // Checking the last state (which must be equal to the result of the multiplication)
        let last_state = split_result.must_last_state();

        // Altstack must be empty
        assert!(last_state.altstack.is_empty(), "altstack is not empty!");

        // The element of the mainstack must be equal to the actual output
        let verification_script = script! {
            { stack_to_script(&last_state.stack) }
            { output }
            { U128::OP_EQUAL(0, 1) }
        };

        let result = execute_script(verification_script);
        assert!(result.success, "verification has failed");

        // Printing
        for (i, state) in split_result.intermediate_states.iter().enumerate() {
            println!(
                "Intermediate state {} is {:?} bytes",
                i,
                state.stack.len() + state.altstack.len()
            );
        }
    }

    #[test]
    fn test_split_each_shard() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output: _ } = FriendlyU254MulScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result =
            FriendlyU254MulScript::default_split(input.clone(), SplitType::ByInstructions);

        for i in 0..split_result.len() {
            // Forming first two inputs. Note that the first input is the input script itself
            // while the second input is the output of the previous shard
            let mut first_input = input.clone();
            if i > 0 {
                first_input = split_result.intermediate_states[i - 1].inject_script();
            }

            let second_input = split_result.intermediate_states[i].inject_script();

            // Forming the function
            let function = split_result.shards[i].clone();

            let verification_script = script! {
                { second_input }
                { first_input }
                { function }

                // Verifying that the output in mainstack is correct
                { OP_LONGEQUALVERIFY(split_result.intermediate_states[i].stack.len()) }

                // Verifying that the output in altstack is correct
                // Pushing elements to the mainstack
                for _ in 0..2*split_result.intermediate_states[i].altstack.len() {
                    OP_FROMALTSTACK
                }

                // Verifying that altstack elements are correct
                { OP_LONGEQUALVERIFY(split_result.intermediate_states[i].altstack.len()) }
                OP_TRUE
            };

            let result = execute_script(verification_script);

            assert!(result.success, "verification has failed");
        }
    }

    #[test]
    fn test_split_to_u32() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output: _ } = FriendlyU254MulScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result =
            FriendlyU254MulScript::default_split(input.clone(), SplitType::ByInstructions);

        for i in 0..split_result.len() {
            // Forming first two inputs. Note that the first input is the input script itself
            // while the second input is the output of the previous shard
            let mut first_input = input.clone();
            if i > 0 {
                first_input = split_result.intermediate_states[i - 1]
                    .to_bytes()
                    .inject_script();
            }
            let second_input = split_result.intermediate_states[i]
                .to_bytes()
                .inject_script();

            // Forming the function
            let function = split_result.shards[i].clone();

            let verification_script = script! {
                { second_input }
                { first_input }
                { function }

                // Verifying that the output in mainstack is correct
                { OP_LONGEQUALVERIFY(split_result.intermediate_states[i].stack.len()) }

                // Verifying that the output in altstack is correct
                // Pushing elements to the mainstack
                for _ in 0..2*split_result.intermediate_states[i].altstack.len() {
                    OP_FROMALTSTACK
                }

                // Verifying that altstack elements are correct
                { OP_LONGEQUALVERIFY(split_result.intermediate_states[i].altstack.len()) }
                OP_TRUE
            };

            let result = execute_script(verification_script);

            assert!(result.success, "verification has failed");
        }
    }
}
