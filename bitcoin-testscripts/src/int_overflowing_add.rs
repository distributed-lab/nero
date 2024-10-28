//! This module contains the test script
//! for performing the addition of two large integers
//! (exceeding standard Bitcoin 31-bit integers)

use bitcoin_splitter::split::script::{IOPair, SplitableScript};
use bitcoin_utils::treepp::*;
use bitcoin_window_mul::{
    bigint::implementation::NonNativeBigIntImpl,
    traits::{arithmeticable::Arithmeticable, integer::NonNativeInteger},
};

use core::ops::{Rem, Shl};
use num_bigint::{BigUint, RandomBits};
use num_traits::One;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Script that performs the overflowing addition of two N-bit numbers
pub struct BigIntOverflowingAddScript<const N_BITS: usize>;

/// The limb size used to represent an integer. In practice,
/// 29 is the most reliable limb size.
const LIMB_SIZE: usize = 29;

impl<const N_BITS: usize> BigIntOverflowingAddScript<N_BITS> {
    /// Limb size in bits to represent an integer
    const LIMB_SIZE: usize = LIMB_SIZE;
}

impl<const N_BITS: usize> SplitableScript for BigIntOverflowingAddScript<N_BITS> {
    /// Input size is double the number of limbs of BigInteger since we are adding two numbers
    const INPUT_SIZE: usize = 2 * usize::div_ceil(N_BITS, Self::LIMB_SIZE);
    /// Output size is the number of limbs of a bit integer
    const OUTPUT_SIZE: usize = usize::div_ceil(N_BITS, Self::LIMB_SIZE);

    fn script() -> Script {
        NonNativeBigIntImpl::<N_BITS, LIMB_SIZE>::OP_ADD(1, 0)
    }

    fn generate_valid_io_pair() -> IOPair {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // Generate two random 254-bit numbers and calculate their sum
        let num_1: BigUint = prng.sample(RandomBits::new(N_BITS as u64));
        let num_2: BigUint = prng.sample(RandomBits::new(N_BITS as u64));
        let sum: BigUint = (num_1.clone() + num_2.clone()).rem(BigUint::one().shl(N_BITS as u64));

        IOPair {
            input: script! {
                { NonNativeBigIntImpl::<N_BITS, LIMB_SIZE>::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
                { NonNativeBigIntImpl::<N_BITS, LIMB_SIZE>::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            },
            output: NonNativeBigIntImpl::<N_BITS, LIMB_SIZE>::OP_PUSH_U32LESLICE(
                &sum.to_u32_digits(),
            ),
        }
    }

    fn generate_invalid_io_pair() -> IOPair {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // Generate two random 254-bit numbers and calculate their sum
        let num_1: BigUint = prng.sample(RandomBits::new(N_BITS as u64));
        let num_2: BigUint = prng.sample(RandomBits::new(N_BITS as u64));
        let mut sum: BigUint =
            (num_1.clone() + num_2.clone()).rem(BigUint::one().shl(N_BITS as u64));

        // Flip a random bit in the sum
        let bit_to_flip = prng.gen_range(0..sum.bits());
        sum.set_bit(bit_to_flip, !sum.bit(bit_to_flip));

        IOPair {
            input: script! {
                { NonNativeBigIntImpl::<N_BITS, LIMB_SIZE>::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
                { NonNativeBigIntImpl::<N_BITS, LIMB_SIZE>::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            },
            output: NonNativeBigIntImpl::<N_BITS, LIMB_SIZE>::OP_PUSH_U32LESLICE(
                &sum.to_u32_digits(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_splitter::split::core::SplitType;
    use bitcoin_utils::{comparison::OP_LONGEQUALVERIFY, stack_to_script};
    use bitcoin_window_mul::{bigint::U254, traits::comparable::Comparable};

    use super::*;

    type U254AddScript = BigIntOverflowingAddScript<254>;

    #[test]
    fn test_verify() {
        assert!(U254AddScript::verify_random());
    }

    #[test]
    fn test_naive_split_correctness() {
        // Generating a random valid input for the script and the script itself
        let IOPair { input, output } = U254AddScript::generate_valid_io_pair();
        assert!(
            U254AddScript::verify(input.clone(), output.clone()),
            "input/output is not correct"
        );

        // Splitting the script into shards
        let split_result = U254AddScript::default_split(input.clone(), SplitType::ByInstructions);

        // Now, we are going to concatenate all the shards and verify that the script is also correct
        let verification_script = script! {
            { input }
            for shard in split_result.shards {
                { shard }
            }
            { output }

            // Now, we need to verify that the output is correct.
            { OP_LONGEQUALVERIFY(U254AddScript::OUTPUT_SIZE) }
            OP_TRUE
        };

        let result = execute_script(verification_script);
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_naive_split() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = U254AddScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = U254AddScript::default_split(input, SplitType::ByInstructions);

        // Checking the last state (which must be equal to the result of the multiplication)
        let last_state = split_result.must_last_state();

        // Altstack must be empty
        assert!(last_state.altstack.is_empty(), "altstack is not empty!");

        // The element of the mainstack must be equal to the actual output
        let verification_script = script! {
            { stack_to_script(&last_state.stack) }
            { output }
            { U254::OP_EQUAL(0, 1) }
        };

        let result = execute_script(verification_script);
        assert!(result.success, "verification has failed");

        // Now, we debug the total size of the states
        let total_size = split_result.total_states_size();
        println!("Total size of the states: {} bytes", total_size);
    }
}
