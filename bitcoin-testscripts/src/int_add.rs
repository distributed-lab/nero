//! This module contains the test script
//! for performing the addition of two large integers
//! (exceeding standard Bitcoin 31-bit integers)

use bitcoin_splitter::split::script::{IOPair, SplitableScript};
use bitcoin_utils::treepp::*;
use bitcoin_window_mul::{
    bigint::U254,
    traits::{
        arithmeticable::Arithmeticable,
        integer::{NonNativeInteger, NonNativeLimbInteger},
    },
};

use core::ops::{Rem, Shl};
use num_bigint::{BigUint, RandomBits};
use num_traits::One;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Script that performs the addition of two 254-bit numbers
pub struct U254AddScript;

impl SplitableScript for U254AddScript {
    /// Input size is double the number of limbs of U254 since we are adding two numbers
    const INPUT_SIZE: usize = 2 * U254::N_LIMBS;
    /// Output size is the number of limbs of U254
    const OUTPUT_SIZE: usize = U254::N_LIMBS;

    fn script() -> Script {
        U254::OP_ADD(1, 0)
    }

    fn generate_valid_io_pair() -> IOPair {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // Generate two random 254-bit numbers and calculate their sum
        let num_1: BigUint = prng.sample(RandomBits::new(254));
        let num_2: BigUint = prng.sample(RandomBits::new(254));
        let sum: BigUint = (num_1.clone() + num_2.clone()).rem(BigUint::one().shl(254));

        IOPair {
            input: script! {
                { U254::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
                { U254::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            },
            output: U254::OP_PUSH_U32LESLICE(&sum.to_u32_digits()),
        }
    }

    fn generate_invalid_io_pair() -> IOPair {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // Generate two random 254-bit numbers and calculate their sum
        let num_1: BigUint = prng.sample(RandomBits::new(254));
        let num_2: BigUint = prng.sample(RandomBits::new(254));
        let mut sum: BigUint = (num_1.clone() + num_2.clone()).rem(BigUint::one().shl(254));

        // Flip a random bit in the sum
        let bit_to_flip = prng.gen_range(0..sum.bits());
        sum.set_bit(bit_to_flip, !sum.bit(bit_to_flip));

        IOPair {
            input: script! {
                { U254::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
                { U254::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            },
            output: U254::OP_PUSH_U32LESLICE(&sum.to_u32_digits()),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_splitter::split::core::SplitType;
    use bitcoin_window_mul::traits::comparable::Comparable;

    use bitcoin_utils::{comparison::OP_LONGEQUALVERIFY, stack_to_script};

    use super::*;

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
