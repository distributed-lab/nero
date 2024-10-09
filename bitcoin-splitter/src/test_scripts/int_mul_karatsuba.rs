//! This module contains the test script
//! for performing the multiplication of two large integers
//! (exceeding standard Bitcoin 31-bit integers)

use crate::{
    split::script::{IOPair, SplitableScript},
    treepp::*,
};
use bitcoin_window_mul::{
    bigint::{arithmetics::u29x9::u29x9_mul_karazuba, implementation::NonNativeBigIntImpl},
    traits::integer::{NonNativeInteger, NonNativeLimbInteger},
};

use num_bigint::{BigUint, RandomBits};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub type U261 = NonNativeBigIntImpl<261, 29>;
pub type U522 = NonNativeBigIntImpl<522, 29>;

/// Script that performs the addition of two 255-bit numbers
pub struct U261MulKaratsubaScript;

/// Input size is double the number of limbs of U254 since we are multiplying two numbers
const INPUT_SIZE: usize = 2 * U261::N_LIMBS;
/// Output size is the number of limbs of U508
const OUTPUT_SIZE: usize = U522::N_LIMBS;

impl SplitableScript<{ INPUT_SIZE }, { OUTPUT_SIZE }> for U261MulKaratsubaScript {
    fn script() -> Script {
        u29x9_mul_karazuba(0, 1)
    }

    fn generate_valid_io_pair() -> IOPair<{ INPUT_SIZE }, { OUTPUT_SIZE }> {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // Generate two random 254-bit numbers and calculate their sum
        let num_1: BigUint = prng.sample(RandomBits::new(254));
        let num_2: BigUint = prng.sample(RandomBits::new(254));
        let product: BigUint = num_1.clone() * num_2.clone();

        IOPair {
            input: script! {
                { U261::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
                { U261::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            },
            output: U522::OP_PUSH_U32LESLICE(&product.to_u32_digits()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{split::core::SplitType, utils::stack_to_script};
    use bitcoin_window_mul::traits::comparable::Comparable;

    #[test]
    fn test_verify() {
        assert!(U261MulKaratsubaScript::verify_random());
    }

    #[test]
    fn test_naive_split_correctness() {
        // Generating a random valid input for the script and the script itself
        let IOPair { input, output } = U261MulKaratsubaScript::generate_valid_io_pair();
        assert!(
            U261MulKaratsubaScript::verify(input.clone(), output.clone()),
            "input/output is not correct"
        );

        // Splitting the script into shards
        let split_result =
            U261MulKaratsubaScript::default_split(input.clone(), SplitType::ByInstructions);

        // Now, we are going to concatenate all the shards and verify that the script is also correct
        let verification_script = script! {
            { input }
            for shard in split_result.shards {
                { shard }
            }
            { output }

            // Now, we need to verify that the output is correct.
            for i in (0..U261MulKaratsubaScript::OUTPUT_SIZE).rev() {
                // { <a_1> <a_2> ... <a_n> <b_1> <b_2> ... <b_n> } <- we need to push element <a_n> to the top of the stack
                { i+1 } OP_ROLL
                OP_EQUALVERIFY
            }

            OP_TRUE
        };

        let result = execute_script(verification_script);
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_naive_split() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = U261MulKaratsubaScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = U261MulKaratsubaScript::default_split(input, SplitType::ByInstructions);

        for shard in split_result.shards.iter() {
            println!("Shard: {:?}", shard.len());
        }

        // Debugging the split result
        println!("Split result: {:?}", split_result);

        // Checking the last state (which must be equal to the result of the multiplication)
        let last_state = split_result.must_last_state();

        // Altstack must be empty
        assert!(last_state.altstack.is_empty(), "altstack is not empty!");

        // The element of the mainstack must be equal to the actual output
        let verification_script = script! {
            { stack_to_script(&last_state.stack) }
            { output }
            { U522::OP_EQUAL(0, 1) }
        };

        let result = execute_script(verification_script);
        assert!(result.success, "verification has failed");

        // Printing
        for (i, state) in split_result.intermediate_states.iter().enumerate() {
            println!(
                "Intermediate state #{}: {:?}",
                i,
                state.stack.len() + state.altstack.len()
            );
        }

        // Now, we debug the total size of the states
        let total_size = split_result.total_states_size();
        println!("Total size of the states: {} bytes", total_size);
    }

    #[test]
    #[ignore = "too-large computation, run separately"]
    fn test_fuzzy_split() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = U261MulKaratsubaScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = U261MulKaratsubaScript::fuzzy_split(input, SplitType::ByInstructions);

        for shard in split_result.shards.iter() {
            println!("Shard: {:?}", shard.len());
        }

        // Debugging the split result
        println!("Split result: {:?}", split_result);

        // Checking the last state (which must be equal to the result of the multiplication)
        let last_state = split_result.must_last_state();

        // Altstack must be empty
        assert!(last_state.altstack.is_empty(), "altstack is not empty!");

        // The element of the mainstack must be equal to the actual output
        let verification_script = script! {
            { stack_to_script(&last_state.stack) }
            { output }
            { U522::OP_EQUAL(0, 1) }
        };

        let result = execute_script(verification_script);
        assert!(result.success, "verification has failed");

        // Printing
        for (i, state) in split_result.intermediate_states.iter().enumerate() {
            println!(
                "Intermediate state #{}: {:?}",
                i,
                state.stack.len() + state.altstack.len()
            );
        }

        // Now, we debug the total size of the states
        let total_size = split_result.total_states_size();
        println!("Total size of the states: {} bytes", total_size);
    }

    #[test]
    #[ignore = "wip"]
    fn test_to_u32_conversion() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = U261MulKaratsubaScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = U261MulKaratsubaScript::default_split(input, SplitType::ByInstructions);

        // Debugging the split result
        println!("Split result: {:?}", split_result);

        // Now, verifying tha the split is correct (meaning, the last state is equal to the output)
        let last_state = split_result.must_last_state();

        // Altstack must be empty
        assert!(last_state.altstack.is_empty(), "altstack is not empty!");

        // The element of the mainstack must be equal to the actual output
        let verification_script = script! {
            { stack_to_script(&last_state.stack) }
            { output }
            { U522::OP_EQUAL(0, 1) }
        };

        let result = execute_script(verification_script);
        assert!(result.success, "verification has failed");

        // Now, let us debug each of the intermediate states
        for (i, state) in split_result.intermediate_states.iter().enumerate() {
            let state_as_bytes = state.stack.clone().serialize_to_bytes();

            println!("Intermediate state #{}: {:?}", i, state);
            println!("Intermediate state as bytes #{}: {:?}", i, state_as_bytes);
            // println!("Intermediate state as u32 array #{}: {:?}", i, Stack::from_u8_vec(state_as_bytes));
        }
    }
}
