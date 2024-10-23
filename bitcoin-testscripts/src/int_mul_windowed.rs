//! This module contains the test script
//! for performing the multiplication of two large integers
//! (exceeding standard Bitcoin 31-bit integers)

use bitcoin_splitter::split::script::{IOPair, SplitableScript};
use bitcoin_utils::treepp::*;
use bitcoin_window_mul::{
    bigint::{U254Windowed, U508},
    traits::integer::{NonNativeInteger, NonNativeLimbInteger},
};

use num_bigint::{BigUint, RandomBits};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Script that performs the addition of two 254-bit numbers
pub struct U254MulScript;

/// Input size is double the number of limbs of U254 since we are multiplying two numbers
const INPUT_SIZE: usize = 2 * U254Windowed::N_LIMBS;
/// Output size is the number of limbs of U508
const OUTPUT_SIZE: usize = U508::N_LIMBS;

impl SplitableScript for U254MulScript {
    const INPUT_SIZE: usize = INPUT_SIZE;
    const OUTPUT_SIZE: usize = OUTPUT_SIZE;

    fn script() -> Script {
        U254Windowed::OP_WIDENINGMUL::<U508>()
    }

    fn generate_valid_io_pair() -> IOPair {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // Generate two random 254-bit numbers and calculate their sum
        let num_1: BigUint = prng.sample(RandomBits::new(254));
        let num_2: BigUint = prng.sample(RandomBits::new(254));
        let product: BigUint = num_1.clone() * num_2.clone();

        IOPair {
            input: script! {
                { U254Windowed::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
                { U254Windowed::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            },
            output: U508::OP_PUSH_U32LESLICE(&product.to_u32_digits()),
        }
    }

    fn generate_invalid_io_pair() -> IOPair {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // Generate two random 254-bit numbers and calculate their sum
        let num_1: BigUint = prng.sample(RandomBits::new(254));
        let num_2: BigUint = prng.sample(RandomBits::new(254));
        let mut product: BigUint = num_1.clone() * num_2.clone();

        // Flip a random bit in the product
        let bit_to_flip = prng.gen_range(0..product.bits());
        product.set_bit(bit_to_flip, !product.bit(bit_to_flip));

        IOPair {
            input: script! {
                { U254Windowed::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
                { U254Windowed::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            },
            output: U508::OP_PUSH_U32LESLICE(&product.to_u32_digits()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_splitter::split::core::SplitType;
    use bitcoin_utils::{comparison::OP_LONGEQUALVERIFY, stack_to_script};
    use bitcoin_window_mul::traits::comparable::Comparable;

    #[test]
    fn test_verify() {
        assert!(U254MulScript::verify_random());
    }

    #[test]
    fn test_invalid_generate() {
        let IOPair { input, output } = U254MulScript::generate_invalid_io_pair();
        assert!(
            !U254MulScript::verify(input.clone(), output.clone()),
            "input/output is correct"
        );
    }

    #[test]
    fn test_naive_split_correctness() {
        // Generating a random valid input for the script and the script itself
        let IOPair { input, output } = U254MulScript::generate_valid_io_pair();
        assert!(
            U254MulScript::verify(input.clone(), output.clone()),
            "input/output is not correct"
        );

        // Splitting the script into shards
        let split_result = U254MulScript::default_split(input.clone(), SplitType::ByInstructions);

        // Now, we are going to concatenate all the shards and verify that the script is also correct
        let verification_script = script! {
            { input }
            for shard in split_result.shards {
                { shard }
            }
            { output }

            // Now, we need to verify that the output is correct.
            { OP_LONGEQUALVERIFY(U254MulScript::OUTPUT_SIZE) }
            OP_TRUE
        };

        let result = execute_script(verification_script);
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_naive_split() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = U254MulScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = U254MulScript::default_split(input, SplitType::ByInstructions);

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
            { U508::OP_EQUAL(0, 1) }
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
    fn test_split_each_shard() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output: _ } = U254MulScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = U254MulScript::default_split(input.clone(), SplitType::ByInstructions);

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
        let IOPair { input, output: _ } = U254MulScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = U254MulScript::default_split(input.clone(), SplitType::ByInstructions);

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

    #[test]
    #[ignore = "too-large computation, run separately"]
    fn test_fuzzy_split() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = U254MulScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = U254MulScript::fuzzy_split(input, SplitType::ByInstructions);

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
            { U508::OP_EQUAL(0, 1) }
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
}
