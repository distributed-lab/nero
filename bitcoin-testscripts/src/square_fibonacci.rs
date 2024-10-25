//! This module contains the test script
//! for performing the multiplication of two large integers
//! (exceeding standard Bitcoin 31-bit integers)

use crate::bitvm::bn254::{fp254impl::Fp254Impl, fq::Fq};
use bitcoin_splitter::split::{
    core::{form_states_from_shards, SplitType},
    script::{IOPair, SplitResult, SplitableScript},
};
use bitcoin_utils::treepp::*;

use core::ops::{Mul, Rem};
use num_bigint::{BigUint, RandomBits};
use num_traits::Num;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Script that performs the square fibonacci sequence evaluation,
/// given by recurrence relation:
/// `x[n+2] = x[n+1]**2 + x[n]**2`
pub struct SquareFibonacciScript<const STEPS: usize>;

impl<const STEPS: usize> SquareFibonacciScript<STEPS> {
    /// Given {x, y}, the script translates it to {y, x**2 + y**2}
    pub fn transition_script() -> Script {
        script! {
            { Fq::copy(0) }   // { x, y, y }
            { Fq::square() }  // { x, y, y**2 }
            { Fq::roll(2) }   // { y, y**2, x }
            { Fq::square() }  // { y, y**2, x**2 }
            { Fq::add(0, 1) } // { y, y**2 + x**2 }
        }
    }

    /// Calculates the result of the square fibonacci sequence
    pub fn calculate_result(x0: &BigUint, x1: &BigUint) -> BigUint {
        let mut x0 = x0.clone();
        let mut x1 = x1.clone();

        for _ in 0..STEPS {
            let t = x1.clone();
            x1 = square_fq(&x0) + square_fq(&x1);
            x0 = t;
        }

        x1
    }
}

impl<const STEPS: usize> SplitableScript for SquareFibonacciScript<STEPS> {
    /// Input size is double the number of limbs of U254 since we are multiplying two numbers
    const INPUT_SIZE: usize = 2 * Fq::N_LIMBS as usize;
    /// Output size is the number of limbs of U508
    const OUTPUT_SIZE: usize = Fq::N_LIMBS as usize;

    fn script() -> Script {
        script! {
            for _ in 0..STEPS {
                { SquareFibonacciScript::<STEPS>::transition_script() }
            }
            { Fq::roll(1) }
            { Fq::drop() }
        }
    }

    fn generate_valid_io_pair() -> IOPair {
        // Generating random Fq elements --- first two elements in the sequence
        let x0 = generate_random_fq();
        let x1 = generate_random_fq();

        // Finding the product of two field elements
        let result = Self::calculate_result(&x0, &x1);

        IOPair {
            input: script! {
                { Fq::push_u32_le(&x0.to_u32_digits()) }
                { Fq::push_u32_le(&x1.to_u32_digits()) }
            },
            output: Fq::push_u32_le(&result.to_u32_digits()),
        }
    }

    fn generate_invalid_io_pair() -> IOPair {
        // We will simply generate three random values to make the script invalid
        let x0 = generate_random_fq();
        let x1 = generate_random_fq();
        let x2 = generate_random_fq();

        IOPair {
            input: script! {
                { Fq::push_u32_le(&x0.to_u32_digits()) }
                { Fq::push_u32_le(&x1.to_u32_digits()) }
            },
            output: Fq::push_u32_le(&x2.to_u32_digits()),
        }
    }

    fn default_split(input: Script, _split_type: SplitType) -> SplitResult {
        // First, form shards
        let mut shards = vec![Self::transition_script(); STEPS + 1];
        // Change last one to be { OP_ROLL, OP_DROP } to remove the element before last.
        if let Some(last) = shards.last_mut() {
            *last = script! {
                { Fq::roll(1) }
                { Fq::drop() }
            }
        }

        // Secondly, form the intermediate states and return
        let intermediate_states = form_states_from_shards(shards.clone(), input);
        SplitResult {
            shards,
            intermediate_states,
        }
    }
}

/// Generates a random Fq element
pub(super) fn generate_random_fq() -> BigUint {
    // Preparing modulus and random generator
    let modulus = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
    let mut prng = ChaCha20Rng::seed_from_u64(0);

    let x: BigUint = prng.sample(RandomBits::new(254));
    x.rem(&modulus)
}

/// Multiplies two Fq elements (by operating over [`BigUint`])
pub(super) fn mul_fq(x: &BigUint, y: &BigUint) -> BigUint {
    let modulus = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();
    x.mul(y).rem(&modulus)
}

/// Squares the given Fq element
pub(super) fn square_fq(x: &BigUint) -> BigUint {
    mul_fq(x, x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_splitter::split::core::SplitType;
    use bitcoin_utils::{comparison::OP_LONGEQUALVERIFY, stack_to_script};

    #[test]
    fn test_verify() {
        const STEPS: usize = 32;
        println!(
            "Square Fibonacci Sequence is {} bytes in size",
            SquareFibonacciScript::<STEPS>::script().len()
        );
        assert!(SquareFibonacciScript::<STEPS>::verify_random());
    }

    #[test]
    fn test_transition_function() {
        let modulus = BigUint::from_str_radix(Fq::MODULUS, 16).unwrap();

        // Generate random (x0, x1)
        let x0 = generate_random_fq();
        let x1 = generate_random_fq();
        let x2 = x0.clone().mul(x0.clone()) + x1.clone().mul(x1.clone()).rem(modulus);

        // Construct the script
        let script = script! {
            { Fq::push_u32_le(&x0.to_u32_digits()) }
            { Fq::push_u32_le(&x1.to_u32_digits()) }
            { SquareFibonacciScript::<1024>::transition_script() }
            { Fq::push_u32_le(&x2.to_u32_digits()) }
            { Fq::equalverify(0, 1) }
            { Fq::push_u32_le(&x1.to_u32_digits()) }
            { Fq::equal(0, 1) }
        };

        let result = execute_script(script);
        assert!(result.success, "transition function failed");
    }

    #[test]
    fn test_naive_split_correctness() {
        // Generating a random valid input for the script and the script itself
        let IOPair { input, output } = SquareFibonacciScript::<16>::generate_valid_io_pair();
        assert!(
            SquareFibonacciScript::<16>::verify(input.clone(), output.clone()),
            "input/output is not correct"
        );
        println!("Script itself is correct!");

        // Splitting the script into shards
        let split_result =
            SquareFibonacciScript::<16>::default_split(input.clone(), SplitType::ByInstructions);

        // Now, we are going to concatenate all the shards and verify that the script is also correct
        let verification_script = script! {
            { input }
            for shard in split_result.shards {
                { shard }
            }
            { output }

            { OP_LONGEQUALVERIFY(SquareFibonacciScript::<16>::OUTPUT_SIZE) }
            OP_TRUE
        };

        let result = execute_script(verification_script);
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_naive_split() {
        type FibonacciScript = SquareFibonacciScript<128>;
        println!(
            "Square Fibonacci Sequence is {} bytes in size",
            FibonacciScript::script().len()
        );

        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = FibonacciScript::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = FibonacciScript::default_split(input, SplitType::ByInstructions);

        for i in 0..split_result.len() {
            let shard_size = split_result.shards[i].len();
            let stack_size = split_result.intermediate_states[i].stack.len();
            println!(
                "Shard {:?}: length is {:?}, stack size is {:?}",
                i, shard_size, stack_size
            );
        }

        // Checking the last state (which must be equal to the result of the multiplication)
        let last_state = split_result.must_last_state();

        // Altstack must be empty
        assert!(last_state.altstack.is_empty(), "altstack is not empty!");

        // The element of the mainstack must be equal to the actual output
        let verification_script = script! {
            { stack_to_script(&last_state.stack) }
            { output }
            { Fq::equal(0, 1) }
        };

        let result = execute_script(verification_script);
        assert!(result.success, "verification has failed");
    }

    #[test]
    #[ignore = "too-large computation, run separately"]
    fn test_fuzzy_split() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = SquareFibonacciScript::<1024>::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result =
            SquareFibonacciScript::<1024>::fuzzy_split(input, SplitType::ByInstructions);

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
            { Fq::equal(0, 1) }
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
