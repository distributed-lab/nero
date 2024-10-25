//! This module contains the test script
//! for performing the multiplication of two large integers
//! (exceeding standard Bitcoin 31-bit integers)

use bitcoin_splitter::split::{core::{form_states_from_shards, SplitType}, script::{IOPair, SplitResult, SplitableScript}};
use bitcoin_utils::{pseudo::OP_2k_MUL, treepp::*};
use bitcoin_window_mul::{
    bigint::{window::{binary_to_windowed_form, precompute::WindowedPrecomputeTable, NonNativeWindowedBigIntImpl}, U254Windowed, U254, U508},
    traits::{arithmeticable::Arithmeticable, bitable::Bitable, integer::{NonNativeInteger, NonNativeLimbInteger}, window::Windowable},
};

use num_bigint::{BigUint, RandomBits};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Script that performs the multiplication of
/// two N-bit numbers.
pub struct FriendlyU254MulScript<const W: usize>;

#[allow(non_snake_case)]
impl<const W: usize> FriendlyU254MulScript<W> {
    /// The size of the decomposition
    const DECOMPOSITION_SIZE: usize = usize::div_ceil(U254::N_BITS, W);

    /// Recovery chunk size that is used to restore the original number
    const RECOVERY_CHUNK_SIZE: usize = U254::LIMB_SIZE / W;

    /// Given a chunk `l[0],l[1],...,l[n-1]`, it outputs
    /// a limb $l = \sum_{i=0}^{n-1} l[i]*2^(W*i)$.
    pub fn convert_chunk_to_limb(chunk_size: usize) -> Script {
        script! {
            for i in 0..chunk_size {
                // Multiplying by 2^(i*W)
                { OP_2k_MUL(i*W) }
                OP_TOALTSTACK
            }

            OP_FROMALTSTACK
            // Adding remaining limbs together
            for _ in 0..chunk_size-1 {
                OP_FROMALTSTACK
                OP_ADD
            }
        }
    }

    /// Restores the original number from the w-width form which lies
    /// in the altstack.
    pub fn recover_from_width_decomposition() -> Script {
        assert_eq!(U254::LIMB_SIZE % W, 0, "N_LIMBS must be divisible by W, but tried to divide {:?} by {:?}", U254::N_LIMBS, W);

        script! {
            // Reverse the decomposition
            for i in (0..Self::DECOMPOSITION_SIZE).rev() {
                { i } OP_ROLL OP_TOALTSTACK
            }
            for _ in 0..Self::DECOMPOSITION_SIZE {
                OP_FROMALTSTACK
            }

            for i in 0..U254::N_LIMBS {
                // Convering the batch of decomposition limbs to the regular limb
                if i != U254::N_LIMBS - 1 {
                    { Self::convert_chunk_to_limb(Self::RECOVERY_CHUNK_SIZE) }
                } else {
                    { Self::convert_chunk_to_limb(Self::DECOMPOSITION_SIZE % Self::RECOVERY_CHUNK_SIZE) }
                }

                // Pushing the limb to the altstack
                OP_TOALTSTACK
            }

            // Picking all the limbs from the altstack
            for _ in 0..U254::N_LIMBS {
                OP_FROMALTSTACK
            }
        }
    }

    /// Given { y_decomposition } { lookup_table } { r }, it converts it to
    /// { y } { x } { r }
    pub fn compress_step() -> Script {
        script!{
            { U508::OP_TOALTSTACK() } // { y_decomposition } { lookup_table }
            for _ in 0..(1<<W)-2 {
                { U508::OP_DROP() } 
            } 
            // At this point, we have { y_decomposition } { 0 } { x }
            { U508::OP_SWAP() } // { y_decomposition } { x } { 0 }
            { U508::OP_DROP() } // { y_decomposition } { x }
            for i in 0..U508::N_LIMBS-U254::N_LIMBS {
                { U508::N_LIMBS - i - 1 } OP_ROLL OP_DROP
            }
            { U254::OP_TOALTSTACK() } // { y_decomposition } U254
            { Self::recover_from_width_decomposition() } // { y }
            { U254::OP_FROMALTSTACK() } // { y } { x }
            { U508::OP_FROMALTSTACK() } // { y } { x } { r }
        }
    }

    /// Given { y } { x } { r }, it converts it to
    /// { y } { x } { r }
    pub fn decompress_step() -> Script {
        script!{
            { U508::OP_TOALTSTACK() } // { y } { x }
            { U254::OP_EXTEND::<U508>() }
            { U508::OP_TOALTSTACK() } // { y }
            { U254::OP_TOBEBITS_TOALTSTACK() }
            { binary_to_windowed_form::<W>(U254::N_BITS) } // { y_decomposition }
            { U508::OP_FROMALTSTACK() } // { y_decomposition } { x }
            { WindowedPrecomputeTable::<U508, W, false>::initialize() } // { y_decomposition } { lookup_table }
            { U508::OP_FROMALTSTACK() } // { y_decomposition } { lookup_table } { r }
        }
    }
}

impl<const W: usize> SplitableScript for FriendlyU254MulScript<W> {
    /// Input is simply two 254-bit numbers
    const INPUT_SIZE: usize = 2 * U254::N_LIMBS;

    /// Output is a 508-bit number
    const OUTPUT_SIZE: usize = U508::N_LIMBS;

    fn script() -> Script {
        script! {
            // Convert to w-width form. This way, our stack looks like
            // { x } { y_decomposition }
            { U254::OP_TOBEBITS_TOALTSTACK() }
            { binary_to_windowed_form::<W>(U254::N_BITS) }
            
            // Picking { x } to the top to get
            // { y_decomposition } { x }
            for _ in (0..U254::N_LIMBS).rev() {
                { Self::DECOMPOSITION_SIZE + U254::N_LIMBS - 1 } OP_ROLL
            }

            // Extend to larger integer to get
            // { y_decomposition } { x_extended }
            { U254::OP_EXTEND::<U508>() }

            // Precomputing {0*z, 1*z, ..., ((1<<WIDTH)-1)*z} to get
            // { y_decomposition } { lookup_table }
            { WindowedPrecomputeTable::<U508, W, false>::initialize() }

            // We initialize the result
            // Note that we can simply pick the precomputed value
            // since 0*16 is still 0, so we omit the doubling :)
            { (1<<W) * U508::N_LIMBS } OP_PICK 1 OP_ADD
            { 1<<W }
            OP_SWAP
            OP_SUB
            { U508::OP_PICKSTACK() }

            // At this point, our stack looks as follows:
            // { y_decomposition } { lookup_table } { r }

            // Dropping stage
            { Self::compress_step() }

            for i in 1..Self::DECOMPOSITION_SIZE {
                { Self::decompress_step() }

                // Double the result WIDTH times
                for _ in 0..W {
                    { U508::OP_2MUL_NOOVERFLOW(0) }
                }

                // Picking di from the stack
                { ((1<<W) + 1) * U508::N_LIMBS + i } OP_PICK

                // Add the precomputed value to the result.
                // Since currently stack looks like:
                // {0*z, 1*z, ..., ((1<<WIDTH)-1)*z, r, di} with
                // r being the result, we need to copy
                // (1<<WIDTH - di)th element to the top of the stack.
                { 1<<W }
                OP_SWAP
                OP_SUB
                { U508::OP_PICKSTACK() }
                { U508::OP_ADD_NOOVERFLOW(0, 1) }

                { Self::compress_step() }
            }

            // Clearing the precomputed values from the stack.
            { U508::OP_TOALTSTACK() }
            { U254::OP_DROP() }
            { U254::OP_DROP() }
            { U508::OP_FROMALTSTACK() }
        }
    }

    fn generate_valid_io_pair() -> IOPair {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // Generate two random 254-bit numbers and calculate their sum
        let num_1: BigUint = prng.sample(RandomBits::new(U254Windowed::N_BITS as u64));
        let num_2: BigUint = prng.sample(RandomBits::new(U254Windowed::N_BITS as u64));
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
        let num_1: BigUint = prng.sample(RandomBits::new(U254Windowed::N_BITS as u64));
        let num_2: BigUint = prng.sample(RandomBits::new(U254Windowed::N_BITS as u64));
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

    fn default_split(input: Script, _split_type: SplitType) -> SplitResult {
        // First, we need to form the script
        let mut shards: Vec<Script> = vec![];
        shards.push(script!{
            // Convert to w-width form. This way, our stack looks like
            // { x } { y_decomposition }
            { U254::OP_TOBEBITS_TOALTSTACK() }
            { binary_to_windowed_form::<W>(U254::N_BITS) }
            
            // Picking { x } to the top to get
            // { y_decomposition } { x }
            for _ in (0..U254::N_LIMBS).rev() {
                { Self::DECOMPOSITION_SIZE + U254::N_LIMBS - 1 } OP_ROLL
            }

            // Extend to larger integer to get
            // { y_decomposition } { x_extended }
            { U254::OP_EXTEND::<U508>() }

            // Precomputing {0*z, 1*z, ..., ((1<<WIDTH)-1)*z} to get
            // { y_decomposition } { lookup_table }
            { WindowedPrecomputeTable::<U508, W, false>::initialize() }

            // We initialize the result
            // Note that we can simply pick the precomputed value
            // since 0*16 is still 0, so we omit the doubling :)
            { (1<<W) * U508::N_LIMBS } OP_PICK 1 OP_ADD
            { 1<<W }
            OP_SWAP
            OP_SUB
            { U508::OP_PICKSTACK() }

            // At this point, our stack looks as follows:
            // { y_decomposition } { lookup_table } { r }

            // Dropping stage
            { Self::compress_step() }
        });

        for i in 1..Self::DECOMPOSITION_SIZE {
            shards.push(script!{
                { Self::decompress_step() }

                // Double the result WIDTH times
                for _ in 0..W {
                    { U508::OP_2MUL_NOOVERFLOW(0) }
                }

                // Picking di from the stack
                { ((1<<W) + 1) * U508::N_LIMBS + i } OP_PICK

                // Add the precomputed value to the result.
                // Since currently stack looks like:
                // {0*z, 1*z, ..., ((1<<WIDTH)-1)*z, r, di} with
                // r being the result, we need to copy
                // (1<<WIDTH - di)th element to the top of the stack.
                { 1<<W }
                OP_SWAP
                OP_SUB
                { U508::OP_PICKSTACK() }
                { U508::OP_ADD_NOOVERFLOW(0, 1) }

                { Self::compress_step() }
            })
        }

        shards.push(script! {
            // Clearing the precomputed values from the stack.
            { U508::OP_TOALTSTACK() }
            { U254::OP_DROP() }
            { U254::OP_DROP() }
            { U508::OP_FROMALTSTACK() }
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
    use bitcoin_window_mul::traits::comparable::Comparable;
    
    #[test]
    fn debug() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let num_1: BigUint = prng.sample(RandomBits::new(U254Windowed::N_BITS as u64));
        let num_2: BigUint = prng.sample(RandomBits::new(U254Windowed::N_BITS as u64));
        let product: BigUint = num_1.clone() * num_2.clone();

        let script = script! {
            { U254Windowed::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
            { U254Windowed::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            { FriendlyU254MulScript::<3>::script() }
            { FriendlyU254MulScript::<3>::decompress_step() }
            // for _ in 0..FriendlyU254MulScript::<3> {
            //     OP_DROP
            // }
            OP_TRUE
            // { U254Windowed::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
            // { U254Windowed::OP_EQUAL(0, 1) }
            // { U508::OP_PUSH_U32LESLICE(&product.to_u32_digits()) }
            // { U508::OP_EQUAL(0, 1) }
        };

        let result = execute_script(script);
        println!("{:?}", stack_to_script(&result.main_stack).to_asm_string());
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_compress_decompress() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let x: BigUint = prng.sample(RandomBits::new(U254Windowed::N_BITS as u64));
    
        let verification_script = script! {
            { U254::OP_PUSH_U32LESLICE(&x.to_u32_digits()) }
            { U254::OP_EXTEND::<U508>() }
            for i in 0..U508::N_LIMBS-U254::N_LIMBS {
                { U508::N_LIMBS - i - 1 } OP_ROLL OP_DROP
            }
            { U254::OP_PUSH_U32LESLICE(&x.to_u32_digits()) }
            { U254::OP_EQUAL(1, 0) }
        };

        let result = execute_script(verification_script);
        println!("{:?}", stack_to_script(&result.main_stack).to_asm_string());
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_verify() {
        assert!(FriendlyU254MulScript::<3>::verify_random());
    }

    #[test]
    fn test_chunk_to_limb() {
        const DECOMPOSITION: [u32; 10] = [2, 4, 2, 6, 3, 4, 1, 3, 4, 1];

        assert_eq!(DECOMPOSITION.len(), FriendlyU254MulScript::<3>::RECOVERY_CHUNK_SIZE, "Invalid decomposition size");

        let verification_script = script! {
            for element in DECOMPOSITION.into_iter() {
                { element }
            }
            { FriendlyU254MulScript::<3>::convert_chunk_to_limb(DECOMPOSITION.len()) }
            { 208026786 }
            OP_EQUAL
        };

        let result = execute_script(verification_script);
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_recovery() {
        const WINDOW_SIZE: usize = 2;

        // Picking a random integer
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let x: BigUint = prng.sample(RandomBits::new(U254Windowed::N_BITS as u64));

        // In the verification script, we do the following:
        // 1. Push x to the stack
        // 2. Convert x to the windowed form
        // 3. Convert the windowed form to the limb form
        // 4. Verify that the result is equal to x
        let verification_script = script! {
            { U254::OP_PUSH_U32LESLICE(&x.to_u32_digits()) }
            { U254::OP_PICK(0) }
            { U254::OP_TOBEBITS_TOALTSTACK() }
            { binary_to_windowed_form::<WINDOW_SIZE>(U254::N_BITS) }
            { FriendlyU254MulScript::<WINDOW_SIZE>::recover_from_width_decomposition() }
            { U254::OP_EQUAL(0, 1) }
        };

        let result = execute_script(verification_script);
        println!("{:?}", stack_to_script(&result.main_stack).to_asm_string());
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_invalid_generate() {
        let IOPair { input, output } = FriendlyU254MulScript::<4>::generate_invalid_io_pair();
        assert!(
            !FriendlyU254MulScript::<2>::verify(input.clone(), output.clone()),
            "input/output is correct"
        );
    }

    #[test]
    fn test_naive_split_correctness() {
        // Generating a random valid input for the script and the script itself
        let IOPair { input, output } = FriendlyU254MulScript::<3>::generate_valid_io_pair();
        assert!(
            FriendlyU254MulScript::<3>::verify(input.clone(), output.clone()),
            "input/output is not correct"
        );

        // Splitting the script into shards
        let split_result = FriendlyU254MulScript::<3>::default_split(input.clone(), SplitType::ByInstructions);

        // Now, we are going to concatenate all the shards and verify that the script is also correct
        let verification_script = script! {
            { input }
            for shard in split_result.shards {
                { shard }
            }
            { output }

            // Now, we need to verify that the output is correct.
            { OP_LONGEQUALVERIFY(FriendlyU254MulScript::<3>::OUTPUT_SIZE) }
            OP_TRUE
        };

        let result = execute_script(verification_script);
        assert!(result.success, "Verification has failed");
    }

    #[test]
    fn test_naive_split() {
        const WIDTH_SIZE: usize = 2;

        // First, we generate the pair of input and output scripts
        let IOPair { input, output } = FriendlyU254MulScript::<WIDTH_SIZE>::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = FriendlyU254MulScript::<WIDTH_SIZE>::default_split(input, SplitType::ByInstructions);

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
        let IOPair { input, output: _ } = FriendlyU254MulScript::<4>::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = FriendlyU254MulScript::<4>::default_split(input.clone(), SplitType::ByInstructions);

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
        let IOPair { input, output: _ } = FriendlyU254MulScript::<4>::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = FriendlyU254MulScript::<4>::default_split(input.clone(), SplitType::ByInstructions);

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
        let IOPair { input, output } = FriendlyU254MulScript::<4>::generate_valid_io_pair();

        // Splitting the script into shards
        let split_result = FriendlyU254MulScript::<4>::fuzzy_split(input, SplitType::ByInstructions);

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
