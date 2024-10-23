// //! This module contains the test script
// //! for performing the multiplication of two large integers
// //! (exceeding standard Bitcoin 31-bit integers)

// use bitcoin_splitter::split::script::{IOPair, SplitableScript};
// use bitcoin_utils::treepp::*;
// use bitcoin_window_mul::{
//     bigint::{implementation::NonNativeBigIntImpl, U254Windowed, U508},
//     traits::{integer::{NonNativeInteger, NonNativeLimbInteger}, window::Windowable},
// };

// use num_bigint::{BigUint, RandomBits};
// use rand::{Rng, SeedableRng};
// use rand_chacha::ChaCha20Rng;

// /// Script that performs the multiplication of
// /// two N-bit numbers.
// pub struct FriendlyBigIntMulScript<const N_BITS: usize, const LIMB_SIZE: usize>;

// impl<const N_BITS: usize, const N_LIMBS: usize, const WIDE_N_LIMBS: usize> FriendlyBigIntMulScript<N_BITS, N_LIMBS, WIDE_N_LIMBS> {

// }

// impl<const N_BITS: usize, const N_LIMBS: usize, const WIDE_N_LIMBS: usize> SplitableScript<{N_LIMBS}, {WIDE_N_LIMBS}> for FriendlyBigIntMulScript<N_BITS, N_LIMBS, WIDE_N_LIMBS> {
//     fn script() -> Script {
//         script! {
//             // Convert to w-width form.
//             { <Self as Windowable>::OP_TOBEWINDOWEDFORM_TOALTSTACK() }

//             // Precomputing {0*z, 1*z, ..., ((1<<WIDTH)-1)*z}
//             { WindowedPrecomputeTable::<T, WIDTH, false>::initialize() }

//             // We initialize the result
//             // Note that we can simply pick the precomputed value
//             // since 0*16 is still 0, so we omit the doubling :)
//             OP_FROMALTSTACK 1 OP_ADD
//             { 1<<WIDTH }
//             OP_SWAP
//             OP_SUB
//             { T::OP_PICKSTACK() }

//             for _ in 1..Self::DECOMPOSITION_SIZE {
//                 // Double the result WIDTH times
//                 for _ in 0..WIDTH {
//                     { T::OP_2MUL(0) }
//                 }

//                 // Picking di from the stack
//                 OP_FROMALTSTACK

//                 // Add the precomputed value to the result.
//                 // Since currently stack looks like:
//                 // {0*z, 1*z, ..., ((1<<WIDTH)-1)*z, r, di} with
//                 // r being the result, we need to copy
//                 // (1<<WIDTH - di)th element to the top of the stack.
//                 { 1<<WIDTH }
//                 OP_SWAP
//                 OP_SUB
//                 { T::OP_PICKSTACK() }
//                 { T::OP_ADD(0, 1) }
//             }

//             // Clearing the precomputed values from the stack.
//             { T::OP_TOALTSTACK() }
//             for _ in 0..1<<WIDTH {
//                 { T::OP_DROP() }
//             }
//             { T::OP_FROMALTSTACK() }
//         }
//     }

//     fn generate_valid_io_pair() -> IOPair<{ INPUT_SIZE }, { OUTPUT_SIZE }> {
//         let mut prng = ChaCha20Rng::seed_from_u64(0);

//         // Generate two random 254-bit numbers and calculate their sum
//         let num_1: BigUint = prng.sample(RandomBits::new(254));
//         let num_2: BigUint = prng.sample(RandomBits::new(254));
//         let product: BigUint = num_1.clone() * num_2.clone();

//         IOPair {
//             input: script! {
//                 { U254Windowed::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
//                 { U254Windowed::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
//             },
//             output: U508::OP_PUSH_U32LESLICE(&product.to_u32_digits()),
//         }
//     }

//     fn generate_invalid_io_pair() -> IOPair<{ INPUT_SIZE }, { OUTPUT_SIZE }> {
//         let mut prng = ChaCha20Rng::seed_from_u64(0);

//         // Generate two random 254-bit numbers and calculate their sum
//         let num_1: BigUint = prng.sample(RandomBits::new(254));
//         let num_2: BigUint = prng.sample(RandomBits::new(254));
//         let mut product: BigUint = num_1.clone() * num_2.clone();

//         // Flip a random bit in the product
//         let bit_to_flip = prng.gen_range(0..product.bits());
//         product.set_bit(bit_to_flip, !product.bit(bit_to_flip));

//         IOPair {
//             input: script! {
//                 { U254Windowed::OP_PUSH_U32LESLICE(&num_1.to_u32_digits()) }
//                 { U254Windowed::OP_PUSH_U32LESLICE(&num_2.to_u32_digits()) }
//             },
//             output: U508::OP_PUSH_U32LESLICE(&product.to_u32_digits()),
//         }
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use bitcoin_splitter::split::core::SplitType;
//     use bitcoin_utils::{comparison::OP_LONGEQUALVERIFY, stack_to_script};
//     use bitcoin_window_mul::traits::comparable::Comparable;

//     #[test]
//     fn test_verify() {
//         assert!(U254MulScript::verify_random());
//     }

//     #[test]
//     fn test_invalid_generate() {
//         let IOPair { input, output } = U254MulScript::generate_invalid_io_pair();
//         assert!(
//             !U254MulScript::verify(input.clone(), output.clone()),
//             "input/output is correct"
//         );
//     }

//     #[test]
//     fn test_naive_split_correctness() {
//         // Generating a random valid input for the script and the script itself
//         let IOPair { input, output } = U254MulScript::generate_valid_io_pair();
//         assert!(
//             U254MulScript::verify(input.clone(), output.clone()),
//             "input/output is not correct"
//         );

//         // Splitting the script into shards
//         let split_result = U254MulScript::default_split(input.clone(), SplitType::ByInstructions);

//         // Now, we are going to concatenate all the shards and verify that the script is also correct
//         let verification_script = script! {
//             { input }
//             for shard in split_result.shards {
//                 { shard }
//             }
//             { output }

//             // Now, we need to verify that the output is correct.
//             { OP_LONGEQUALVERIFY(U254MulScript::OUTPUT_SIZE) }
//             OP_TRUE
//         };

//         let result = execute_script(verification_script);
//         assert!(result.success, "Verification has failed");
//     }

//     #[test]
//     fn test_naive_split() {
//         // First, we generate the pair of input and output scripts
//         let IOPair { input, output } = U254MulScript::generate_valid_io_pair();

//         // Splitting the script into shards
//         let split_result = U254MulScript::default_split(input, SplitType::ByInstructions);

//         for shard in split_result.shards.iter() {
//             println!("Shard: {:?}", shard.len());
//         }

//         // Debugging the split result
//         println!("Split result: {:?}", split_result);

//         // Checking the last state (which must be equal to the result of the multiplication)
//         let last_state = split_result.must_last_state();

//         // Altstack must be empty
//         assert!(last_state.altstack.is_empty(), "altstack is not empty!");

//         // The element of the mainstack must be equal to the actual output
//         let verification_script = script! {
//             { stack_to_script(&last_state.stack) }
//             { output }
//             { U508::OP_EQUAL(0, 1) }
//         };

//         let result = execute_script(verification_script);
//         assert!(result.success, "verification has failed");

//         // Printing
//         for (i, state) in split_result.intermediate_states.iter().enumerate() {
//             println!(
//                 "Intermediate state #{}: {:?}",
//                 i,
//                 state.stack.len() + state.altstack.len()
//             );
//         }

//         // Now, we debug the total size of the states
//         let total_size = split_result.total_states_size();
//         println!("Total size of the states: {} bytes", total_size);
//     }

//     #[test]
//     fn test_split_each_shard() {
//         // First, we generate the pair of input and output scripts
//         let IOPair { input, output: _ } = U254MulScript::generate_valid_io_pair();

//         // Splitting the script into shards
//         let split_result = U254MulScript::default_split(input.clone(), SplitType::ByInstructions);

//         for i in 0..split_result.len() {
//             // Forming first two inputs. Note that the first input is the input script itself
//             // while the second input is the output of the previous shard
//             let mut first_input = input.clone();
//             if i > 0 {
//                 first_input = split_result.intermediate_states[i - 1].inject_script();
//             }

//             let second_input = split_result.intermediate_states[i].inject_script();

//             // Forming the function
//             let function = split_result.shards[i].clone();

//             let verification_script = script! {
//                 { second_input }
//                 { first_input }
//                 { function }

//                 // Verifying that the output in mainstack is correct
//                 { OP_LONGEQUALVERIFY(split_result.intermediate_states[i].stack.len()) }

//                 // Verifying that the output in altstack is correct
//                 // Pushing elements to the mainstack
//                 for _ in 0..2*split_result.intermediate_states[i].altstack.len() {
//                     OP_FROMALTSTACK
//                 }

//                 // Verifying that altstack elements are correct
//                 { OP_LONGEQUALVERIFY(split_result.intermediate_states[i].altstack.len()) }
//                 OP_TRUE
//             };

//             let result = execute_script(verification_script);

//             assert!(result.success, "verification has failed");
//         }
//     }

//     #[test]
//     fn test_split_to_u32() {
//         // First, we generate the pair of input and output scripts
//         let IOPair { input, output: _ } = U254MulScript::generate_valid_io_pair();

//         // Splitting the script into shards
//         let split_result = U254MulScript::default_split(input.clone(), SplitType::ByInstructions);

//         for i in 0..split_result.len() {
//             // Forming first two inputs. Note that the first input is the input script itself
//             // while the second input is the output of the previous shard
//             let mut first_input = input.clone();
//             if i > 0 {
//                 first_input = split_result.intermediate_states[i - 1]
//                     .to_bytes()
//                     .inject_script();
//             }
//             let second_input = split_result.intermediate_states[i]
//                 .to_bytes()
//                 .inject_script();

//             // Forming the function
//             let function = split_result.shards[i].clone();

//             let verification_script = script! {
//                 { second_input }
//                 { first_input }
//                 { function }

//                 // Verifying that the output in mainstack is correct
//                 { OP_LONGEQUALVERIFY(split_result.intermediate_states[i].stack.len()) }

//                 // Verifying that the output in altstack is correct
//                 // Pushing elements to the mainstack
//                 for _ in 0..2*split_result.intermediate_states[i].altstack.len() {
//                     OP_FROMALTSTACK
//                 }

//                 // Verifying that altstack elements are correct
//                 { OP_LONGEQUALVERIFY(split_result.intermediate_states[i].altstack.len()) }
//                 OP_TRUE
//             };

//             let result = execute_script(verification_script);

//             assert!(result.success, "verification has failed");
//         }
//     }

//     #[test]
//     #[ignore = "too-large computation, run separately"]
//     fn test_fuzzy_split() {
//         // First, we generate the pair of input and output scripts
//         let IOPair { input, output } = U254MulScript::generate_valid_io_pair();

//         // Splitting the script into shards
//         let split_result = U254MulScript::fuzzy_split(input, SplitType::ByInstructions);

//         for shard in split_result.shards.iter() {
//             println!("Shard: {:?}", shard.len());
//         }

//         // Debugging the split result
//         println!("Split result: {:?}", split_result);

//         // Checking the last state (which must be equal to the result of the multiplication)
//         let last_state = split_result.must_last_state();

//         // Altstack must be empty
//         assert!(last_state.altstack.is_empty(), "altstack is not empty!");

//         // The element of the mainstack must be equal to the actual output
//         let verification_script = script! {
//             { stack_to_script(&last_state.stack) }
//             { output }
//             { U508::OP_EQUAL(0, 1) }
//         };

//         let result = execute_script(verification_script);
//         assert!(result.success, "verification has failed");

//         // Printing
//         for (i, state) in split_result.intermediate_states.iter().enumerate() {
//             println!(
//                 "Intermediate state #{}: {:?}",
//                 i,
//                 state.stack.len() + state.altstack.len()
//             );
//         }

//         // Now, we debug the total size of the states
//         let total_size = split_result.total_states_size();
//         println!("Total size of the states: {} bytes", total_size);
//     }
// }
