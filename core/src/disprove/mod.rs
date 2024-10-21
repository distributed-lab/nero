use bitcoin::{opcodes::ClassifyContext, script::Instruction};
use bitcoin_utils::{comparison::OP_LONGNOTEQUAL, stack_to_script, treepp::*};

use signing::SignedIntermediateState;

use bitcoin_splitter::split::{
    core::SplitType, intermediate_state::IntermediateState, script::SplitableScript,
};

pub mod signing;

#[cfg(test)]
mod tests;

/// Script letting challengers spend the **Assert** transaction
/// output if the operator computated substates incorrectly.
///
/// This a typed version of [`Script`] can be easily converted into it.
///
/// The script structure in general is simple:
/// ## Witness:
/// ```bitcoin_script
/// { Enc(z[i+1]) and Sig[i+1] } // Zipped
/// { Enc(z[i]) and Sig[i] }     // Zipped
/// ```
///
/// ## Script:
/// ```bitcoin_script
/// { pk[i] }                // { Zip(Enc(z[i+1]), Sig[i+1]), Zip(Enc(z[i]), Sig[i]), pk[i] }
/// { OP_WINTERNITZVERIFY }  // { Zip(Enc(z[i+1]), Sig[i+1]), Enc(z[i]) }
/// { OP_RESTORE }           // { Zip(Enc(z[i+1]), Sig[i+1]), z[i] }
/// { OP_TOALTSTACK }        // { Zip(Enc(z[i+1]), Sig[i+1]) }
/// { pk[i+1] }              // { Zip(Enc(z[i+1]), Sig[i+1]), pk[i+1] }
/// { OP_WINTERNITZVERIFY }  // { Enc(z[i+1]) }
/// { OP_RESTORE }           // { z[i+1] }
/// { OP_FROMALTSTACK }      // { z[i+1] z[i] }
/// { fn[i] }                // { z[i+1] fn[i](z[i]) }
/// { OP_EQUAL }             // { z[i+1] == fn[i](z[i]) }
/// { OP_NOT }               // { z[i+1] != fn[i](z[i]) }
/// ```
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DisproveScript {
    pub script_witness: Script,
    pub script_pubkey: Script,
}

impl DisproveScript {
    /// Given the previous and current states, and the function that was executed,
    /// creates a new DisproveScript according to the BitVM2 protocol.
    pub fn new(from: &IntermediateState, to: &IntermediateState, function: &Script) -> Self {
        // Step 1.
        // First, we sign the states
        let from_signed = SignedIntermediateState::sign(from);
        let to_signed = SignedIntermediateState::sign(to);

        // Step 2.
        // Now, we form the witness script. Just pushing all
        // signatures + messages to the witness script
        let script_witness = script! {
            { from_signed.witness_script() } // Zipped Enc(z[i]) and Sig[i]
            { to_signed.witness_script() }   // Zipped Enc(z[i+1]) and Sig[i+1]
        };

        // Step 3.
        // Now, we form the script pubkey
        let script_pubkey = script! {
            // 1. Public key + verification of "to" state
            { to_signed.verification_script_toaltstack() } // This leaves z[i+1] in the altstack
            { from_signed.verification_script() } // This leaves z[i].mainstack in the mainstack, while (z[i+1], z[i].altstack) is still in the altstack

            // 2. Applying function and popping "to" state
            { function.clone() } // This leaves f[i](z[i]).mainstack in the mainstack and { z[i+1].altstack, f[i](z[i]).altstack } in the altstack
            for _ in 0..to_signed.altstack.len() {
                OP_FROMALTSTACK
            }
            { to_signed.verification_script_fromaltstack() } // This leaves z[i+1].mainstack and f[i](z[i]).mainstack in the mainstack, while f[i](z[i]).altstack and z[i+1].alstack is in the altstack

            // At tbis point, our stack consists of:
            // { f[i](z[i]).mainstack, f[i](z[i]).altstack, z[i+1].mainstack }
            // while the altstack has z[i+1].altstack.
            // Thus, we have to pick f[i](z[i]).mainstack to the top of the stack
            for _ in (0..to_signed.stack.len()).rev() {
                { to_signed.total_len() + to_signed.stack.len() - 1 } OP_ROLL
            }

            // At this point, we should have
            // { f[i](z[i]).altstack, z[i+1].mainstack, f[i](z[i]).mainstack }

            // 3. Checking if z[i+1] == f(z[i])
            // 3.1. Mainstack verification
            { OP_LONGNOTEQUAL(to_signed.stack.len()) }

            // 3.2. Altstack verification
            for _ in 0..to_signed.altstack.len() {
                OP_FROMALTSTACK
            }

            // Since currently our stack looks like:
            // { f[i](z[i]).altstack, {bit}, z[i+1].altstack, },
            // we need to push f[i](z[i]).altstack to the top of the stack
            for _ in 0..to_signed.altstack.len() {
                { 2*to_signed.altstack.len() } OP_ROLL
            }

            { OP_LONGNOTEQUAL(to_signed.altstack.len()) }
            OP_BOOLOR
        };

        Self {
            script_witness,
            script_pubkey,
        }
    }

    pub fn witness_elements(&self) -> Vec<Vec<u8>> {
        let mut elements = Vec::with_capacity(self.script_witness.len());

        for instruction in self.script_witness.instructions() {
            match instruction.unwrap() {
                Instruction::PushBytes(bytes) => {
                    elements.push(bytes.as_bytes().to_vec());
                }
                Instruction::Op(opcode) => {
                    match opcode.classify(ClassifyContext::TapScript) {
                        bitcoin::opcodes::Class::PushNum(num) => {
                            let buf = num.to_le_bytes().into_iter().filter(|b| *b != 0).collect();
                            elements.push(buf);
                        }
                        _ => {
                            unreachable!("script witness shouldn't have opcodes, got {opcode}")
                        }
                    };
                }
            }
        }

        elements
    }
}

/// Given the script and its input, does the following:
/// - Splits the script into shards
/// - For each shard, creates a DisproveScript
/// - Returns the list of DisproveScripts
pub fn form_disprove_scripts<
    const INPUT_SIZE: usize,
    const OUTPUT_SIZE: usize,
    S: SplitableScript<INPUT_SIZE, OUTPUT_SIZE>,
>(
    input: Script,
) -> Vec<DisproveScript> {
    // Splitting the script into shards
    let split_result = S::default_split(input.clone(), SplitType::default());

    assert_eq!(
        split_result.shards.len(),
        split_result.intermediate_states.len(),
        "Shards and intermediate states must have the same length"
    );

    (0..split_result.shards.len())
        .map(|i| {
            let from_state = if i == 0 {
                IntermediateState::from_inject_script(&input.clone())
            } else {
                split_result.intermediate_states[i - 1].clone()
            };

            DisproveScript::new(
                &from_state,
                &split_result.intermediate_states[i],
                &split_result.shards[i],
            )
        })
        .collect()
}

/// Given the script and its input, does the following:
/// - Splits the script into shards
/// - Distorts the random intermediate state, making
///   two state transitions incorrect
/// - For each shard, creates a DisproveScript
/// - Returns the list of DisproveScripts and the index of distorted shard
pub fn form_disprove_scripts_distorted<
    const INPUT_SIZE: usize,
    const OUTPUT_SIZE: usize,
    S: SplitableScript<INPUT_SIZE, OUTPUT_SIZE>,
>(
    input: Script,
) -> (Vec<DisproveScript>, usize) {
    // Splitting the script into shards
    let mut split_result = S::default_split(input.clone(), SplitType::default());

    assert_eq!(
        split_result.shards.len(),
        split_result.intermediate_states.len(),
        "Shards and intermediate states must have the same length"
    );

    // Distorting the output of the random shard
    let distorted_shard_id = rand::random::<usize>() % split_result.shards.len();
    let current_stack = split_result.intermediate_states[distorted_shard_id]
        .stack
        .clone();
    assert!(!current_stack.is_empty(), "Stack must not be empty");
    split_result.intermediate_states[distorted_shard_id].stack = {
        // Executing a random script and getting the stack
        let random_state = script! {
            { stack_to_script(&current_stack) }
            OP_DROP OP_0 // Changing the last limb to OP_0
        };

        execute_script(random_state).main_stack
    };

    let disprove_scripts = (0..split_result.shards.len())
        .map(|i| {
            let from_state = if i == 0 {
                IntermediateState::from_inject_script(&input.clone())
            } else {
                split_result.intermediate_states[i - 1].clone()
            };

            DisproveScript::new(
                &from_state,
                &split_result.intermediate_states[i],
                &split_result.shards[i],
            )
        })
        .collect();

    (disprove_scripts, distorted_shard_id)
}
