use bitcoin::{opcodes::ClassifyContext, script::Instruction};
use bitcoin_utils::{comparison::OP_LONGNOTEQUAL, pseudo::OP_LONGFROMALTSTACK, treepp::*};

use signing::SignedIntermediateState;

use bitcoin_splitter::split::{
    core::SplitType,
    intermediate_state::IntermediateState,
    script::{SplitResult, SplitableScript},
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
        // Sign the states with the regular entropy randomness
        let from_signed = SignedIntermediateState::sign(from);
        let to_signed = SignedIntermediateState::sign(to);

        Self::new_from_signed_states(&from_signed, &to_signed, function)
    }

    /// Given the previous and current states, and the function that was executed,
    /// creates a new DisproveScript according to the BitVM2 protocol.
    ///
    /// The randomness is derived from the `seed`.
    pub fn new_with_seed<Seed, Rng>(
        from: &IntermediateState,
        to: &IntermediateState,
        function: &Script,
        seed: Seed,
    ) -> Self
    where
        Seed: Sized + Default + AsMut<[u8]> + Copy,
        Rng: rand::SeedableRng<Seed = Seed> + rand::Rng,
    {
        // Sign the states with the seed randomness
        let from_signed = SignedIntermediateState::sign_with_seed::<Seed, Rng>(from, seed);
        let to_signed = SignedIntermediateState::sign_with_seed::<Seed, Rng>(to, seed);

        Self::new_from_signed_states(&from_signed, &to_signed, function)
    }

    /// Given the previous and current states signed, and the function that was executed,
    /// creates a new DisproveScript according to the BitVM2 protocol.
    fn new_from_signed_states(
        from: &SignedIntermediateState,
        to: &SignedIntermediateState,
        function: &Script,
    ) -> Self {
        // Step 1.
        // We form the witness script. Just pushing all
        // signatures + messages to the witness script
        let script_witness = script! {
            { from.witness_script() } // Zipped Enc(z[i]) and Sig[i]
            { to.witness_script() }   // Zipped Enc(z[i+1]) and Sig[i+1]
        };

        // Step 3.
        // Now, we form the script pubkey
        let script_pubkey = script! {
            // Step 3.1. Public key + verification of "to" state
            { to.verification_script_toaltstack() } // This leaves z[i+1] in the altstack
            { from.verification_script() } // This leaves z[i].mainstack in the mainstack, while (z[i+1], z[i].altstack) is still in the altstack

            // Step 3.2. Applying function and popping "to" state
            { function.clone() } // This leaves f[i](z[i]).mainstack in the mainstack and { z[i+1].altstack, f[i](z[i]).altstack } in the altstack
            { OP_LONGFROMALTSTACK(to.altstack.len()) }
            { to.verification_script_fromaltstack() } // This leaves z[i+1].mainstack and f[i](z[i]).mainstack in the mainstack, while f[i](z[i]).altstack and z[i+1].alstack is in the altstack

            // Step 3.3.
            // At this point, our stack consists of:
            // { f[i](z[i]).mainstack, f[i](z[i]).altstack, z[i+1].mainstack }
            // while the altstack has z[i+1].altstack.
            // Thus, we have to pick f[i](z[i]).mainstack to the top of the stack
            for _ in (0..to.stack.len()).rev() {
                { to.total_len() + to.stack.len() - 1 } OP_ROLL
            }

            // At this point, we should have
            // { f[i](z[i]).altstack, z[i+1].mainstack, f[i](z[i]).mainstack }

            // Step 3.4. Checking if z[i+1] == f(z[i])
            // a) Mainstack verification
            { OP_LONGNOTEQUAL(to.stack.len()) }

            // b) Altstack verification
            { OP_LONGFROMALTSTACK(to.altstack.len()) }

            // Since currently our stack looks like:
            // { f[i](z[i]).altstack, {bit}, z[i+1].altstack, },
            // we need to push f[i](z[i]).altstack to the top of the stack
            for _ in 0..to.altstack.len() {
                { 2*to.altstack.len() } OP_ROLL
            }

            { OP_LONGNOTEQUAL(to.altstack.len()) }
            OP_BOOLOR
        };

        Self {
            script_witness,
            script_pubkey,
        }
    }

    /// Returns the elements of the witness script
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

/// Given the `input` script, [`SplitResult`] and `constructor`, does the following:
/// - For each shard, creates a DisproveScript using `constructor`
/// - Returns the list of [`DisproveScript`]s.
fn disprove_scripts_with_constructor<F>(
    input: Script,
    split_result: SplitResult,
    constructor: F,
) -> Vec<DisproveScript>
where
    F: Fn(&IntermediateState, &IntermediateState, &Script) -> DisproveScript + Clone,
{
    assert_eq!(
        split_result.shards.len(),
        split_result.intermediate_states.len(),
        "Shards and intermediate states must have the same length"
    );

    (0..split_result.shards.len())
        .map(|i| {
            let from_state = match i {
                0 => IntermediateState::from_inject_script(&input.clone()),
                _ => split_result.intermediate_states[i - 1].clone(),
            };

            constructor(
                &from_state,
                &split_result.intermediate_states[i],
                &split_result.shards[i],
            )
        })
        .collect()
}

/// Given the script and its input, does the following:
/// - Splits the script into shards
/// - For each shard, creates a [`DisproveScript`]
/// - Returns the list of [`DisproveScript`]s
pub fn form_disprove_scripts<S: SplitableScript>(input: Script) -> Vec<DisproveScript> {
    let split_result = S::default_split(input.clone(), SplitType::default());
    disprove_scripts_with_constructor(input, split_result, DisproveScript::new)
}

/// Given the script and its input, does the following:
/// - Splits the script into shards
/// - Distorts the random intermediate state, making
///   two state transitions incorrect
/// - For each shard, creates a [`DisproveScript`]
/// - Returns the list of [`DisproveScript`]s and the index of distorted shard
pub fn form_disprove_scripts_distorted<S: SplitableScript>(
    input: Script,
) -> (Vec<DisproveScript>, usize) {
    // Splitting the script into shards
    let split_result = S::default_split(input.clone(), SplitType::default());

    // Distorting the output of the random shard
    let (distorted_split_result, distorted_shard_id) = split_result.distort();

    // Creating the disprove scripts
    let disprove_scripts =
        disprove_scripts_with_constructor(input, distorted_split_result, DisproveScript::new);

    // Returning the result
    (disprove_scripts, distorted_shard_id)
}

/// Given the script and its input, does the following:
/// - Splits the script into shards
/// - For each shard, creates a [`DisproveScript`]
/// - Returns the list of [`DisproveScript`]s
///
/// The randomness is derived from the `seed`.
pub fn form_disprove_scripts_with_seed<S, Seed, Rng>(
    input: Script,
    seed: Seed,
) -> Vec<DisproveScript>
where
    S: SplitableScript,
    Seed: Sized + Default + AsMut<[u8]> + Copy,
    Rng: rand::SeedableRng<Seed = Seed> + rand::Rng,
{
    let split_result = S::default_split(input.clone(), SplitType::default());
    disprove_scripts_with_constructor(input, split_result, |from, to, shard| {
        DisproveScript::new_with_seed::<Seed, Rng>(from, to, shard, seed)
    })
}

/// Given the script and its input, does the following:
/// - Splits the script into shards
/// - Distorts the random intermediate state, making
///   two state transitions incorrect
/// - For each shard, creates a [`DisproveScript`]
/// - Returns the list of [`DisproveScript`]s and the index of distorted shard
///
/// The randomness is derived from the `seed`.
pub fn form_disprove_scripts_distorted_with_seed<S, Seed, Rng>(
    input: Script,
    seed: Seed,
) -> (Vec<DisproveScript>, usize)
where
    S: SplitableScript,
    Seed: Sized + Default + AsMut<[u8]> + Copy,
    Rng: rand::SeedableRng<Seed = Seed> + rand::Rng,
{
    // Splitting the script into shards
    let split_result = S::default_split(input.clone(), SplitType::default());

    // Distorting the output of the random shard
    let (distorted_split_result, distorted_shard_id) = split_result.distort();

    // Creating the disprove scripts
    let disprove_scripts =
        disprove_scripts_with_constructor(input, distorted_split_result, |from, to, shard| {
            DisproveScript::new_with_seed::<Seed, Rng>(from, to, shard, seed)
        });

    // Returning the result
    (disprove_scripts, distorted_shard_id)
}
