use std::iter;

use bitcoin::{
    absolute::LockTime,
    key::{constants::SCHNORR_SIGNATURE_SIZE, Secp256k1, TweakedPublicKey, Verification},
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafVersion, Signature},
    transaction::Version,
    Amount, OutPoint, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut, Txid,
    Weight, Witness, XOnlyPublicKey,
};
use bitcoin_utils::{comparison::OP_LONGNOTEQUAL, pseudo::OP_LONGFROMALTSTACK, treepp::*};

use itertools::Itertools;
use musig2::{
    secp256k1::{schnorr, PublicKey, SecretKey, Signing},
    AggNonce, PartialSignature, SecNonce,
};
use signing::SignedIntermediateState;

use bitcoin_splitter::split::{
    core::SplitType,
    intermediate_state::IntermediateState,
    script::{SplitResult, SplitableScript},
};

use crate::{schnorr_sign_partial, scripts::OP_CHECKCOVENANTVERIFY, UNSPENDABLE_KEY};

pub mod signing;

#[cfg(test)]
mod tests;

pub struct Disprove {
    /// Disprove script.
    ///
    /// Used for calculating the burn amount, particlarly the weight of Disprove transaction.
    script: DisproveScript,
    /// ID of Assert transaction which output disprove tx spends.
    assert_txid: Txid,
    /// Control block required for spending the disprove.
    control_block: ControlBlock,
}

impl Disprove {
    pub fn new(script: &DisproveScript, assert_txid: Txid, control_block: ControlBlock) -> Self {
        Self {
            script: script.clone(),
            assert_txid,
            control_block,
        }
    }

    pub fn to_unsigned_tx(&self) -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(self.assert_txid, 0),
                script_sig: Script::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![
                // Burn output
                TxOut {
                    // TODO(Velnbur): calculate by ourself or make the amount configurable.
                    value: Amount::from_sat(4_000),
                    script_pubkey: Script::new_p2tr_tweaked(
                        TweakedPublicKey::dangerous_assume_tweaked(*UNSPENDABLE_KEY),
                    ),
                },
            ],
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_partial<C: Verification + Signing>(
        &self,
        ctx: &Secp256k1<C>,
        assert_output: &TxOut,
        comittee_pubkeys: Vec<PublicKey>,
        agg_nonce: &AggNonce,
        secret_key: SecretKey,
        secnonce: SecNonce,
    ) -> PartialSignature {
        let sighash = self.sighash(assert_output);

        schnorr_sign_partial(
            ctx,
            sighash,
            comittee_pubkeys,
            agg_nonce,
            secret_key,
            secnonce,
        )
    }

    pub(crate) fn sighash(&self, assert_txout: &TxOut) -> bitcoin::TapSighash {
        let unsigned_tx = self.to_unsigned_tx();

        SighashCache::new(&unsigned_tx)
            .taproot_script_spend_signature_hash(
                /* assert output spending input is the first one */ 0,
                &Prevouts::All(&[assert_txout]),
                TapLeafHash::from_script(&self.script.to_script_pubkey(), LeafVersion::TapScript),
                TapSighashType::All,
            )
            .unwrap()
    }

    fn unsigned_tx_with_witness(&self) -> Transaction {
        let mut unsigned_tx = self.to_unsigned_tx();

        let witness = &mut unsigned_tx.input[0].witness;

        for element in self.script.to_witness_stack_elements() {
            witness.push(element);
        }

        witness.push(self.script.to_script_pubkey());
        witness.push(self.control_block.serialize());
        unsigned_tx
    }

    /// Computes transaction weight
    // TODO(Velnbur): current implementation requires copying large
    // script into transaction for simpler weight calculations. But in
    // future we should calculate it by ourself.
    pub fn compute_weigth(&self) -> Weight {
        let unsigned_tx = self.unsigned_tx_with_witness();

        unsigned_tx.weight() + Weight::from_witness_data_size(SCHNORR_SIGNATURE_SIZE as u64)
    }

    pub fn script(&self) -> &DisproveScript {
        &self.script
    }
}

pub struct SignedDisprove {
    inner: Disprove,

    covenants_sig: Signature,
}

impl SignedDisprove {
    pub fn new(inner: Disprove, covenants_sig: impl Into<schnorr::Signature>) -> Self {
        Self {
            inner,
            covenants_sig: Signature {
                signature: covenants_sig.into(),
                sighash_type: TapSighashType::All,
            },
        }
    }

    pub fn to_tx<C: Verification>(&self, _ctx: &Secp256k1<C>) -> Transaction {
        let mut unsigned_tx = self.inner.to_unsigned_tx();

        let witness = &mut unsigned_tx.input[0].witness;

        // Push winternitz signatures, stack and altstack elements.
        for element in self.inner.script.to_witness_stack_elements() {
            witness.push(element);
        }
        // Push convenants signature to stack.
        witness.push(self.covenants_sig.serialize());

        witness.push(self.inner.script.to_script_pubkey());
        witness.push(self.inner.control_block.serialize());

        unsigned_tx
    }
}

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
    pub from_state: SignedIntermediateState,
    pub to_state: SignedIntermediateState,
    pub function: Script,
    pub covenants_aggpubkey: XOnlyPublicKey,
}

impl DisproveScript {
    /// Given the previous and current states, and the function that was executed,
    /// creates a new DisproveScript according to the BitVM2 protocol.
    pub fn new(
        from: IntermediateState,
        to: IntermediateState,
        function: Script,
        covenants_aggpubkey: impl Into<XOnlyPublicKey>,
    ) -> Self {
        // Sign the states with the regular entropy randomness
        let from_signed = SignedIntermediateState::sign(from);
        let to_signed = SignedIntermediateState::sign(to);

        Self::from_signed_states(from_signed, to_signed, function, covenants_aggpubkey.into())
    }

    /// Given the previous and current states, and the function that was executed,
    /// creates a new DisproveScript according to the BitVM2 protocol.
    ///
    /// The randomness is derived from the `seed`.
    pub fn new_with_seed<Seed, Rng>(
        from: IntermediateState,
        to: IntermediateState,
        function: Script,
        seed: Seed,
        covenants_aggpubkey: XOnlyPublicKey,
    ) -> Self
    where
        Seed: Sized + Default + AsMut<[u8]> + Copy,
        Rng: rand::SeedableRng<Seed = Seed> + rand::Rng,
    {
        // Sign the states with the seed randomness
        let from_signed = SignedIntermediateState::sign_with_seed::<Seed, Rng>(from, seed);
        let to_signed = SignedIntermediateState::sign_with_seed::<Seed, Rng>(to, seed);

        Self::from_signed_states(from_signed, to_signed, function, covenants_aggpubkey)
    }

    /// Construct new disprove script from already signed state.
    pub fn from_signed_states(
        from_signed: SignedIntermediateState,
        to_signed: SignedIntermediateState,
        function: Script,
        covenants_aggpubkey: XOnlyPublicKey,
    ) -> Self {
        Self {
            from_state: from_signed,
            to_state: to_signed,
            function,
            covenants_aggpubkey,
        }
    }

    /// Given the previous and current states signed, and the function that was executed,
    /// creates a new DisproveScript according to the BitVM2 protocol.
    pub fn to_script_pubkey(&self) -> Script {
        script! {
            { OP_CHECKCOVENANTVERIFY(self.covenants_aggpubkey) }

            // Step 1. Public key + verification of "to" state
            { self.to_state.verification_script_toaltstack() } // This leaves z[i+1] in the altstack
            { self.from_state.verification_script() } // This leaves z[i].mainstack in the mainstack, while (z[i+1], z[i].altstack) is still in the altstack

            // Step 2. Applying function and popping "to" state
            { self.function.clone() } // This leaves f[i](z[i]).mainstack in the mainstack and { z[i+1].altstack, f[i](z[i]).altstack } in the altstack
            { OP_LONGFROMALTSTACK(self.to_state.altstack.len()) }
            { self.to_state.verification_script_fromaltstack() } // This leaves z[i+1].mainstack and f[i](z[i]).mainstack in the mainstack, while f[i](z[i]).altstack and z[i+1].alstack is in the altstack

            // Step 3.
            // At this point, our stack consists of:
            // { f[i](z[i]).mainstack, f[i](z[i]).altstack, z[i+1].mainstack }
            // while the altstack has z[i+1].altstack.
            // Thus, we have to pick f[i](z[i]).mainstack to the top of the stack
            for _ in (0..self.to_state.stack.len()).rev() {
                { self.to_state.total_len() + self.to_state.stack.len() - 1 } OP_ROLL
            }

            // At this point, we should have
            // { f[i](z[i]).altstack, z[i+1].mainstack, f[i](z[i]).mainstack }

            // Step 4. Checking if z[i+1] == f(z[i])
            // a) Mainstack verification
            { OP_LONGNOTEQUAL(self.to_state.stack.len()) }

            // b) Altstack verification
            { OP_LONGFROMALTSTACK(self.to_state.altstack.len()) }

            // Since currently our stack looks like:
            // { f[i](z[i]).altstack, {bit}, z[i+1].altstack, },
            // we need to push f[i](z[i]).altstack to the top of the stack
            for _ in 0..self.to_state.altstack.len() {
                { 2*self.to_state.altstack.len() } OP_ROLL
            }

            { OP_LONGNOTEQUAL(self.to_state.altstack.len()) }
            OP_BOOLOR
        }
    }

    /// Construct elements for witness stack which fulfill the spending
    /// condition in assert transaction taptree.
    pub fn to_witness_stack_elements(&self) -> Vec<Vec<u8>> {
        let mut stack = Vec::new();
        stack.extend(self.from_state.witness_elements());
        stack.extend(self.to_state.witness_elements());
        stack
    }

    /// Construct script sig for fullfiling the disprove script conditions.
    pub fn to_script_sig(&self, comittee_signature: Signature) -> Script {
        script! {
            { self.from_state.to_script_sig() }
            { self.to_state.to_script_sig() }
            { comittee_signature.serialize().to_vec() }
        }
    }
}

/// Given the `input` script, [`SplitResult`] and `constructor`, does the following:
/// - For each shard, creates a DisproveScript using `constructor`
/// - Returns the list of [`DisproveScript`]s.
fn disprove_scripts_with_constructor<F>(
    input: Script,
    split_result: SplitResult,
    covenants_aggpubkey: XOnlyPublicKey,
    constructor: F,
) -> Vec<DisproveScript>
where
    F: Fn(IntermediateState, IntermediateState, Script, XOnlyPublicKey) -> DisproveScript + Clone,
{
    assert_eq!(
        split_result.shards.len(),
        split_result.intermediate_states.len(),
        "Shards and intermediate states must have the same length"
    );

    iter::once(IntermediateState::from_inject_script(input))
        .chain(split_result.intermediate_states)
        .tuple_windows()
        .zip(split_result.shards)
        .map(|((from, to), function)| constructor(from, to, function, covenants_aggpubkey))
        .collect()
}

/// Given the script and its input, does the following:
/// - Splits the script into shards
/// - For each shard, creates a [`DisproveScript`]
/// - Returns the list of [`DisproveScript`]s
pub fn form_disprove_scripts<S: SplitableScript>(
    input: Script,
    covenants_aggpubkey: XOnlyPublicKey,
) -> Vec<DisproveScript> {
    let split_result = S::default_split(input.clone(), SplitType::default());
    disprove_scripts_with_constructor(
        input,
        split_result,
        covenants_aggpubkey,
        DisproveScript::new,
    )
}

/// Given the script and its input, does the following:
/// - Splits the script into shards
/// - Distorts the random intermediate state, making
///   two state transitions incorrect
/// - For each shard, creates a [`DisproveScript`]
/// - Returns the list of [`DisproveScript`]s and the index of distorted shard
pub fn form_disprove_scripts_distorted<S: SplitableScript>(
    input: Script,
    covenants_aggpubkey: XOnlyPublicKey,
) -> (Vec<DisproveScript>, usize) {
    // Splitting the script into shards
    let split_result = S::default_split(input.clone(), SplitType::default());

    // Distorting the output of the random shard
    let (distorted_split_result, distorted_shard_id) = split_result.distort();

    // Creating the disprove scripts
    let disprove_scripts = disprove_scripts_with_constructor(
        input,
        distorted_split_result,
        covenants_aggpubkey,
        DisproveScript::new,
    );

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
    covenants_aggpubkey: XOnlyPublicKey,
    seed: Seed,
) -> Vec<DisproveScript>
where
    S: SplitableScript,
    Seed: Sized + Default + AsMut<[u8]> + Copy,
    Rng: rand::SeedableRng<Seed = Seed> + rand::Rng,
{
    let split_result = S::default_split(input.clone(), SplitType::default());
    disprove_scripts_with_constructor(
        input,
        split_result,
        covenants_aggpubkey,
        |from, to, shard, covenants_aggpubkey: XOnlyPublicKey| {
            DisproveScript::new_with_seed::<Seed, Rng>(from, to, shard, seed, covenants_aggpubkey)
        },
    )
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
    covenants_aggpubkey: XOnlyPublicKey,
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
    let disprove_scripts = disprove_scripts_with_constructor(
        input,
        distorted_split_result,
        covenants_aggpubkey,
        |from, to, shard, covenants_aggpubkey| {
            DisproveScript::new_with_seed::<Seed, Rng>(from, to, shard, seed, covenants_aggpubkey)
        },
    );

    // Returning the result
    (disprove_scripts, distorted_shard_id)
}

pub fn extract_signed_states(
    disproves: &[DisproveScript],
) -> impl DoubleEndedIterator<Item = &SignedIntermediateState> {
    iter::once(&disproves[0].from_state).chain(disproves.iter().map(|d| &d.to_state))
}
