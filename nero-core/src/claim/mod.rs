//! Clain transaction.

use bitcoin::{
    absolute::LockTime,
    key::{Secp256k1, Verification},
    relative::Height,
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Amount, FeeRate, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use bitcoin_splitter::split::script::SplitableScript;

use crate::{
    context::Context, disprove::signing::SignedIntermediateState, scripts::OP_CHECKCOVENANTVERIFY,
    treepp::*, UNSPENDABLE_KEY,
};

pub struct Claim {
    /// Amount stacked for claim
    amount: Amount,

    /// Public keys of comittee prepared for aggregation.
    comittee_aggpubkey: XOnlyPublicKey,

    /// Claim transaction challenge period.
    claim_challenge_period: Height,

    /// Operator's pubkey
    operator_pubkey: XOnlyPublicKey,

    /// All signed states
    signed_states: Vec<SignedIntermediateState>,
}

impl Claim {
    pub fn from_context<S: SplitableScript, C: Verification>(
        ctx: &Context<S, C>,
        fee_rate: FeeRate,
    ) -> Self {
        Self {
            amount: ctx.staked_amount
                + fee_rate
                    .checked_mul_by_weight(
                        ctx.assert_tx_weight + *ctx.disprove_weights.iter().max().unwrap(),
                    )
                    .unwrap(),
            comittee_aggpubkey: ctx.comittee_aggpubkey(),
            claim_challenge_period: ctx.claim_challenge_period,
            operator_pubkey: ctx.operator_pubkey.x_only_public_key().0,
            signed_states: ctx.signed_states(),
        }
    }

    pub fn challenge_output<C>(&self, ctx: &Secp256k1<C>) -> TxOut
    where
        C: Verification,
    {
        TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: Script::new_p2tr(ctx, self.operator_pubkey, None),
        }
    }

    pub fn assert_output<C>(&self, ctx: &Secp256k1<C>) -> TxOut
    where
        C: Verification,
    {
        let taptree = self.taptree(ctx);

        TxOut {
            value: self.amount,
            script_pubkey: Script::new_p2tr_tweaked(taptree.output_key()),
        }
    }

    fn taptree<C: Verification>(&self, ctx: &Secp256k1<C>) -> TaprootSpendInfo {
        TaprootBuilder::new()
            .add_leaf(1, self.optimistic_payout_script())
            .expect("Depth is right")
            .add_leaf(1, self.assert_script())
            .expect("Depth is right")
            .finalize(ctx, *UNSPENDABLE_KEY)
            .unwrap()
    }

    pub fn optimistic_payout_script(&self) -> Script {
        optimistic_payout_script(self.claim_challenge_period, self.comittee_aggpubkey)
    }

    pub fn assert_script(&self) -> Script {
        assert_script(self.comittee_aggpubkey, self.signed_states.iter())
    }

    pub fn to_unsigned_tx<C>(&self, ctx: &Secp256k1<C>) -> Transaction
    where
        C: Verification,
    {
        let challenge_output = self.challenge_output(ctx);
        let assert_output = self.assert_output(ctx);

        Transaction {
            // Requires for OP_CSV
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            // Inputs are empty as they should be funded by wallet.
            input: vec![],
            output: vec![assert_output, challenge_output],
        }
    }
}

/// Script which is spent in optimistic payout flow adter challenge period ends.
fn optimistic_payout_script(claim_challenge_period: Height, aggpubkey: XOnlyPublicKey) -> Script {
    script! {
        { claim_challenge_period.value().to_le_bytes().to_vec() }
        OP_CSV
        OP_DROP
        OP_DROP
        // { OP_CHECKCOVENANTVERIFY(aggpubkey) }
    }
}

/// `AssertScript` from original BitVM2 paper. Checks from stack  all
/// Winternitz commitments for signed intermidiate states.
fn assert_script<'a>(
    aggpubkey: XOnlyPublicKey,
    states: impl Iterator<Item = &'a SignedIntermediateState>,
) -> Script {
    script! {
        { OP_CHECKCOVENANTVERIFY(aggpubkey) }
        for state in states {
            for element in &state.stack {
                { element.public_key.checksig_verify_script_compact(&element.encoding) }
            }
            for element in &state.altstack {
                { element.public_key.checksig_verify_script_compact(&element.encoding) }
            }
        }
    }
}

pub struct FundedClaim {
    /// Inner clain transaction.
    claim: Claim,
    /// $x$ - input of the program
    #[allow(dead_code)]
    input: Script,
    /// Funding input got from external wallet.
    funding_input: TxIn,
    /// The change output created after funding the claim tx.
    change_output: TxOut,
}

impl FundedClaim {
    /// Construct new funded claim transaction.
    pub fn new(
        claim: Claim,
        funding_input: TxIn,
        change_output: TxOut,
        program_input: Script,
    ) -> Self {
        Self {
            claim,
            funding_input,
            input: program_input,
            change_output,
        }
    }

    /// Construct bitcoin transaction from funded claim.
    pub fn to_tx<C>(&self, ctx: &Secp256k1<C>) -> Transaction
    where
        C: Verification,
    {
        let mut unsigned_tx = self.claim.to_unsigned_tx(ctx);
        let funding_input = self.funding_input.clone();

        // Fullfill the last elements of witness stack
        // for instruction in self.input.instructions() {
        //     match instruction.unwrap() {
        //         Instruction::PushBytes(bytes) => {
        //             funding_input.witness.push(bytes.as_bytes());
        //         }
        //         Instruction::Op(opcode) => {
        //             match opcode.classify(ClassifyContext::TapScript) {
        //                 bitcoin::opcodes::Class::PushNum(num) => {
        //                     let buf: Vec<u8> =
        //                         num.to_le_bytes().into_iter().filter(|b| *b != 0).collect();
        //                     funding_input.witness.push(buf);
        //                 }
        //                 _ => {
        //                     unreachable!("script witness shouldn't have opcodes, got {opcode}")
        //                 }
        //             };
        //         }
        //     }
        // }

        unsigned_tx.input.push(funding_input);
        unsigned_tx.output.push(self.change_output.clone());

        unsigned_tx
    }

    pub fn compute_txid<C: Verification>(&self, ctx: &Secp256k1<C>) -> Txid {
        let tx = self.to_tx(ctx);
        tx.compute_txid()
    }

    pub fn optimistic_payout_script(&self) -> Script {
        self.claim.optimistic_payout_script()
    }

    pub fn assert_script(&self) -> Script {
        self.claim.assert_script()
    }

    // TODO(Velnbur): Current implementation is memory inefficient. Here we
    //   contruct script twice, in taptree creation and fetching the control
    //   block after it.
    pub fn assert_script_control_block<C: Verification>(&self, ctx: &Secp256k1<C>) -> ControlBlock {
        let taptree = self.claim.taptree(ctx);

        taptree
            .control_block(&(self.assert_script(), LeafVersion::TapScript))
            .expect("taptree was constructed including assert script!")
    }

    // TODO(Velnbur): Current implementation is memory inefficient. Here we
    //   contruct script twice, in taptree creation and fetching the control
    //   block after it.
    pub fn optimistic_payout_script_control_block<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
    ) -> ControlBlock {
        let taptree = self.claim.taptree(ctx);

        taptree
            .control_block(&(self.optimistic_payout_script(), LeafVersion::TapScript))
            .expect("taptree was constructed including assert script!")
    }
}
