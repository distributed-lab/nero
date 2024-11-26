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
    context::Context, disprove::signing::SignedIntermediateState, treepp::*, UNSPENDABLE_KEY,
};

use self::scripts::{AssertScript, OptimisticPayoutScript};

pub(crate) mod scripts;

pub struct Claim {
    /// Amount stacked for claim
    amount: Amount,

    /// Public keys of comittee prepared for aggregation.
    comittee_aggpubkey: XOnlyPublicKey,

    /// Claim transaction challenge period.
    claim_challenge_period: Height,

    /// Output of the operator's wallet for spending
    operator_script_pubkey: Script,

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
            operator_script_pubkey: ctx.operator_script_pubkey.clone(),
            comittee_aggpubkey: ctx.comittee_aggpubkey(),
            claim_challenge_period: ctx.claim_challenge_period,
            signed_states: ctx.signed_states(),
        }
    }

    pub fn challenge_output(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: self.operator_script_pubkey.clone(),
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
            .add_leaf(1, self.optimistic_payout_script().to_script())
            .expect("Depth is right")
            .add_leaf(1, self.assert_script().into_script())
            .expect("Depth is right")
            .finalize(ctx, *UNSPENDABLE_KEY)
            .unwrap()
    }

    pub fn optimistic_payout_script(&self) -> OptimisticPayoutScript {
        OptimisticPayoutScript::new(self.claim_challenge_period, self.comittee_aggpubkey)
    }

    pub fn assert_script(
        &self,
    ) -> AssertScript<'_, impl Iterator<Item = &'_ SignedIntermediateState>> {
        AssertScript::new(self.comittee_aggpubkey, self.signed_states.iter())
    }

    pub fn to_unsigned_tx<C>(&self, ctx: &Secp256k1<C>) -> Transaction
    where
        C: Verification,
    {
        let challenge_output = self.challenge_output();
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

pub struct FundedClaim {
    /// Inner clain transaction.
    claim: Claim,
    /// $x$ - input of the program
    #[allow(dead_code)]
    input: Script,
    /// Funding input got from external wallet.
    funding_inputs: Vec<TxIn>,
    /// The change output created after funding the claim tx.
    change_output: TxOut,
}

impl FundedClaim {
    /// Construct new funded claim transaction.
    pub fn new(
        claim: Claim,
        funding_inputs: Vec<TxIn>,
        change_output: TxOut,
        program_input: Script,
    ) -> Self {
        Self {
            claim,
            funding_inputs,
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

        unsigned_tx.input.clone_from(&self.funding_inputs);
        unsigned_tx.output.push(self.change_output.clone());

        unsigned_tx
    }

    pub fn compute_txid<C: Verification>(&self, ctx: &Secp256k1<C>) -> Txid {
        let tx = self.to_tx(ctx);
        tx.compute_txid()
    }

    pub fn optimistic_payout_script(&self) -> OptimisticPayoutScript {
        self.claim.optimistic_payout_script()
    }

    pub fn assert_script(
        &self,
    ) -> AssertScript<'_, impl Iterator<Item = &SignedIntermediateState>> {
        self.claim.assert_script()
    }

    // TODO(Velnbur): Current implementation is memory inefficient. Here we
    //   contruct script twice, in taptree creation and fetching the control
    //   block after it.
    pub fn assert_script_control_block<C: Verification>(&self, ctx: &Secp256k1<C>) -> ControlBlock {
        let taptree = self.claim.taptree(ctx);

        taptree
            .control_block(&(self.assert_script().into_script(), LeafVersion::TapScript))
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
            .control_block(&(
                self.optimistic_payout_script().to_script(),
                LeafVersion::TapScript,
            ))
            .expect("taptree was constructed including assert script!")
    }

    pub fn assert_output<C>(&self, ctx: &Secp256k1<C>) -> TxOut
    where
        C: Verification,
    {
        self.claim.assert_output(ctx)
    }

    pub(crate) fn challenge_output(&self) -> TxOut {
        self.claim.challenge_output()
    }
}
