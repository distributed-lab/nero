use std::iter;

use bitcoin::{
    absolute::LockTime,
    key::{constants::SCHNORR_SIGNATURE_SIZE, Secp256k1, Verification},
    relative::Height,
    sighash::{Prevouts, SighashCache},
    taproot::{self, ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Amount, FeeRate, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn,
    TxOut, Txid, Weight, Witness, XOnlyPublicKey,
};
use bitcoin_splitter::split::script::SplitableScript;
use musig2::{
    secp256k1::{schnorr::Signature, PublicKey, SecretKey, Signing},
    AggNonce, PartialSignature, SecNonce,
};

use crate::{
    claim::{scripts::AssertScript, FundedClaim},
    context::Context,
    disprove::{extract_signed_states, signing::SignedIntermediateState, DisproveScript},
    payout::PayoutScript,
    schnorr_sign_partial, UNSPENDABLE_KEY,
};

const DISPROVE_SCRIPT_WEIGHT: u32 = 1;
const PAYOUT_SCRIPT_WEIGHT: u32 = 5;

pub struct Assert {
    claim_txid: Txid,
    disprove_scripts: Vec<DisproveScript>,
    payout_script: PayoutScript,
    staked_amount: Amount,
}

impl Assert {
    pub fn from_context<S: SplitableScript, C: Verification>(
        ctx: &Context<S, C>,
        claim_txid: Txid,
        fee_rate: FeeRate,
    ) -> Self {
        Self {
            claim_txid,
            disprove_scripts: ctx.disprove_scripts.clone(),
            payout_script: PayoutScript::with_locktime(
                ctx.operator_pubkey.into(),
                ctx.comittee_aggpubkey(),
                ctx.assert_challenge_period,
            ),
            staked_amount: ctx.staked_amount
                + fee_rate
                    .checked_mul_by_weight(ctx.largest_disprove_weight)
                    .unwrap(),
        }
    }

    pub fn new(
        disprove_scripts: &[DisproveScript],
        operator_pubkey: XOnlyPublicKey,
        assert_challenge_period: Height,
        claim_txid: Txid,
        comittee_aggpubkey: XOnlyPublicKey,
        staked_amount: Amount,
    ) -> Self {
        Self {
            claim_txid,
            disprove_scripts: disprove_scripts.to_owned(),
            payout_script: PayoutScript::with_locktime(
                operator_pubkey,
                comittee_aggpubkey,
                assert_challenge_period,
            ),
            staked_amount,
        }
    }

    pub fn taproot<C>(&self, ctx: &Secp256k1<C>) -> TaprootSpendInfo
    where
        C: Verification,
    {
        let scripts_with_weights =
            iter::once((PAYOUT_SCRIPT_WEIGHT, self.payout_script.to_script())).chain(
                self.disprove_scripts
                    .iter()
                    .map(|script| (DISPROVE_SCRIPT_WEIGHT, script.to_script_pubkey())),
            );

        TaprootBuilder::with_huffman_tree(scripts_with_weights)
            .expect("Weights are low, and number of scripts shoudn't create the tree greater than 128 in depth (I believe)")
            .finalize(ctx, *UNSPENDABLE_KEY)
            .expect("Scripts and keys should be valid")
    }

    pub fn to_unsigned_tx<C>(&self, ctx: &Secp256k1<C>) -> Transaction
    where
        C: Verification,
    {
        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(self.claim_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![self.output(ctx)],
        }
    }

    fn to_unsigned_tx_with_witness<C: Verification>(&self, ctx: &Secp256k1<C>) -> Transaction {
        let mut unsigned_tx = self.to_unsigned_tx(ctx);

        let witness = &mut unsigned_tx.input[0].witness;

        for disprove in &self.disprove_scripts {
            for element in disprove.to_witness_stack_elements() {
                witness.push(element);
            }
        }

        unsigned_tx
    }

    pub fn compute_weight<C: Verification>(&self, ctx: &Secp256k1<C>) -> Weight {
        let unsigned_tx = self.to_unsigned_tx_with_witness(ctx);

        unsigned_tx.weight() + /* comitte signature */ Weight::from_witness_data_size(SCHNORR_SIGNATURE_SIZE as u64)
    }

    pub fn compute_txid<C: Verification>(&self, ctx: &Secp256k1<C>) -> Txid {
        let unsigned_tx = self.to_unsigned_tx(ctx);
        unsigned_tx.compute_txid()
    }

    pub fn output<C: Verification>(&self, ctx: &Secp256k1<C>) -> TxOut {
        let taproot = self.taproot(ctx);
        TxOut {
            value: self.staked_amount,
            script_pubkey: ScriptBuf::new_p2tr_tweaked(taproot.output_key()),
        }
    }

    /// Create partial Schnorr signatures from claim transaction.
    pub fn sign_partial_from_claim<C: Verification + Signing>(
        &self,
        ctx: &Secp256k1<C>,
        claim: &FundedClaim,
        comittee_pubkeys: Vec<PublicKey>,
        agg_nonce: &AggNonce,
        secret_key: SecretKey,
        secnonce: SecNonce,
    ) -> PartialSignature {
        let claim_assert_output = &claim.to_tx(ctx).output[0];
        let claim_assert_script = claim.assert_script();

        self.sign_partial(
            ctx,
            claim_assert_output,
            claim_assert_script,
            comittee_pubkeys,
            agg_nonce,
            secret_key,
            secnonce,
        )
    }

    // Let's reconsider the number of parameters later.
    #[allow(clippy::too_many_arguments)]
    /// Partially sign transaction using operator's key.
    pub fn sign_partial<'a, C: Verification + Signing>(
        &self,
        ctx: &Secp256k1<C>,
        claim_assert_output: &TxOut,
        claim_assert_script: AssertScript<'a, impl Iterator<Item = &'a SignedIntermediateState>>,
        comittee_pubkeys: Vec<PublicKey>,
        agg_nonce: &AggNonce,
        secret_key: SecretKey,
        secnonce: SecNonce,
    ) -> PartialSignature {
        let sighash = self.sighash(ctx, claim_assert_output, claim_assert_script);

        schnorr_sign_partial(
            ctx,
            sighash,
            comittee_pubkeys,
            agg_nonce,
            secret_key,
            secnonce,
        )
    }

    /// Return sighash of assert transaction for signing.
    pub(crate) fn sighash<'a, C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        claim_assert_output: &TxOut,
        claim_assert_script: AssertScript<'a, impl Iterator<Item = &'a SignedIntermediateState>>,
    ) -> bitcoin::TapSighash {
        let script = claim_assert_script.into_script();
        let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
        let unsigned_tx = self.to_unsigned_tx(ctx);

        SighashCache::new(&unsigned_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[claim_assert_output]),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap()
    }

    pub fn payout_script(&self) -> &PayoutScript {
        &self.payout_script
    }
}

pub struct SignedAssert {
    inner: Assert,
    signature: taproot::Signature,
    assert_script: ScriptBuf,
    assert_script_control_block: ControlBlock,
}

impl SignedAssert {
    pub fn new<'a>(
        inner: Assert,
        signature: impl Into<Signature>,
        assert_script: AssertScript<'a, impl Iterator<Item = &'a SignedIntermediateState>>,
        assert_script_control_block: ControlBlock,
    ) -> Self {
        Self {
            inner,
            signature: taproot::Signature {
                signature: signature.into(),
                sighash_type: TapSighashType::Default,
            },
            assert_script: assert_script.into_script(),
            assert_script_control_block,
        }
    }

    /// Return signed transaction which is ready fo publishing.
    pub fn to_tx<C: Verification>(&self, ctx: &Secp256k1<C>) -> Transaction {
        let mut unsigned_tx = self.inner.to_unsigned_tx(ctx);

        let witness = &mut unsigned_tx.input[0].witness;

        let signed_states = extract_signed_states(&self.inner.disprove_scripts);

        /* Push witness stack */
        for state in signed_states.rev() {
            for element in state.witness_elements() {
                witness.push(element);
            }
        }
        witness.push(self.signature.serialize());

        /* Push script */
        witness.push(self.assert_script.clone());

        /* Push control block */
        witness.push(self.assert_script_control_block.serialize());

        unsigned_tx
    }

    pub fn payout_script(&self) -> &PayoutScript {
        &self.inner.payout_script
    }

    pub fn disprove_script(&self, idx: usize) -> &DisproveScript {
        &self.inner.disprove_scripts[idx]
    }

    pub fn payout_script_control_block<C: Verification>(&self, ctx: &Secp256k1<C>) -> ControlBlock {
        let script = self.inner.payout_script();

        let taptree = self.inner.taproot(ctx);

        taptree
            .control_block(&(script.to_script(), LeafVersion::TapScript))
            .expect("Payout script is included into taptree")
    }

    pub fn disprove_script_control_block<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        idx: usize,
    ) -> ControlBlock {
        let script = self.inner.disprove_scripts[idx].to_script_pubkey();

        let taptree = self.inner.taproot(ctx);

        taptree
            .control_block(&(script, LeafVersion::TapScript))
            .expect("Payout script is included into taptree")
    }
}
