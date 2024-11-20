use std::iter;

use bitcoin::{
    absolute::LockTime,
    key::{constants::SCHNORR_SIGNATURE_SIZE, Secp256k1, Verification},
    relative::Height,
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut,
    Txid, Weight, Witness, XOnlyPublicKey,
};
use musig2::{
    secp256k1::{schnorr::Signature, PublicKey, SecretKey, Signing},
    AggNonce, PartialSignature, SecNonce,
};

use crate::{
    claim::FundedClaim,
    disprove::DisproveScript,
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
            iter::once((PAYOUT_SCRIPT_WEIGHT, self.payout_script.to_script_pubkey())).chain(
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
        let taproot = self.taproot(ctx);

        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(self.claim_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: self.staked_amount,
                script_pubkey: ScriptBuf::new_p2tr_tweaked(taproot.output_key()),
            }],
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
        let claim_assert_leaf_hash =
            TapLeafHash::from_script(&claim.assert_script(), LeafVersion::TapScript);

        self.sign_partial(
            ctx,
            claim_assert_output,
            claim_assert_leaf_hash,
            comittee_pubkeys,
            agg_nonce,
            secret_key,
            secnonce,
        )
    }

    // Let's reconsider the number of parameters later.
    #[allow(clippy::too_many_arguments)]
    /// Partially sign transaction using operator's key.
    pub fn sign_partial<C: Verification + Signing>(
        &self,
        ctx: &Secp256k1<C>,
        claim_assert_output: &TxOut,
        claim_assert_leaf_hash: TapLeafHash,
        comittee_pubkeys: Vec<PublicKey>,
        agg_nonce: &AggNonce,
        secret_key: SecretKey,
        secnonce: SecNonce,
    ) -> PartialSignature {
        let sighash = self.sighash(ctx, claim_assert_output, claim_assert_leaf_hash);

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
    pub(crate) fn sighash<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        claim_assert_output: &TxOut,
        claim_assert_leaf_hash: TapLeafHash,
    ) -> bitcoin::TapSighash {
        let unsigned_tx = self.to_unsigned_tx(ctx);

        SighashCache::new(&unsigned_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[claim_assert_output]),
                claim_assert_leaf_hash,
                TapSighashType::Default,
            )
            .unwrap()
    }

    pub fn payout_script(&self) -> ScriptBuf {
        self.payout_script.to_script_pubkey()
    }
}

pub struct SignedAssert {
    inner: Assert,
    signature: Signature,
    assert_script: ScriptBuf,
    assert_script_control_block: ControlBlock,
}

impl SignedAssert {
    pub fn new(
        inner: Assert,
        signature: impl Into<Signature>,
        assert_script: ScriptBuf,
        assert_script_control_block: ControlBlock,
    ) -> Self {
        Self {
            inner,
            signature: signature.into(),
            assert_script,
            assert_script_control_block,
        }
    }

    /// Return signed transaction which is ready fo publishing.
    pub fn to_tx<C: Verification>(&self, ctx: &Secp256k1<C>) -> Transaction {
        let mut unsigned_tx = self.inner.to_unsigned_tx(ctx);

        let witness = &mut unsigned_tx.input[0].witness;

        /* Push witness stack */
        // Don't forget that this is a signature without hash type, as it's
        // default one.
        witness.push(self.signature.serialize());

        for disprove in &self.inner.disprove_scripts {
            for element in disprove.to_witness_stack_elements() {
                witness.push(element);
            }
        }

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
            .control_block(&(script, LeafVersion::TapScript))
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
