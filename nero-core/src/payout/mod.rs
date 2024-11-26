use bitcoin::{
    absolute::LockTime, key::{Keypair, Parity, Secp256k1, Verification}, relative::Height, sighash::{Prevouts, SighashCache}, taproot::{ControlBlock, LeafVersion, Signature}, transaction::Version, Amount, OutPoint, Sequence, TapLeafHash, TapSighashType, TapTweakHash, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey
};
use bitcoin_splitter::split::script::SplitableScript;
use musig2::{
    secp256k1::{schnorr, PublicKey, SecretKey, Signing},
    AggNonce, PartialSignature, SecNonce,
};

use crate::{
    assert::Assert,
    claim::{
        scripts::OptimisticPayoutScript,
        FundedClaim,
    },
    context::Context,
    schnorr_sign_partial,
    scripts::OP_CHECKCOVENANT,
    treepp::*,
};

/// Assuming that mean block mining time is 10 minutes:
pub const LOCKTIME: u16 =  6 /* hour */ * 24 /* day */ * 14 /* two weeks */;

/// Script by which Operator spends the Assert transaction after timelock.
#[derive(Debug, Clone)]
pub struct PayoutScript {
    /// Comittee public keys
    pub comittee_aggpubkey: XOnlyPublicKey,
    /// Public key of the operator
    pub operator_pubkey: XOnlyPublicKey,

    /// Specified locktime after which assert transaction is spendable
    /// by payout script, default value is [`LOCKTIME`].
    pub locktime: Height,
}

impl PayoutScript {
    pub fn new(operator_pubkey: XOnlyPublicKey, comittee_aggpubkey: XOnlyPublicKey) -> Self {
        Self {
            operator_pubkey,
            comittee_aggpubkey,
            locktime: Height::from(LOCKTIME),
        }
    }

    pub fn with_locktime(
        operator_pubkey: XOnlyPublicKey,
        comittee_aggpubkey: XOnlyPublicKey,
        locktime: Height,
    ) -> Self {
        Self {
            operator_pubkey,
            comittee_aggpubkey,
            locktime,
        }
    }

    pub fn to_script(&self) -> Script {
        script! {
            { self.locktime.value() as u32 }
            OP_CSV
            OP_DROP
            { self.operator_pubkey }
            OP_CHECKSIGVERIFY
            { OP_CHECKCOVENANT(self.comittee_aggpubkey) }
        }
    }
}

pub struct PayoutOptimistic {
    /// Claim transaction id.
    claim_txid: Txid,

    /// Operator's pubkey for output.
    operator_script_pubkey: Script,

    /// Claim transaction challenge period.
    claim_challenge_period: Height,

    /// Stacked amount mentioned in paper as $d$.
    staked_amount: Amount,
}

impl PayoutOptimistic {
    pub fn from_context<S, C>(ctx: &Context<S, C>, claim_txid: Txid) -> Self
    where
        S: SplitableScript,
        C: Verification,
    {
        Self {
            operator_script_pubkey: ctx.operator_script_pubkey.clone(),
            claim_challenge_period: ctx.claim_challenge_period,
            staked_amount: ctx.staked_amount,
            claim_txid,
        }
    }

    pub fn to_unsigned_tx(&self) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(self.claim_txid, 0),
                    script_sig: Script::new(),
                    sequence: Sequence::from_height(self.claim_challenge_period.value()),
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint::new(self.claim_txid, 1),
                    script_sig: Script::new(),
                    sequence: Sequence::ZERO,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: self.staked_amount,
                script_pubkey: self.operator_script_pubkey.clone(),
            }],
        }
    }

    pub fn sign_partial_from_claim<C: Verification + Signing>(
        &self,
        ctx: &Secp256k1<C>,
        claim: &FundedClaim,
        comittee_pubkeys: Vec<PublicKey>,
        agg_nonce: &AggNonce,
        secret_key: SecretKey,
        secnonce: SecNonce,
    ) -> PartialSignature {
        let tx = claim.to_tx(ctx);
        let claim_assert_output = &tx.output[0];
        let claim_challenge_output = &tx.output[1];
        let claim_assert_script = claim.optimistic_payout_script();

        self.sign_partial(
            ctx,
            claim_assert_output,
            claim_challenge_output,
            &claim_assert_script,
            comittee_pubkeys,
            agg_nonce,
            secret_key,
            secnonce,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_partial<C: Verification + Signing>(
        &self,
        ctx: &Secp256k1<C>,
        claim_assert_output: &TxOut,
        claim_challenge_output: &TxOut,
        claim_assert_script: &OptimisticPayoutScript,
        comittee_pubkeys: Vec<PublicKey>,
        agg_nonce: &AggNonce,
        secret_key: SecretKey,
        secnonce: SecNonce,
    ) -> PartialSignature {
        let sighash = self.assert_sighash(
            claim_assert_output,
            claim_challenge_output,
            claim_assert_script,
        );

        schnorr_sign_partial(
            ctx,
            sighash,
            comittee_pubkeys,
            agg_nonce,
            secret_key,
            secnonce,
        )
    }

    /// Return sighash for assert output of Claim transaction.
    pub(crate) fn assert_sighash(
        &self,
        claim_assert_txout: &TxOut,
        claim_challenge_txout: &TxOut,
        claim_payout_script: &OptimisticPayoutScript,
    ) -> bitcoin::TapSighash {
        let leaf_hash =
            TapLeafHash::from_script(&claim_payout_script.to_script(), LeafVersion::TapScript);
        let unsigned_tx = self.to_unsigned_tx();
        SighashCache::new(&unsigned_tx)
            .taproot_script_spend_signature_hash(
                /* Payout optimisitc assert input is the first one */ 0,
                &Prevouts::All(&[claim_assert_txout, claim_challenge_txout]),
                leaf_hash,
                TapSighashType::All,
            )
            .unwrap()
    }

    pub fn sign_challenge_input<C: Verification + Signing>(
        &self,
        claim_assert_txout: &TxOut,
        claim_challenge_txout: &TxOut,
        ctx: &Secp256k1<C>,
        mut secret_key: SecretKey,
    ) -> schnorr::Signature {
        let unsigned_tx = self.to_unsigned_tx();
        let sighash = SighashCache::new(&unsigned_tx)
            .taproot_key_spend_signature_hash(
                /* Payout optimisitc challenge input is the second one */ 1,
                &Prevouts::All(&[claim_assert_txout, claim_challenge_txout]),
                TapSighashType::All,
            )
            .unwrap();

        let (xonly, parity) = secret_key.public_key(ctx).x_only_public_key();
        if parity == Parity::Odd {
            secret_key = secret_key.negate();
        }
        let tweak = TapTweakHash::from_key_and_tweak(xonly, None);
        secret_key = secret_key.add_tweak(&tweak.to_scalar()).unwrap();

        ctx.sign_schnorr(&sighash.into(), &Keypair::from_secret_key(ctx, &secret_key))
    }
}

pub struct SignedPayoutOptimistic {
    /// Unsigned payout transaction
    inner: PayoutOptimistic,

    /// Multisig created with comittee.
    covenants_sig: Signature,

    /// Operator's spending witness created by wallet.
    operator_sig: Signature,

    /// Script by which transaction will be spent
    script: Script,

    /// Control block with inclusion proof to payout script
    script_control_block: ControlBlock,
}

impl SignedPayoutOptimistic {
    pub fn new(
        inner: PayoutOptimistic,
        covenants_sig: impl Into<schnorr::Signature>,
        operator_sig: impl Into<schnorr::Signature>,
        script: &OptimisticPayoutScript,
        script_control_block: ControlBlock,
    ) -> Self {
        Self {
            inner,
            covenants_sig: Signature {
                signature: covenants_sig.into(),
                sighash_type: TapSighashType::All,
            },
            operator_sig: Signature {
                signature: operator_sig.into(),
                sighash_type: TapSighashType::All,
            },
            script: script.to_script(),
            script_control_block,
        }
    }

    pub fn to_tx(&self) -> Transaction {
        let mut unsigned_tx = self.inner.to_unsigned_tx();

        /* Fill assert output */
        let witness = &mut unsigned_tx.input[0].witness;
        witness.push(self.covenants_sig.serialize());
        witness.push(&self.script);
        witness.push(self.script_control_block.serialize());

        /* Fill challenge output */
        let witness = &mut unsigned_tx.input[1].witness;
        witness.push(self.operator_sig.serialize());

        unsigned_tx
    }
}

pub struct Payout {
    /// Assert transaction id.
    assert_txid: Txid,

    /// Operator's pubkey for output.
    operator_pubkey: XOnlyPublicKey,

    /// Assert transaction challenge period.
    assert_challenge_period: Height,

    /// Stacked amount mentioned in paper as $d$.
    staked_amount: Amount,
}

impl Payout {
    pub fn from_context<S, C>(ctx: &Context<S, C>, assert_txid: Txid) -> Self
    where
        S: SplitableScript,
        C: Verification,
    {
        Self {
            operator_pubkey: ctx.operator_pubkey.into(),
            assert_challenge_period: ctx.assert_challenge_period,
            staked_amount: ctx.staked_amount,
            assert_txid,
        }
    }

    pub fn to_unsigned_tx<C>(&self, ctx: &Secp256k1<C>) -> Transaction
    where
        C: Verification,
    {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(self.assert_txid, 0),
                script_sig: Script::new(),
                sequence: Sequence::from_height(self.assert_challenge_period.value()),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: self.staked_amount,
                script_pubkey: Script::new_p2tr(ctx, self.operator_pubkey, None),
            }],
        }
    }

    pub fn sign_partial_from_assert<C: Verification + Signing>(
        &self,
        ctx: &Secp256k1<C>,
        assert: &Assert,
        comittee_pubkeys: Vec<PublicKey>,
        agg_nonce: &AggNonce,
        secret_key: SecretKey,
        secnonce: SecNonce,
    ) -> PartialSignature {
        let assert_output = assert.output(ctx);

        self.sign_partial(
            ctx,
            &assert_output,
            assert.payout_script(),
            comittee_pubkeys,
            agg_nonce,
            secret_key,
            secnonce,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_partial<C: Verification + Signing>(
        &self,
        ctx: &Secp256k1<C>,
        assert_output: &TxOut,
        assert_payout: &PayoutScript,
        comittee_pubkeys: Vec<PublicKey>,
        agg_nonce: &AggNonce,
        secret_key: SecretKey,
        secnonce: SecNonce,
    ) -> PartialSignature {
        let sighash = self.sighash(ctx, assert_output, assert_payout);

        schnorr_sign_partial(
            ctx,
            sighash,
            comittee_pubkeys,
            agg_nonce,
            secret_key,
            secnonce,
        )
    }

    pub fn sign_operator<C: Verification + Signing>(
        &self,
        ctx: &Secp256k1<C>,
        assert_txout: &TxOut,
        assert_payout: &PayoutScript,
        seckey: &SecretKey,
    ) -> Signature {
        let unsigned_tx = self.to_unsigned_tx(ctx);
        let leaf_hash = TapLeafHash::from_script(&assert_payout.to_script(), LeafVersion::TapScript);
        let sighash_type = TapSighashType::SinglePlusAnyoneCanPay;

        let sighash = SighashCache::new(&unsigned_tx)
            .taproot_script_spend_signature_hash(
                /* Payout is signed fully and should have only one input */ 0,
                &Prevouts::All(&[assert_txout]),
                leaf_hash,
                sighash_type,
            )
            .unwrap();

        let signature = ctx.sign_schnorr(&sighash.into(), &Keypair::from_secret_key(ctx, seckey));

        Signature {
            signature,
            sighash_type,
        }
    }

    pub(crate) fn sighash<C: Verification>(
        &self,
        ctx: &Secp256k1<C>,
        assert_output: &TxOut,
        assert_payout_script: &PayoutScript,
    ) -> bitcoin::TapSighash {
        let unsigned_tx = self.to_unsigned_tx(ctx);
        let leaf_hash = TapLeafHash::from_script(
            &assert_payout_script.to_script(),
            LeafVersion::TapScript,
        );

        SighashCache::new(&unsigned_tx)
            .taproot_script_spend_signature_hash(
                /* assert output with taproot should be first */ 0,
                &Prevouts::All(&[assert_output]),
                leaf_hash,
                TapSighashType::All,
            )
            .unwrap()
    }
}

pub struct SignedPayout {
    inner: Payout,

    payout_script: PayoutScript,
    payout_control_block: ControlBlock,

    /// Covenant signature created with comittee
    covenants_sig: Signature,
    /// Operator's signature.
    operators_sig: Signature,
}

impl SignedPayout {
    pub fn new(
        inner: Payout,
        payout_script: PayoutScript,
        payout_control_block: ControlBlock,
        covenants_sig: impl Into<schnorr::Signature>,
        operators_sig: Signature,
    ) -> Self {
        Self {
            inner,
            payout_script,
            payout_control_block,
            covenants_sig: Signature {
                signature: covenants_sig.into(),
                sighash_type: TapSighashType::All,
            },
            operators_sig,
        }
    }

    pub fn to_tx<C: Verification>(&self, ctx: &Secp256k1<C>) -> Transaction {
        let mut unsigned_tx = self.inner.to_unsigned_tx(ctx);

        let witness = &mut unsigned_tx.input[0].witness;

        /* Push stack elements */
        witness.push(self.covenants_sig.serialize());
        witness.push(self.operators_sig.serialize());
        /* script */
        witness.push(self.payout_script.to_script());
        /* control block */
        witness.push(self.payout_control_block.serialize());

        unsigned_tx
    }
}
