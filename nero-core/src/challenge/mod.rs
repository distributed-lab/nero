//! Provides challenge transaction.

use bitcoin::{
    absolute::LockTime,
    key::{Keypair, Parity, Secp256k1},
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, TapTweakHash, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use musig2::secp256k1::{schnorr, SecretKey, Signing};

const SIGHASHTYPE: TapSighashType = TapSighashType::SinglePlusAnyoneCanPay;

pub struct Challenge {
    /// ID of Claim transaction.
    claim_txid: Txid,

    /// Crowdfundedd amount in BTC required for operator to pay the fee for
    /// assert and disprove transaction.
    assert_tx_fee_amount: Amount,

    /// Public key of operator which will get
    /// [`Challenge::assert_tx_fee_amount`] after the challenge transcation is
    /// published.
    operator_script_pubkey: ScriptBuf,
}

impl Challenge {
    pub fn new(operator: ScriptBuf, claim_txid: Txid, assert_tx_fee_amount: Amount) -> Self {
        Self {
            claim_txid,
            assert_tx_fee_amount,
            operator_script_pubkey: operator,
        }
    }

    pub fn to_unsigned_tx(&self) -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(self.claim_txid, 1),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: self.assert_tx_fee_amount,
                script_pubkey: self.operator_script_pubkey.clone(),
            }],
        }
    }

    pub fn sign<C: Signing>(
        self,
        ctx: &Secp256k1<C>,
        claim_challenge_txout: &TxOut,
        mut operator_seckey: SecretKey,
    ) -> SignedChallenge {
        let unsigned_tx = self.to_unsigned_tx();
        const INPUT_INDEX: usize = /* challenge has only one input */ 0;
        let sighash = SighashCache::new(unsigned_tx)
            .taproot_key_spend_signature_hash(
                INPUT_INDEX,
                &Prevouts::All(&[claim_challenge_txout]),
                SIGHASHTYPE,
            )
            .unwrap();

        let (xonly, parity) = operator_seckey.public_key(ctx).x_only_public_key();
        if parity == Parity::Odd {
            operator_seckey = operator_seckey.negate();
        }
        let tweak = TapTweakHash::from_key_and_tweak(xonly, None);
        operator_seckey = operator_seckey.add_tweak(&tweak.to_scalar()).unwrap();

        let sig = ctx.sign_schnorr(
            &sighash.into(),
            &Keypair::from_secret_key(ctx, &operator_seckey),
        );

        SignedChallenge::new(self, sig)
    }
}

pub struct SignedChallenge {
    /// Unsigned challenge transaciton.
    inner: Challenge,

    /// Operator's signature for Single + AnyoneCanPay
    operators_sig: Signature,
}

impl SignedChallenge {
    pub(crate) fn new(inner: Challenge, sig: impl Into<schnorr::Signature>) -> Self {
        Self {
            inner,
            operators_sig: Signature {
                signature: sig.into(),
                sighash_type: SIGHASHTYPE,
            },
        }
    }

    pub fn to_tx(&self) -> Transaction {
        let mut unsigned_tx = self.inner.to_unsigned_tx();

        // add signature to tx, converting it to signed one.
        let witness = &mut unsigned_tx.input[0].witness;
        witness.push(self.operators_sig.serialize());

        unsigned_tx
    }
}
