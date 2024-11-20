//! Provides challenge transaction.

use bitcoin::{
    absolute::LockTime,
    key::{Keypair, Parity, Secp256k1, Verification},
    secp256k1,
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness,
    XOnlyPublicKey,
};
use musig2::secp256k1::{SecretKey, Signing};

pub struct Challenge {
    /// ID of Claim transaction.
    claim_txid: Txid,

    /// Crowdfundedd amount in BTC required for operator to pay the fee for
    /// assert and disprove transaction.
    assert_tx_fee_amount: Amount,

    /// Public key of operator which will get
    /// [`Challenge::assert_tx_fee_amount`] after the challenge transcation is
    /// published.
    operator_pubkey: XOnlyPublicKey,
}

impl Challenge {
    pub fn new(operator: XOnlyPublicKey, claim_txid: Txid, assert_tx_fee_amount: Amount) -> Self {
        Self {
            claim_txid,
            assert_tx_fee_amount,
            operator_pubkey: operator,
        }
    }

    pub fn to_unsigned_tx<C>(&self, ctx: &Secp256k1<C>) -> Transaction
    where
        C: secp256k1::Verification,
    {
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
                script_pubkey: ScriptBuf::new_p2tr(ctx, self.operator_pubkey, None),
            }],
        }
    }

    pub fn sign<C: Signing + Verification>(
        self,
        ctx: &Secp256k1<C>,
        operator_seckey: &SecretKey,
        claim_challenge_txout: &TxOut,
    ) -> SignedChallenge {
        let unsigned_tx = self.to_unsigned_tx(ctx);
        let sighash_type = TapSighashType::SinglePlusAnyoneCanPay;
        let sighash = SighashCache::new(&unsigned_tx)
            .taproot_key_spend_signature_hash(
                /* challenge transaciton always has this first input */ 0,
                &Prevouts::One(
                    /* Challenge tx has only one input */ 0,
                    claim_challenge_txout,
                ),
                sighash_type,
            )
            .unwrap();

        let (xonly, parity) = operator_seckey.public_key(ctx).x_only_public_key();
        let operator_seckey = if parity == Parity::Odd {
            operator_seckey.negate()
        } else {
            *operator_seckey
        };

        let signature = ctx.sign_schnorr(
            &sighash.into(),
            &Keypair::from_secret_key(ctx, &operator_seckey),
        );

        ctx.verify_schnorr(&signature, &sighash.into(), &xonly)
            .unwrap();

        SignedChallenge::new(
            self,
            Signature {
                signature,
                sighash_type,
            },
        )
    }
}

pub struct SignedChallenge {
    /// Unsigned challenge transaciton.
    inner: Challenge,

    /// Signature of challenge transaction signed by operator's pubkey.
    signature: Signature,
}

impl SignedChallenge {
    pub(crate) fn new(inner: Challenge, signature: Signature) -> Self {
        Self { inner, signature }
    }

    pub fn to_tx<C: Verification>(&self, ctx: &Secp256k1<C>) -> Transaction {
        let mut unsigned_tx = self.inner.to_unsigned_tx(ctx);

        // add signature to tx, converting it to signed one.
        unsigned_tx.input[0]
            .witness
            .push(self.signature.serialize());

        unsigned_tx
    }
}
