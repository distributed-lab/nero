//! Provides challenge transaction.

use bitcoin::{
    absolute::LockTime,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

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
}

pub struct SignedChallenge {
    /// Unsigned challenge transaciton.
    inner: Challenge,

    /// Wintess for Single + AnyoneCanPay input.
    input_witness: Witness,
}

impl SignedChallenge {
    pub(crate) fn new(inner: Challenge, witness: Witness) -> Self {
        Self {
            inner,
            input_witness: witness,
        }
    }

    pub fn to_tx(&self) -> Transaction {
        let mut unsigned_tx = self.inner.to_unsigned_tx();

        // add signature to tx, converting it to signed one.
        unsigned_tx.input[0].witness = self.input_witness.clone();

        unsigned_tx
    }
}
