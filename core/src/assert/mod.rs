use std::{collections::HashMap, iter, marker::PhantomData};

use bitcoin::{
    absolute::LockTime,
    ecdsa,
    key::{Keypair, Secp256k1},
    psbt::Input,
    relative::Height,
    secp256k1::{All, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Amount, EcdsaSighashType, OutPoint, Psbt, Sequence, TapSighashType, Transaction, TxIn, TxOut,
    Txid, Witness, XOnlyPublicKey,
};
use bitcoin_splitter::split::script::SplitableScript;

use crate::{
    assert::payout_script::PayoutScript, disprove::form_disprove_scripts_distorted, treepp::*,
    UNSPENDABLE_KEY,
};

use crate::disprove::{form_disprove_scripts, DisproveScript};

pub mod payout_script;

const DISPROVE_SCRIPT_WEIGHT: u32 = 1;
const PAYOUT_SCRIPT_WEIGHT: u32 = 5;

pub struct AssertTransaction<const I: usize, const O: usize, S: SplitableScript<I, O>> {
    /// Input of the program.
    pub input: Script,

    /// Operator's public key.
    pub operator_pubkey: XOnlyPublicKey,

    /// Amount staked for assertion.
    pub amount: Amount,

    pub disprove_scripts: Vec<DisproveScript>,
    pub payout_script: PayoutScript,

    /// Program this transaction asserts.
    __program: PhantomData<S>,
}

impl<const I: usize, const O: usize, S: SplitableScript<I, O>> Clone
    for AssertTransaction<I, O, S>
{
    fn clone(&self) -> Self {
        Self {
            input: self.input.clone(),
            operator_pubkey: self.operator_pubkey,
            amount: self.amount,
            disprove_scripts: self.disprove_scripts.clone(),
            payout_script: self.payout_script.clone(),
            __program: self.__program,
        }
    }
}

pub struct Options {
    pub payout_locktime: Height,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            payout_locktime: payout_script::LOCKTIME.into(),
        }
    }
}

impl<const I: usize, const O: usize, S: SplitableScript<I, O>> AssertTransaction<I, O, S> {
    /// Construct new Assert transaction.
    pub fn new(input: Script, operator_pubkey: XOnlyPublicKey, amount: Amount) -> Self {
        Self::with_options(input, operator_pubkey, amount, Default::default())
    }

    pub fn with_options(
        input: Script,
        operator_pubkey: XOnlyPublicKey,
        amount: Amount,
        options: Options,
    ) -> Self {
        let disprove_scripts = form_disprove_scripts::<I, O, S>(input.clone());
        let payout_script = PayoutScript::with_locktime(operator_pubkey, options.payout_locktime);
        Self {
            input,
            operator_pubkey,
            amount,
            disprove_scripts,
            payout_script,
            __program: PhantomData,
        }
    }

    pub fn with_options_distorted(
        input: Script,
        operator_pubkey: XOnlyPublicKey,
        amount: Amount,
        options: Options,
    ) -> (Self, usize) {
        let (disprove_scripts, idx) = form_disprove_scripts_distorted::<I, O, S>(input.clone());
        let payout_script = PayoutScript::with_locktime(operator_pubkey, options.payout_locktime);
        (
            Self {
                input,
                operator_pubkey,
                amount,
                disprove_scripts,
                payout_script,
                __program: PhantomData,
            },
            idx,
        )
    }

    /// Return partially signed transaction with P2TR output with all disprove
    /// scripts and payout script.
    pub fn into_psbt(self, ctx: &Secp256k1<All>) -> Psbt {
        let txout = self.txout(ctx);

        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![txout],
        };

        Psbt::from_unsigned_tx(tx)
            .expect("witness and script_sigs are not filled, so this should never panic")
    }

    pub fn txout(self, ctx: &Secp256k1<All>) -> TxOut {
        let taptree = self.form_taptree(ctx);

        self.assert_taproot_output(&taptree)
    }

    fn assert_taproot_output(&self, taptree: &TaprootSpendInfo) -> TxOut {
        let script_pubkey = Script::new_p2tr_tweaked(taptree.output_key());

        TxOut {
            value: self.amount,
            script_pubkey,
        }
    }

    fn form_taptree(&self, ctx: &Secp256k1<All>) -> TaprootSpendInfo {
        let scripts_with_weights =
            iter::once((PAYOUT_SCRIPT_WEIGHT, self.payout_script.clone().to_script())).chain(
                self.disprove_scripts
                    .clone()
                    .into_iter()
                    .map(|script| (DISPROVE_SCRIPT_WEIGHT, script.script_pubkey)),
            );

        TaprootBuilder::with_huffman_tree(scripts_with_weights)
            .expect("Weights are low, and number of scripts shoudn't create the tree greater than 128 in depth (I believe)")
            .finalize(ctx, *UNSPENDABLE_KEY)
            .expect("Scripts and keys should be valid")
    }

    /// Create Payout transaction which spends first output of Assert
    /// transaction using Payout script path.
    pub fn payout_transaction(
        &self,
        ctx: &Secp256k1<All>,
        txout: TxOut,
        txid: Txid,
        operator_seckey: &SecretKey,
    ) -> eyre::Result<Transaction> {
        let taptree = self.form_taptree(ctx);

        let script = self.payout_script.to_script();

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(txid, 0),
                script_sig: Script::new(),
                sequence: Sequence::from_height(self.payout_script.locktime.value()),
                witness: Witness::new(),
            }],
            output: vec![txout],
        };

        let leaf_hash = script.tapscript_leaf_hash();
        let prev_txout = self.assert_taproot_output(&taptree);

        let sighash = SighashCache::new(&tx).taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prev_txout]),
            leaf_hash,
            TapSighashType::Default,
        )?;

        let signature = ctx.sign_schnorr(
            &sighash.into(),
            &Keypair::from_secret_key(ctx, operator_seckey),
        );

        let control_block = &taptree
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap();

        let mut witness = Witness::new();
        witness.push(signature.as_ref());
        witness.push(self.operator_pubkey.serialize());
        witness.push(script.as_bytes());
        witness.push(control_block.serialize());

        tx.input[0].witness = witness;

        Ok(tx)
    }

    /// Create Payout transaction which spends first output of Assert
    /// transaction using Payout script path.
    pub fn disprove_transactions(
        &self,
        ctx: &Secp256k1<All>,
        txout: TxOut,
        txid: Txid,
    ) -> eyre::Result<HashMap<DisproveScript, Transaction>> {
        let taptree = self.form_taptree(ctx);
        let mut map = HashMap::with_capacity(self.disprove_scripts.len());

        for disprove in &self.disprove_scripts {
            let script = disprove.script_pubkey.clone();
            let mut witness = Witness::new();

            for elem in disprove.witness_elements() {
                witness.push(elem);
            }

            let control_block = &taptree
                .control_block(&(script.clone(), LeafVersion::TapScript))
                .unwrap();

            witness.push(script.as_bytes());
            witness.push(control_block.serialize());

            let tx = Transaction {
                version: Version::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::new(txid, 0),
                    script_sig: Script::new(),
                    sequence: Sequence::ZERO,
                    witness,
                }],
                output: vec![txout.clone()],
            };

            map.insert(disprove.clone(), tx);
        }

        Ok(map)
    }

    /// Create transaction which spends provided utxo (assuming that it's the
    /// P2WPKH one) signed with provided key.
    pub fn spend_p2wpkh_input_tx(
        self,
        ctx: &Secp256k1<All>,
        secret_key: &SecretKey,
        txout: TxOut,
        outpoint: OutPoint,
    ) -> eyre::Result<Transaction> {
        let mut psbt = self.into_psbt(ctx);

        psbt.unsigned_tx.input.push(TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        });

        let sighash = SighashCache::new(&psbt.unsigned_tx).p2wpkh_signature_hash(
            0,
            &txout.script_pubkey,
            txout.value,
            EcdsaSighashType::All,
        )?;

        let signature = ctx.sign_ecdsa(&sighash.into(), secret_key);

        let mut witness = Witness::new();

        // for disprove in disprove_scripts {
        //     for elem in disprove.witness_elements() {
        //         witness.push(elem);
        //     }
        // }
        witness.push_ecdsa_signature(&ecdsa::Signature::sighash_all(signature));
        witness.push(secret_key.public_key(ctx).serialize());

        psbt.inputs.push(Input {
            witness_utxo: Some(txout),
            final_script_witness: Some(witness),
            ..Default::default()
        });

        psbt.extract_tx().map_err(Into::into)
    }
}
