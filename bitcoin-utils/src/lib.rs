use bitcoin::{
    key::{Keypair, Parity, Secp256k1},
    secp256k1::{All, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, Signature},
    TapLeafHash, TapSighashType, Transaction, TxOut,
};
use bitcoin_scriptexec::Stack;
use treepp::*;

pub mod comparison;
pub mod debug;
pub mod pseudo;

#[allow(dead_code)]
// Re-export what is needed to write treepp scripts
pub mod treepp {
    pub use crate::debug::{execute_script, run};
    pub use bitcoin_script::{define_pushable, script};

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}

/// Converts a stack to a script that pushes all elements of the stack
pub fn stack_to_script(stack: &Stack) -> Script {
    script! {
        for element in stack.iter_str() {
            { element.to_vec() }
        }
    }
}

pub fn comittee_signature(
    disprove_script: &Script,
    secp_ctx: &Secp256k1<All>,
    mut seckey: SecretKey,
) -> Signature {
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    let sighash = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::<&TxOut>::All(&[]),
            TapLeafHash::from_script(disprove_script, LeafVersion::TapScript),
            TapSighashType::All,
        )
        .unwrap();

    if seckey.public_key(secp_ctx).x_only_public_key().1 == Parity::Even {
        seckey = seckey.negate();
    }

    let signature = secp_ctx.sign_schnorr(
        &sighash.into(),
        &Keypair::from_secret_key(secp_ctx, &seckey),
    );

    Signature {
        signature,
        sighash_type: TapSighashType::All,
    }
}
