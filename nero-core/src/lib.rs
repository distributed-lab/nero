use std::iter;

use bitcoin::{
    key::{Secp256k1, Verification},
    TapSighash, XOnlyPublicKey,
};
use musig2::{
    secp256k1::{PublicKey, SecretKey, Signing},
    AggNonce, KeyAggContext, PartialSignature, SecNonce,
};
use once_cell::sync::Lazy;

pub use musig2;

pub mod assert;
pub mod challenge;
pub mod claim;
pub mod context;
pub mod disprove;
pub mod operator;
pub mod payout;
pub mod scripts;

#[allow(dead_code)]
// Re-export what is needed to write treepp scripts
pub mod treepp {
    pub use bitcoin_script::{define_pushable, script};
    pub use bitcoin_utils::debug::{execute_script, run};

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}

/// Unspendable key used in inner key of taproot addresses through protocol.
///
/// The definition you can find in BIP341.
pub(crate) static UNSPENDABLE_KEY: Lazy<XOnlyPublicKey> = Lazy::new(|| {
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        .parse()
        .unwrap()
});

pub(crate) fn schnorr_sign_partial<C: Verification + Signing>(
    ctx: &Secp256k1<C>,
    sighash: TapSighash,
    comittee_pubkeys: Vec<PublicKey>,
    agg_nonce: &AggNonce,
    secret_key: SecretKey,
    secnonce: SecNonce,
) -> PartialSignature {
    let mut pubkeys = iter::once(secret_key.public_key(ctx))
        .chain(comittee_pubkeys)
        .collect::<Vec<_>>();
    pubkeys.sort();
    let keyagg_ctx = KeyAggContext::new(pubkeys).unwrap();

    let partial_sig =
        musig2::sign_partial(&keyagg_ctx, secret_key, secnonce, agg_nonce, sighash).unwrap();

    partial_sig
}

#[cfg(test)]
mod tests {
    use crate::UNSPENDABLE_KEY;

    #[test]
    fn test_unspendable_key() {
        let _ = *UNSPENDABLE_KEY;
    }
}
