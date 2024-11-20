//! Shared between transaction scripts

#![allow(non_snake_case)]

use bitcoin::XOnlyPublicKey;

use crate::treepp::*;

/// `CheckCovenant` from BitVM2 paper which accepts aggregated pubkey and
/// expects signature from top of the stack.
pub fn OP_CHECKCOVENANTVERIFY(agg_pubkey: XOnlyPublicKey) -> Script {    
    script! {
        { agg_pubkey }
        OP_CHECKSIGVERIFY
    }
}

/// `CheckCovenant` from BitVM2 paper which accepts aggregated pubkey and
/// expects signature from top of the stack.
pub fn OP_CHECKCOVENANT(agg_pubkey: XOnlyPublicKey) -> Script {
    script! {
        { agg_pubkey }
        OP_CHECKSIG
    }
}
