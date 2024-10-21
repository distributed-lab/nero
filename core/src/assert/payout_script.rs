use bitcoin::{
    hashes::{hash160::Hash as Hash160, Hash},
    relative::Height,
    XOnlyPublicKey,
};

use crate::treepp::*;

/// Assuming that mean block mining time is 10 minutes:
pub const LOCKTIME: u16 =  6 /* hour */ * 24 /* day */ * 14 /* two weeks */;

/// Script by which Operator spends the Assert transaction after timelock.
#[derive(Debug, Clone)]
pub struct PayoutScript {
    // TODO(Velnbur): add mutisig of the comittee.
    // pub comittee_pubkeys: Vec<PublicKey>,
    /// Public key of the operator
    pub operator_pubkey: XOnlyPublicKey,

    /// Specified locktime after which assert transaction is spendable
    /// by payout script, default value is [`LOCKTIME`].
    pub locktime: Height,
}

impl PayoutScript {
    pub fn new(operator_pubkey: XOnlyPublicKey) -> Self {
        Self {
            operator_pubkey,
            locktime: Height::from(LOCKTIME),
        }
    }

    pub fn with_locktime(operator_pubkey: XOnlyPublicKey, locktime: Height) -> Self {
        Self {
            operator_pubkey,
            locktime,
        }
    }

    pub fn to_script(&self) -> Script {
        script! {
            { self.locktime.value() as u32 }
            OP_CSV
            OP_DROP
            OP_DUP
            OP_HASH160
            {
                Hash160::hash(
                    &self.operator_pubkey.serialize()
                ).as_byte_array().to_vec()
            }
            OP_EQUALVERIFY
            OP_CHECKSIG
        }
    }
}
