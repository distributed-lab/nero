use bitcoin::{relative::Height, XOnlyPublicKey};
use bitcoin_script::script;
use bitcoin_winternitz::u32::N0;

use crate::disprove::signing::SignedIntermediateState;
use crate::scripts::{OP_CHECKCOVENANT, OP_CHECKCOVENANTVERIFY};
use crate::treepp::*;

/// Script which is spent in optimistic payout flow after challenge period
/// ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OptimisticPayoutScript {
    claim_challenge_period: Height,
    comittee_agg_pubkey: XOnlyPublicKey,
}

impl OptimisticPayoutScript {
    pub fn new(claim_challenge_period: Height, comittee_agg_pubkey: XOnlyPublicKey) -> Self {
        Self {
            claim_challenge_period,
            comittee_agg_pubkey,
        }
    }

    pub fn to_script(self) -> Script {
        script! {
            { self.claim_challenge_period.value() as i32 }
            OP_CSV
            OP_DROP
            { OP_CHECKCOVENANT(self.comittee_agg_pubkey) }
        }
    }
}

/// `AssertScript` from original BitVM2 paper. Checks from stack  all
/// Winternitz commitments for signed intermidiate states.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssertScript<'a, I>
where
    I: Iterator<Item = &'a SignedIntermediateState>,
{
    comittee_agg_pubkey: XOnlyPublicKey,
    states: I,
}

impl<'a, I> AssertScript<'a, I>
where
    I: Iterator<Item = &'a SignedIntermediateState>,
{
    pub fn new(comittee_agg_pubkey: XOnlyPublicKey, states: I) -> Self {
        Self {
            comittee_agg_pubkey,
            states,
        }
    }

    pub fn into_script(self) -> Script {
        script! {
            { OP_CHECKCOVENANTVERIFY(self.comittee_agg_pubkey) }
            for state in self.states {
                for element in &state.altstack {
                    { element.public_key.checksig_verify_script() }
                    // FIXME(Velnbur): in script above we copied and
                    // pushed the elements, but immidiaatle droped here.
                    // That's why we should create a separate script where
                    // we don't copy it on the stack and only check for
                    // existance.
                    for _ in 0..N0 {
                        OP_DROP
                    }
                }
                for element in state.stack.iter().rev() {
                    { element.public_key.checksig_verify_script() }
                    // FIXME(Velnbur): the same here
                    for _ in 0..N0 {
                        OP_DROP
                    }
                }
            }
            OP_TRUE
        }
    }
}
