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

#[cfg(test)]
mod tests {
    use crate::{
        claim::scripts::AssertScript,
        disprove::{extract_signed_states, signing::SignedIntermediateState},
        treepp::*,
    };
    use bitcoin::{key::Secp256k1, taproot::LeafVersion, TapLeafHash, XOnlyPublicKey};
    use bitcoin_scriptexec::Stack;
    use bitcoin_splitter::split::{
        intermediate_state::IntermediateState,
        script::{IOPair, SplitableScript as _},
    };
    use bitcoin_testscripts::int_mul_windowed::U32MulScript;
    use bitcoin_utils::{comittee_signature, debug::execute_script_with_leaf};
    use rand::thread_rng;

    use crate::disprove::form_disprove_scripts;

    #[test]
    fn test_simple_singed_states_assert_script() {
        let secp_ctx = Secp256k1::new();
        let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());
        let xonly: XOnlyPublicKey = pubkey.into();

        let mut stack = Stack::new();
        stack.pushnum(8);

        let signed_states = &[SignedIntermediateState::sign(IntermediateState {
            stack,
            altstack: Stack::new(),
        })];

        let assert_script = AssertScript::new(xonly, signed_states.iter()).into_script();
        let leaf_hash = TapLeafHash::from_script(&assert_script, LeafVersion::TapScript);
        let sig = comittee_signature(&assert_script, &secp_ctx, seckey);

        let verify_script = script! {
            for state in signed_states.iter().rev() {
                { state.to_script_sig() }
            }
            { sig.serialize().to_vec() }
            { assert_script }
        };

        let result = execute_script_with_leaf(verify_script, leaf_hash);

        assert!(result.success, "Script failed:\n{result}");
    }

    #[test]
    fn test_u32mul_signed_states_assert_script() {
        // First, we generate the pair of input and output scripts
        let IOPair { input, output: _ } = U32MulScript::generate_valid_io_pair();

        let secp_ctx = Secp256k1::new();
        let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());
        let xonly: XOnlyPublicKey = pubkey.into();

        let disprove_scripts = form_disprove_scripts::<U32MulScript>(input, xonly);

        let signed_states = extract_signed_states(&disprove_scripts);

        let assert_script = AssertScript::new(xonly, signed_states).into_script();
        let leaf_hash = TapLeafHash::from_script(&assert_script, LeafVersion::TapScript);
        let sig = comittee_signature(&assert_script, &secp_ctx, seckey);

        let signed_states = extract_signed_states(&disprove_scripts);
        let verify_script = script! {
            for state in signed_states.rev() {
                { state.to_script_sig() }
            }
            { sig.serialize().to_vec() }
            { assert_script }
        };

        let result = execute_script_with_leaf(verify_script, leaf_hash);

        assert!(result.success, "Script failed:\n{result}");
    }
}
