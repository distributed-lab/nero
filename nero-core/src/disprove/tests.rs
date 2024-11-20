use crate::disprove::{form_disprove_scripts_distorted, DisproveScript};

use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::SecretKey,
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, Signature},
    TapLeafHash, TapSighashType, Transaction, TxOut,
};
use bitcoin_splitter::split::{
    core::SplitType,
    intermediate_state::IntermediateState,
    script::{IOPair, SplitableScript},
};
use bitcoin_testscripts::{
    bitvm::bn254::{fp254impl::Fp254Impl, fq::Fq},
    int_mul_windowed::U254MulScript,
    square_fibonacci::SquareFibonacciScript,
};
use bitcoin_utils::stack_to_script;
use bitcoin_utils::{comparison::OP_LONGEQUALVERIFY, treepp::*};
use bitcoin_window_mul::{bigint::U508, traits::comparable::Comparable};
use musig2::secp256k1::All;
use rand::thread_rng;

use crate::{disprove::form_disprove_scripts, disprove::signing::SignedIntermediateState};

#[test]
pub fn test_stack_sign_and_verify() {
    let a: u32 = (1 << 31) - 1;
    // Define the test intermediate state
    let state = IntermediateState::from_input_script(
        &script! {},
        &script! {
            { a } OP_3 OP_4
        },
    );

    // Now, we sign the state
    let signed_state = SignedIntermediateState::sign(state);

    // Check that witness + verification scripts are correct
    let verify_script = script! {
        { signed_state.to_script_sig() }
        { signed_state.verification_script() }
        OP_4 OP_EQUALVERIFY
        OP_3 OP_EQUALVERIFY
        { a } OP_EQUALVERIFY
        OP_TRUE
    };

    let result = execute_script(verify_script);
    assert!(result.success, "Verification failed");
}

#[test]
pub fn test_zero_stack_sign_and_verify() {
    // Define the test intermediate state
    let state = IntermediateState::from_input_script(
        &script! {},
        &script! {
            for _ in 0..30 {
                OP_0
            }
        },
    );

    // Now, we sign the state
    let signed_state = SignedIntermediateState::sign(state);

    // Check that witness + verification scripts are correct
    let verify_script = script! {
        { signed_state.to_script_sig() }
        { signed_state.verification_script() }
        for _ in 0..30 {
            OP_0 OP_EQUALVERIFY
        }
        OP_TRUE
    };

    let result = execute_script(verify_script);
    assert!(result.success, "Verification failed");
}

#[test]
pub fn test_stack_sign_and_verify_with_altstack() {
    // Define the test intermediate state
    let state = IntermediateState::from_input_script(
        &script! {},
        &script! {
            { 2345 } OP_3 { 1636 }
            OP_5 OP_TOALTSTACK
            OP_6 OP_TOALTSTACK
            OP_7 OP_TOALTSTACK
        },
    );

    // Now, we sign the state
    let signed_state = SignedIntermediateState::sign(state);

    // Check that witness + verification scripts are correct
    let verify_script = script! {
        { signed_state.to_script_sig() }
        { signed_state.verification_script() }
        { 1636 } OP_EQUALVERIFY
        OP_3 OP_EQUALVERIFY
        { 2345 } OP_EQUALVERIFY
        OP_FROMALTSTACK OP_7 OP_EQUALVERIFY
        OP_FROMALTSTACK OP_6 OP_EQUALVERIFY
        OP_FROMALTSTACK OP_5 OP_EQUALVERIFY
        OP_TRUE
    };

    let result = execute_script(verify_script);
    assert!(result.success, "Verification failed");
}

#[test]
pub fn test_stack_sign_and_verify_bigint() {
    // First, we generate the pair of input and output scripts
    let IOPair { input, output: _ } = U254MulScript::generate_valid_io_pair();

    // Splitting the script into shards
    let split_result = U254MulScript::default_split(input, SplitType::ByInstructions);

    for (i, intermediate_state) in split_result.intermediate_states.into_iter().enumerate() {
        // Now, we sign the state
        let signed_state = SignedIntermediateState::sign(intermediate_state.clone());

        // Check that witness + verification scripts are correct
        let verify_script = script! {
            { signed_state.to_script_sig() }
            { signed_state.verification_script() }
            { stack_to_script(&intermediate_state.stack) }
            { OP_LONGEQUALVERIFY(signed_state.stack.len()) }
            OP_TRUE
        };

        let result = execute_script(verify_script);
        assert!(result.success, "Verification {:?} failed", i);
    }
}

#[test]
pub fn test_trivial_disprove_script_success() {
    // Define the following setup:
    // Transition function: OP_ADD
    // From: {3, 4}
    // To:   Should be { 7 }, but we have { 8 }
    let state_from = IntermediateState::from_input_script(
        &script! {},
        &script! {
            OP_3 OP_4
        },
    );
    let state_to = IntermediateState::from_input_script(
        &script! {},
        &script! {
            OP_8
        },
    );
    let function = script! {
        OP_ADD
    };

    let secp_ctx = Secp256k1::new();
    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    // Now, form the disprove script
    let disprove_script =
        DisproveScript::new(state_from, state_to, function, pubkey.x_only_public_key().0);
    let signature = comittee_signature(&disprove_script, &secp_ctx, seckey);

    // Check that witness + verification scripts are satisfied
    let verify_script = script! {
        { disprove_script.to_script_sig(signature) }
        { disprove_script.to_script_pubkey() }
    };

    let result = execute_script(verify_script);
    assert!(result.success, "Verification failed");
}

fn comittee_signature(
    disprove_script: &DisproveScript,
    secp_ctx: &Secp256k1<All>,
    seckey: SecretKey,
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
            TapLeafHash::from_script(&disprove_script.to_script_pubkey(), LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap();

    let signature = secp_ctx.sign_schnorr(
        &sighash.into(),
        &Keypair::from_secret_key(secp_ctx, &seckey),
    );

    Signature {
        signature,
        sighash_type: TapSighashType::Default,
    }
}

#[test]
pub fn test_trivial_disprove_script_should_fail() {
    // Define the following setup:
    // Transition function: OP_ADD
    // From: {3, 4}
    // To:   Should be { 7 }, but we have { 8 }
    let state_from = IntermediateState::from_input_script(
        &script! {},
        &script! {
            OP_3 OP_4
        },
    );
    let state_to = IntermediateState::from_input_script(
        &script! {},
        &script! {
            OP_7
        },
    );
    let function = script! {
        OP_ADD
    };

    let secp_ctx = Secp256k1::new();
    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    // Now, form the disprove script
    let disprove_script = DisproveScript::new(state_from, state_to, function, pubkey);
    let signature = comittee_signature(&disprove_script, &secp_ctx, seckey);

    // Check that witness + verification scripts are satisfied
    let verify_script = script! {
        { disprove_script.to_script_sig(signature) }
        { disprove_script.to_script_pubkey() }
    };

    let result = execute_script(verify_script);
    println!("{:?}", stack_to_script(&result.main_stack).to_asm_string());
    assert!(!result.success, "Verification failed");
}

#[test]
pub fn test_disprove_script_with_altstack_should_fail() {
    // Define the following setup:
    // Transition function: {OP_ADD OP_TOALTSTACK OP_TOALTSTACK}
    // From: { mainstack: { 1, 2, 3, 4, 5 }, altstack: { } }
    // To:   { mainstack: { 1, 2 }, altstack: { 9, 3 } }
    let state_from = IntermediateState::from_input_script(
        &script! {},
        &script! {
            OP_1 OP_2 OP_3 OP_4 OP_5
        },
    );
    let state_to = IntermediateState::from_input_script(
        &script! {},
        &script! {
            OP_1 OP_2 OP_9 OP_TOALTSTACK OP_3 OP_TOALTSTACK
        },
    );
    let function = script! {
        OP_ADD OP_TOALTSTACK OP_TOALTSTACK
    };

    let secp_ctx = Secp256k1::new();
    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    // Now, form the disprove script
    let disprove_script = DisproveScript::new(state_from, state_to, function, pubkey);
    let signature = comittee_signature(&disprove_script, &secp_ctx, seckey);

    // Check that witness + verification scripts are satisfied
    let verify_script = script! {
        { disprove_script.to_script_sig(signature) }
        { disprove_script.to_script_pubkey() }
    };

    let result = execute_script(verify_script);

    assert!(!result.success, "Verification failed");
}

#[test]
pub fn test_disprove_script_with_altstack_success() {
    // Define the following setup:
    // Transition function: {OP_ADD OP_TOALTSTACK OP_TOALTSTACK}
    // From: { mainstack: { 1, 2, 3, 4, 5 }, altstack: { } }
    // To:   { mainstack: { 1, 2 }, altstack: { 9, 3 } }
    let state_from = IntermediateState::from_input_script(
        &script! {},
        &script! {
            OP_1 OP_2 OP_3 OP_4 OP_5
        },
    );
    let state_to = IntermediateState::from_input_script(
        &script! {},
        &script! {
            OP_10 OP_2 OP_9 OP_TOALTSTACK OP_3 OP_TOALTSTACK
        },
    );
    let function = script! {
        OP_ADD OP_TOALTSTACK OP_TOALTSTACK
    };

    let secp_ctx = Secp256k1::new();
    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    // Now, form the disprove script
    let disprove_script = DisproveScript::new(state_from, state_to, function, pubkey);
    let signature = comittee_signature(&disprove_script, &secp_ctx, seckey);

    // Check that witness + verification scripts are satisfied
    let verify_script = script! {
        { disprove_script.to_script_sig(signature) }
        { disprove_script.to_script_pubkey() }
    };

    let result = execute_script(verify_script);

    assert!(result.success, "Verification failed");
}

#[test]
pub fn test_disprove_script_with_altstack_2() {
    // Define the following setup:
    // Transition function: { OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_TOALTSTACK }
    // From: { mainstack: { 1, 2, 3 }, altstack: { 4, 5 } }
    // To:   { mainstack: { 1 }, altstack: { 4, 8, 2 } }
    let state_from = IntermediateState::from_input_script(
        &script! {},
        &script! {
            OP_1 OP_2 OP_3 OP_4 OP_TOALTSTACK OP_5 OP_TOALTSTACK
        },
    );
    let state_to = IntermediateState::from_input_script(
        &script! {},
        &script! {
            OP_1 OP_4 OP_TOALTSTACK OP_8 OP_TOALTSTACK OP_2 OP_TOALTSTACK
        },
    );
    let function = script! {
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK OP_TOALTSTACK
    };

    let secp_ctx = Secp256k1::new();
    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    // Now, form the disprove script
    let disprove_script = DisproveScript::new(state_from, state_to, function, pubkey);
    let signature = comittee_signature(&disprove_script, &secp_ctx, seckey);

    // Check that witness + verification scripts are satisfied
    let verify_script = script! {
        { disprove_script.to_script_sig(signature) }
        { disprove_script.to_script_pubkey() }
    };

    let result = execute_script(verify_script);

    assert!(!result.success, "Verification failed");
}

#[test]
pub fn test_disprove_script_mul_script() {
    // First, we generate the pair of input and output scripts
    let IOPair { input, output } = U254MulScript::generate_invalid_io_pair();

    // Splitting the script into shards
    let split_result = U254MulScript::default_split(input, SplitType::ByInstructions);

    // Checking the last state (which must be equal to the result of the multiplication)
    let last_state = split_result.must_last_state();

    // The element of the mainstack must be equal to the actual output
    let verification_script = script! {
        { stack_to_script(&last_state.stack) }
        { output }
        { U508::OP_EQUAL(0, 1) }
    };

    let result = execute_script(verification_script);
    assert!(!result.success, "verification has failed");

    let secp_ctx = Secp256k1::new();
    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    // Now, we form the disprove script for each shard
    for i in 0..(split_result.shards.len() - 1) {
        let disprove_script = DisproveScript::new(
            split_result.intermediate_states[i].clone(),
            split_result.intermediate_states[i + 1].clone(),
            split_result.shards[i + 1].clone(),
            pubkey,
        );

        // Now, form the disprove script
        let signature = comittee_signature(&disprove_script, &secp_ctx, seckey);

        // Check that witness + verification scripts are satisfied
        let verify_script = script! {
            { disprove_script.to_script_sig(signature) }
            { disprove_script.to_script_pubkey() }
        };

        let result = execute_script(verify_script);
        assert!(!result.success, "Verification {:?} failed", i + 1);
    }
}

#[test]
pub fn test_disprove_script_fibonacci_script_invalid_input() {
    // The number of steps for the Fibonacci script
    const STEPS: usize = 64;

    // First, we generate the pair of input and output scripts
    let IOPair { input, output } = SquareFibonacciScript::<STEPS>::generate_invalid_io_pair();

    // Splitting the script into shards
    let split_result =
        SquareFibonacciScript::<STEPS>::default_split(input, SplitType::ByInstructions);

    // Checking the last state (which must be equal to the result of the multiplication)
    let last_state = split_result.must_last_state();

    // The element of the mainstack must be equal to the actual output
    let verification_script = script! {
        { stack_to_script(&last_state.stack) }
        { output }
        { Fq::equal(0, 1) }
    };

    let result = execute_script(verification_script);
    assert!(!result.success, "verification has failed");

    let secp_ctx = Secp256k1::new();
    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    // Now, we form the disprove script for each shard
    for i in 0..(split_result.shards.len() - 1) {
        let disprove_script = DisproveScript::new(
            split_result.intermediate_states[i].clone(),
            split_result.intermediate_states[i + 1].clone(),
            split_result.shards[i + 1].clone(),
            pubkey,
        );

        // Now, form the disprove script
        let signature = comittee_signature(&disprove_script, &secp_ctx, seckey);

        // Check that witness + verification scripts are satisfied
        let verify_script = script! {
            { disprove_script.to_script_sig(signature) }
            { disprove_script.to_script_pubkey() }
        };

        let result = execute_script(verify_script);
        assert!(!result.success, "Verification {:?} failed", i + 1);
    }
}

#[test]
pub fn test_disprove_script_fibonacci_script_valid_input() {
    // The number of steps for the Fibonacci script
    const STEPS: usize = 64;

    // First, we generate the pair of input and output scripts
    let IOPair { input, output: _ } = SquareFibonacciScript::<STEPS>::generate_valid_io_pair();

    // Splitting the script into shards
    let split_result =
        SquareFibonacciScript::<STEPS>::default_split(input, SplitType::ByInstructions);

    let secp_ctx = Secp256k1::new();
    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    // Now, we form the disprove script for each shard
    for i in 0..(split_result.shards.len() - 1) {
        let disprove_script = DisproveScript::new(
            split_result.intermediate_states[i].clone(),
            split_result.intermediate_states[i + 1].clone(),
            split_result.shards[i + 1].clone(),
            pubkey,
        );

        // Now, form the disprove script
        let signature = comittee_signature(&disprove_script, &secp_ctx, seckey);

        // Check that witness + verification scripts are satisfied
        let verify_script = script! {
            { disprove_script.to_script_sig(signature) }
            { disprove_script.to_script_pubkey() }
        };

        let result = execute_script(verify_script);
        assert!(!result.success, "Verification {:?} failed", i + 1);
    }
}

#[test]
pub fn test_distorted_disprove_script_fibonacci_sequence() {
    // The number of steps for the Fibonacci script
    const STEPS: usize = 64;
    type FibonacciScript = SquareFibonacciScript<STEPS>;

    // First, we generate the pair of input and output scripts
    let IOPair { input, output: _ } = FibonacciScript::generate_valid_io_pair();

    let secp_ctx = Secp256k1::new();
    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    // Splitting the script into shards
    let (disprove_scripts, distorted_id) =
        form_disprove_scripts_distorted::<FibonacciScript>(input.clone(), pubkey.into());

    println!("Distorted ID: {:?}", distorted_id);

    // Now, we form the disprove script for each shard
    for (i, disprove_script) in disprove_scripts.into_iter().enumerate() {
        // Now, form the disprove script
        let signature = comittee_signature(&disprove_script, &secp_ctx, seckey);

        // Check that witness + verification scripts are satisfied only for the distorted shard
        let verify_script = script! {
            { disprove_script.to_script_sig(signature) }
            { disprove_script.to_script_pubkey() }
        };

        let result = execute_script(verify_script);

        if i == distorted_id || i == distorted_id + 1 {
            assert!(result.success, "Verification {:?} failed", i + 1);
        } else {
            assert!(!result.success, "Verification {:?} failed", i + 1);
        }
    }
}

#[test]
pub fn test_disprove_script_batch_correctness() {
    // First, we generate the pair of input and output scripts
    let IOPair { input, output: _ } = U254MulScript::generate_valid_io_pair();

    let secp_ctx = Secp256k1::new();
    let (seckey, pubkey) = secp_ctx.generate_keypair(&mut thread_rng());

    // Splitting the script into shards
    let disprove_scripts = form_disprove_scripts::<U254MulScript>(input.clone(), pubkey.into());

    // Now, we form the disprove script for each shard
    for (i, disprove_script) in disprove_scripts.into_iter().enumerate() {
        // Now, form the disprove script
        let signature = comittee_signature(&disprove_script, &secp_ctx, seckey);

        // Check that witness + verification scripts are satisfied only for the distorted shard
        let verify_script = script! {
            { disprove_script.to_script_sig(signature) }
            { disprove_script.to_script_pubkey() }
        };

        let result = execute_script(verify_script);
        assert!(!result.success, "Verification {:?} failed", i + 1);
    }
}
