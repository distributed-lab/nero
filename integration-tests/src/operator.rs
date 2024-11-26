use bitcoin::{
    key::{
        rand::{rngs::StdRng, thread_rng},
        Secp256k1,
    },
    relative::Height,
    Address, Amount, FeeRate, Network, PrivateKey, ScriptBuf,
};
use bitcoin_splitter::split::script::{IOPair, SplitableScript};
use bitcoin_testscripts::int_mul_windowed::U32MulScript;
use jsonrpc::Client;
use nero_core::{
    musig2::{NonceSeed, SecNonce},
    operator::{
        ChallengeSigningOperator, FinalOperator, NoncesAggregationOperator, Operator,
        OperatorConfig, PartialSignatures, SignaturesAggOperator, UnfundedOperator,
    },
};
use once_cell::sync::Lazy;

use crate::common::{
    fund_raw_transaction, generate_to_address, init_client, init_wallet, send_raw_transaciton,
    sign_raw_transaction_with_wallet,
};

const CLAIM_CHALLENGE_PERIOD: u16 = 6;
const ASSERT_CHALLENGE_PERIOD: u16 = 6;
const FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(5);

/// In tests we are assuming the comitte consists of 1 participant.
static COMITTEE_PRIVATE_KEY: Lazy<PrivateKey> = Lazy::new(|| {
    "cNMMXcLoM65N5GaULU7ct2vexmQnJ5i5j3Sjc6iNnEF18vY7gzn9"
        .parse()
        .unwrap()
});

static COMITTEE_SECNONCE: Lazy<SecNonce> = Lazy::new(|| {
    SecNonce::build(NonceSeed::from([1; 32]))
        .with_seckey(COMITTEE_PRIVATE_KEY.inner)
        .build()
});

fn setup_unfunded_operator<S: SplitableScript>(
    wallet_addr: ScriptBuf,
    distort: bool,
) -> UnfundedOperator<S> {
    let IOPair { input, .. } = S::generate_valid_io_pair();
    let ctx = Secp256k1::new();

    let config = OperatorConfig {
        network: Network::Regtest,
        operator_script_pubkey: wallet_addr,
        staked_amount: Amount::from_sat(50_000),
        input,
        claim_challenge_period: Height::from(CLAIM_CHALLENGE_PERIOD),
        assert_challenge_period: Height::from(ASSERT_CHALLENGE_PERIOD),
        comittee: vec![COMITTEE_PRIVATE_KEY.inner.public_key(&ctx)],
        seed: [1u8; 32],
    };

    let operator = if !distort {
        Operator::<S>::new::<_, StdRng>(config)
    } else {
        Operator::<S>::new_distorted::<_, StdRng>(config)
    };

    UnfundedOperator::from_operator(operator, FEE_RATE)
}

fn sign_txs_from_operator<S: SplitableScript>(
    operator: &SignaturesAggOperator<S>,
) -> eyre::Result<PartialSignatures> {
    let ctx = Secp256k1::new();

    let claim_tx = operator.claim_tx();

    let assert_tx = operator.unsigned_assert_tx();
    let partial_assert_sig = assert_tx.sign_partial_from_claim(
        &ctx,
        claim_tx,
        // This method adds secret key to list of comittee
        // participants, so this time we exclude
        vec![operator.context().operator_pubkey()],
        operator.aggnonce(),
        COMITTEE_PRIVATE_KEY.inner,
        COMITTEE_SECNONCE.clone(),
    );

    let payout_optimistic_tx = operator.unsigned_payout_optimistic();
    let partial_payout_optimistic_sig = payout_optimistic_tx.sign_partial_from_claim(
        &ctx,
        claim_tx,
        vec![operator.context().operator_pubkey()],
        operator.aggnonce(),
        COMITTEE_PRIVATE_KEY.inner,
        COMITTEE_SECNONCE.clone(),
    );

    let payout_tx = operator.unsigned_payout_tx();
    let partial_payout_sig = payout_tx.sign_partial_from_assert(
        &ctx,
        assert_tx,
        vec![operator.context().operator_pubkey()],
        operator.aggnonce(),
        COMITTEE_PRIVATE_KEY.inner,
        COMITTEE_SECNONCE.clone(),
    );

    let assert_output = assert_tx.output(&ctx);
    let partial_disprove_sigs = operator
        .unsigned_disprove_txs()
        .iter()
        .map(|disprove| {
            disprove.sign_partial(
                &ctx,
                &assert_output,
                vec![operator.context().operator_pubkey()],
                operator.aggnonce(),
                COMITTEE_PRIVATE_KEY.inner,
                COMITTEE_SECNONCE.clone(),
            )
        })
        .map(|sig| vec![sig])
        .collect::<Vec<_>>();

    Ok(PartialSignatures {
        partial_assert_sigs: vec![partial_assert_sig],
        partial_payout_optimistic_sigs: vec![partial_payout_optimistic_sig],
        partial_payout_sigs: vec![partial_payout_sig],
        partial_disprove_sigs,
    })
}

struct TestSetup<S: SplitableScript> {
    operator: FinalOperator<S>,
    wallet_addr: Address,
    client: Client,
}

fn setup_operator<S: SplitableScript>(distort: bool) -> eyre::Result<TestSetup<S>> {
    let client = init_client()?;
    let wallet_addr = init_wallet()?;
    let unfunded_operator = setup_unfunded_operator::<S>(wallet_addr.script_pubkey(), distort);

    let tx = unfunded_operator.unsigned_claim_tx();
    let funded_claim_tx = fund_raw_transaction(&client, &tx, 2)?;
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&funded_claim_tx),
        "Claim is funded"
    );
    let signed_funded_tx = sign_raw_transaction_with_wallet(&client, &funded_claim_tx)?;
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&signed_funded_tx),
        "Funded claim is signed"
    );
    let funding_inputs = signed_funded_tx.input;
    let change_output = &signed_funded_tx.output[2];

    let challenge_signing_operator = ChallengeSigningOperator::from_challenge_singing_operator(
        unfunded_operator,
        funding_inputs,
        change_output.clone(),
        FEE_RATE,
    );

    let challenge_tx = challenge_signing_operator.unsigned_challenge_tx();
    let signed_challenge_tx = sign_raw_transaction_with_wallet(&client, &challenge_tx)?;
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&signed_challenge_tx),
        "Signed challenge transaction"
    );
    let challenge_tx_witness = signed_challenge_tx.input[0].witness.clone();

    let nonce_agg_operator = NoncesAggregationOperator::from_challenge_singing_operator(
        challenge_signing_operator,
        challenge_tx_witness,
        &mut thread_rng(),
    );

    let comitte_pub_nonce = COMITTEE_SECNONCE.public_nonce();

    let sigs_agg_operator = SignaturesAggOperator::from_nonces_agg_operator(
        nonce_agg_operator,
        vec![comitte_pub_nonce],
        FEE_RATE,
    );

    let partial_sigs = sign_txs_from_operator(&sigs_agg_operator)?;
    let final_operator =
        FinalOperator::from_signatures_agg_operator(sigs_agg_operator, partial_sigs);

    Ok(TestSetup {
        operator: final_operator,
        wallet_addr,
        client,
    })
}

fn test_operator_optimistic_payout<S: SplitableScript>() -> eyre::Result<()> {
    let TestSetup {
        operator,
        wallet_addr,
        client,
    } = setup_operator::<S>(false)?;
    let ctx = Secp256k1::new();

    let claim_tx = operator.claim_tx();
    let tx = claim_tx.to_tx(&ctx);
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&tx),
        "Sending claim"
    );
    send_raw_transaciton(&client, &tx)?;
    generate_to_address(&client, CLAIM_CHALLENGE_PERIOD.into(), wallet_addr.clone())?;

    let payout_optimistic_tx = operator.payout_optimistic_tx();
    let tx = payout_optimistic_tx.to_tx();
    tracing::info!(
        txid = tx.compute_txid().to_string(),
        tx = bitcoin::consensus::encode::serialize_hex(&tx),
        "Sending payout optimistic"
    );
    send_raw_transaciton(&client, &tx)?;
    generate_to_address(&client, 1, wallet_addr)?;

    Ok(())
}

fn test_operator_payout<S: SplitableScript>() -> eyre::Result<()> {
    let TestSetup {
        operator,
        wallet_addr,
        client,
    } = setup_operator::<S>(false)?;
    let ctx = Secp256k1::new();

    let claim_tx = operator.claim_tx();
    let tx = claim_tx.to_tx(&ctx);
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&tx),
        "Sending claim"
    );
    send_raw_transaciton(&client, &tx)?;
    generate_to_address(&client, 1, wallet_addr.clone())?;

    let challenge_tx = operator.challenge_tx();
    let tx = challenge_tx.to_tx();
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&tx),
        "Got challenge tx"
    );
    // Fund and sign challenge tx
    let mut funded_challenge_tx = fund_raw_transaction(&client, &tx, 1)?;
    // NOTE(Velnbur): for some reason `fundrawtransaction` removes
    // witness from all inputs, that's why we add witness again from
    // previous tx state.
    //
    // We always know that our input is the first one.
    funded_challenge_tx.input[0].witness = tx.input[0].witness.clone();
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&funded_challenge_tx),
        "Challenge is funded"
    );
    let signed_funded_challenge_tx =
        sign_raw_transaction_with_wallet(&client, &funded_challenge_tx)?;
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&signed_funded_challenge_tx),
        "Funded challenge is signed"
    );
    send_raw_transaciton(&client, &signed_funded_challenge_tx)?;
    tracing::info!(
        txid = signed_funded_challenge_tx.compute_txid().to_string(),
        "Sending challenge tx"
    );

    let assert_tx = operator.assert_tx();
    let tx = assert_tx.to_tx(&ctx);
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&tx),
        "Sending assert tx"
    );
    send_raw_transaciton(&client, &tx)?;

    generate_to_address(
        &client,
        (ASSERT_CHALLENGE_PERIOD + 1).into(),
        wallet_addr.clone(),
    )?;

    let payout_tx = operator.payout_tx();
    let tx = payout_tx.to_tx(&ctx);
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&tx),
        "Sending payout tx"
    );
    send_raw_transaciton(&client, &tx)?;
    generate_to_address(&client, 1, wallet_addr)?;

    Ok(())
}

fn test_operator_disprove<S: SplitableScript>() -> eyre::Result<()> {
    let TestSetup {
        operator,
        wallet_addr,
        client,
    } = setup_operator::<S>(true)?;
    let ctx = Secp256k1::new();

    let claim_tx = operator.claim_tx();
    let tx = claim_tx.to_tx(&ctx);
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&tx),
        "Sending claim"
    );
    send_raw_transaciton(&client, &tx)?;
    generate_to_address(&client, 1, wallet_addr.clone())?;

    let challenge_tx = operator.challenge_tx();
    let tx = challenge_tx.to_tx();
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&tx),
        "Got challenge tx"
    );
    // Fund and sign challenge tx
    let mut funded_challenge_tx = fund_raw_transaction(&client, &tx, 1)?;
    // NOTE(Velnbur): for some reason `fundrawtransaction` removes
    // witness from all inputs, that's why we add witness again from
    // previous tx state.
    //
    // We always know that our input is the first one.
    funded_challenge_tx.input[0].witness = tx.input[0].witness.clone();
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&funded_challenge_tx),
        "Challenge is funded"
    );
    let signed_funded_challenge_tx =
        sign_raw_transaction_with_wallet(&client, &funded_challenge_tx)?;
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&signed_funded_challenge_tx),
        "Funded challenge is signed"
    );
    send_raw_transaciton(&client, &signed_funded_challenge_tx)?;
    tracing::info!(
        txid = signed_funded_challenge_tx.compute_txid().to_string(),
        "Sending challenge tx"
    );

    let assert_tx = operator.assert_tx();
    let tx = assert_tx.to_tx(&ctx);
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&tx),
        "Sending assert tx"
    );
    send_raw_transaciton(&client, &tx)?;
    generate_to_address(&client, 1, wallet_addr.clone())?;

    let found_disprove = operator.disprove_txs().iter().enumerate().find_map(|(idx, disprove)| {
        let tx = disprove.to_tx(&ctx);
        tracing::info!(
            ?idx,
            tx = bitcoin::consensus::encode::serialize_hex(&tx),
            "Sending disprove tx"
        );
        
        if let Err(err) = send_raw_transaciton(&client, &tx) {
            tracing::info!(
                %err,
                "Failed to spend disprove tx"
            );
            None
        } else {
            Some(disprove)
        }
    });

    assert!(found_disprove.is_some());
    generate_to_address(&client, 1, wallet_addr)?;

    Ok(())
}

fn test_operator_generic<S: SplitableScript>() -> eyre::Result<()> {
    test_operator_payout::<S>()?;
    // test_operator_optimistic_payout::<S>()?;
    test_operator_disprove::<S>()?;

    Ok(())
}

#[test]
fn test_operator_u32mul() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt().init();

    test_operator_generic::<U32MulScript>()
}
