use bitcoin::{
    key::{
        rand::{rngs::StdRng, thread_rng},
        Secp256k1,
    },
    relative::Height,
    taproot::LeafVersion,
    Address, Amount, FeeRate, Network, PrivateKey, TapLeafHash,
};
use bitcoin_splitter::split::script::{IOPair, SplitableScript};
use bitcoin_testscripts::square_fibonacci::SquareFibonacciScript;
use jsonrpc::Client;
use nero_core::{
    musig2::{NonceSeed, SecNonce},
    operator::{
        FinalOperator, NoncesAggregationOperator, Operator, OperatorConfig, PartialSignatures,
        SignaturesAggOperator, UnfundedOperator,
    },
};
use once_cell::sync::Lazy;

use crate::common::{
    fund_raw_transaction, generate_to_address, init_client, init_wallet, send_raw_transaciton,
    sign_raw_transaction_with_wallet,
};

const CLAIM_CHALLENGE_PERIOD: u16 = 6;
const ASSERT_CHALLENGE_PERIOD: u16 = 6;
const FEE_RATE: FeeRate = FeeRate::BROADCAST_MIN;

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

fn setup_unfunded_operator<S: SplitableScript>() -> UnfundedOperator<S> {
    let IOPair { input, .. } = S::generate_valid_io_pair();
    let ctx = Secp256k1::new();

    let config = OperatorConfig {
        network: Network::Regtest,
        staked_amount: Amount::from_sat(50_000),
        input,
        claim_challenge_period: Height::from(CLAIM_CHALLENGE_PERIOD),
        assert_challenge_period: Height::from(ASSERT_CHALLENGE_PERIOD),
        comittee: vec![COMITTEE_PRIVATE_KEY.inner.public_key(&ctx)],
        seed: [1u8; 32],
    };

    let operator = Operator::<S>::new::<_, StdRng>(config);

    UnfundedOperator::from_operator(operator, FEE_RATE)
}

fn sign_txs_from_operator<S: SplitableScript>(
    operator: &SignaturesAggOperator<S>,
) -> eyre::Result<PartialSignatures> {
    let ctx = Secp256k1::new();

    let claim_tx = operator.claim_tx();

    let assert_tx = operator.assert_tx();
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

    let payout_optimistic_tx = operator.payout_optimistic_tx();
    let partial_payout_optimistic_sig = payout_optimistic_tx.sign_partial_from_claim(
        &ctx,
        claim_tx,
        vec![operator.context().operator_pubkey()],
        operator.aggnonce(),
        COMITTEE_PRIVATE_KEY.inner,
        COMITTEE_SECNONCE.clone(),
    );

    let payout_tx = operator.payout_tx();
    let partial_payout_sig = payout_tx.sign_partial_from_assert(
        &ctx,
        assert_tx,
        vec![operator.context().operator_pubkey()],
        operator.aggnonce(),
        COMITTEE_PRIVATE_KEY.inner,
        COMITTEE_SECNONCE.clone(),
    );

    let assert_output = &assert_tx.to_unsigned_tx(&ctx).output[0];
    let partial_disprove_sigs = operator
        .disprove_txs()
        .iter()
        .map(|disprove| {
            let leaf_hash = TapLeafHash::from_script(
                &disprove.script().to_script_pubkey(),
                LeafVersion::TapScript,
            );

            disprove.sign_partial(
                &ctx,
                assert_output,
                leaf_hash,
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

fn setup_operator<S: SplitableScript>() -> eyre::Result<TestSetup<S>> {
    let unfunded_operator = setup_unfunded_operator::<S>();
    let client = init_client()?;
    let wallet_addr = init_wallet()?;

    let tx = unfunded_operator.unsigned_claim_tx();
    let funded_tx = fund_raw_transaction(&client, &tx, 2)?;
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&funded_tx),
        "Claim is funded"
    );
    let signed_funded_tx = sign_raw_transaction_with_wallet(&client, &funded_tx)?;
    tracing::info!(
        tx = bitcoin::consensus::encode::serialize_hex(&signed_funded_tx),
        "Funded claim is signed"
    );
    let funding_input = &signed_funded_tx.input[0];
    let change_output = &signed_funded_tx.output[2];

    let nonce_agg_operator = NoncesAggregationOperator::from_unfunded_operator(
        unfunded_operator,
        funding_input.clone(),
        change_output.clone(),
        FEE_RATE,
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
    } = setup_operator::<S>()?;
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
    let tx = payout_optimistic_tx.to_tx(&ctx);
    tracing::info!(
        txid = tx.compute_txid().to_string(),
        tx = bitcoin::consensus::encode::serialize_hex(&tx),
        "Sending payout optimistic"
    );
    send_raw_transaciton(&client, &tx)?;
    generate_to_address(&client, 1, wallet_addr)?;

    Ok(())
}

fn test_operator_challenge<S: SplitableScript>() -> eyre::Result<()> {
    let TestSetup {
        operator,
        wallet_addr,
        client,
    } = setup_operator::<S>()?;
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
    let tx = challenge_tx.to_tx(&ctx);
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
    tracing::info!(
        txid = signed_funded_challenge_tx.compute_txid().to_string(),
        "Sending challenge tx"
    );
    send_raw_transaciton(&client, &signed_funded_challenge_tx)?;
    generate_to_address(&client, 1, wallet_addr)?;

    Ok(())
}

fn test_operator_generic<S: SplitableScript>() -> eyre::Result<()> {
    test_operator_challenge::<S>()?;
    test_operator_optimistic_payout::<S>()?;

    Ok(())
}

#[test]
fn test_operator_square_fibb() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt().init();

    test_operator_generic::<SquareFibonacciScript<5>>()
}