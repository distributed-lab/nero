use std::{env, fs, str::FromStr as _};

use bitcoin::{
    consensus::{Decodable, Encodable as _},
    io::Cursor,
    key::Secp256k1,
    relative::Height,
    secp256k1::{All, PublicKey, SecretKey},
    Address, Amount, CompressedPublicKey, Network, OutPoint, Transaction, TxOut, Txid,
};
use bitcoin_splitter::split::script::{IOPair, SplitableScript};
use bitcoin_testscripts::{
    int_mul_windowed::U254MulScript, square_fibonacci::SquareFibonacciScript, u32mul::U32MulScript,
};
use bitcoincore_rpc::{
    bitcoin::consensus::{Decodable as _, Encodable as _},
    RawTx as _, RpcApi,
};
use bitvm2_core::{
    assert::{AssertTransaction, Options},
    treepp::*,
};
use once_cell::sync::Lazy;

use crate::common::{init_bitcoin_client, init_wallet};

static OPERATOR_SECKEY: Lazy<SecretKey> = Lazy::new(|| {
    "50c8f972285ad27527d79c80fe4df1b63c1192047713438b45758ea4e110a88b"
        .parse()
        .unwrap()
});

static OPERATOR_PUBKEY: Lazy<PublicKey> = Lazy::new(|| {
    let ctx = Secp256k1::new();
    OPERATOR_SECKEY.public_key(&ctx)
});

macro_rules! hex {
    ($tx:expr) => {{
        let mut buf = Vec::new();
        $tx.consensus_encode(&mut buf).unwrap();
        hex::encode(&buf)
    }};
}

macro_rules! txconv {
    ($tx:expr) => {{
        let mut buf = Vec::new();
        $tx.consensus_encode(&mut buf).unwrap();
        let mut cursor = std::io::Cursor::new(&buf);
        bitcoincore_rpc::bitcoin::Transaction::consensus_decode(&mut cursor)?.raw_hex()
    }};
}

struct TestSetup {
    ctx: Secp256k1<All>,
    client: bitcoincore_rpc::Client,
    funder_address: bitcoincore_rpc::bitcoin::Address,
    input_script: Script,
    _output_script: Script,
    funding_txid: Txid,
    funding_txout_idx: usize,
    funding_txout: TxOut,
}

fn setup_test<const I: usize, const O: usize, S>(amount_sats: u64) -> eyre::Result<TestSetup>
where
    S: SplitableScript<I, O>,
{
    let client = init_bitcoin_client()?;
    let address = init_wallet()?;

    let IOPair { input, output } = S::generate_invalid_io_pair();

    let ctx = Secp256k1::new();

    let operator_pubkey = OPERATOR_SECKEY.public_key(&ctx);
    let operator_p2wpkh_addr = Address::p2wpkh(
        &CompressedPublicKey::try_from(bitcoin::PublicKey::new(operator_pubkey)).unwrap(),
        Network::Regtest,
    );

    // TODO(Velnbur): fix version of bitcoincorerpc and Bitcoin for this...
    let operator_funding_txid = client.send_to_address(
        &bitcoincore_rpc::bitcoin::Address::from_str(&operator_p2wpkh_addr.to_string())
            .unwrap()
            .assume_checked(),
        bitcoincore_rpc::bitcoin::Amount::from_sat(amount_sats),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;
    let tx = client.get_raw_transaction(&operator_funding_txid, None)?;
    let tx = {
        let mut buf = Vec::new();
        tx.consensus_encode(&mut buf).unwrap();
        let mut cursor = Cursor::new(&buf);
        Transaction::consensus_decode(&mut cursor)?
    };

    tracing::info!(hex = %hex!(tx), txid = %operator_funding_txid, "Created funding");
    client.generate_to_address(6, &address)?;

    // find txout
    let txid = tx.compute_txid();
    let (idx, funding_txout) = tx
        .output
        .into_iter()
        .enumerate()
        .find(|(_idx, out)| out.value == Amount::from_sat(amount_sats))
        .unwrap();

    Ok(TestSetup {
        ctx,
        client,
        funder_address: address,
        input_script: input,
        _output_script: output,
        funding_txid: txid,
        funding_txout_idx: idx,
        funding_txout,
    })
}

fn test_script_payout_spending<const I: usize, const O: usize, S>() -> eyre::Result<()>
where
    S: SplitableScript<I, O>,
{
    let TestSetup {
        ctx,
        client,
        input_script,
        funding_txid,
        funding_txout_idx,
        funding_txout,
        funder_address,
        ..
    } = setup_test::<I, O, S>(71_000)?;

    let operator_xonly = OPERATOR_PUBKEY.x_only_public_key().0;
    let assert_tx = AssertTransaction::<{ I }, { O }, S>::with_options(
        input_script,
        operator_xonly,
        Amount::from_sat(70_000),
        Options {
            payout_locktime: Height::from(1),
        },
    );

    let atx = assert_tx.clone().spend_p2wpkh_input_tx(
        &ctx,
        &OPERATOR_SECKEY,
        funding_txout.clone(),
        OutPoint::new(funding_txid, funding_txout_idx as u32),
    )?;

    println!("Txid: {}", atx.compute_txid());
    println!("Assert: {}", hex!(atx));
    client.send_raw_transaction(txconv!(atx))?;
    client.generate_to_address(1, &funder_address)?;

    let payout_tx = assert_tx.payout_transaction(
        &ctx,
        TxOut {
            value: Amount::from_sat(69_000),
            script_pubkey: funding_txout.script_pubkey,
        },
        atx.compute_txid(),
        &OPERATOR_SECKEY,
    )?;

    println!("Txid: {}", payout_tx.compute_txid());
    println!("Payout: {}", hex!(payout_tx));
    client.send_raw_transaction(txconv!(payout_tx))?;
    client.generate_to_address(6, &funder_address)?;

    Ok(())
}

fn test_script_disprove_distorted<const I: usize, const O: usize, S>() -> eyre::Result<()>
where
    S: SplitableScript<I, O>,
{
    let TestSetup {
        ctx,
        client,
        input_script,
        funding_txid,
        funding_txout_idx,
        funding_txout,
        funder_address,
        ..
    } = setup_test::<I, O, S>(100_000)?;

    let operator_xonly = OPERATOR_PUBKEY.x_only_public_key().0;
    let (assert_tx, distored_idx) = AssertTransaction::<{ I }, { O }, S>::with_options_distorted(
        input_script,
        operator_xonly,
        Amount::from_sat(90_000),
        Options {
            payout_locktime: Height::from(1),
        },
    );

    let atx = assert_tx.clone().spend_p2wpkh_input_tx(
        &ctx,
        &OPERATOR_SECKEY,
        funding_txout.clone(),
        OutPoint::new(funding_txid, funding_txout_idx as u32),
    )?;

    println!("Txid: {}", atx.compute_txid());
    println!("Assert: {}", hex!(atx));
    client.send_raw_transaction(txconv!(atx))?;
    client.generate_to_address(1, &funder_address)?;

    let disprove_txs = assert_tx.clone().disprove_transactions(
        &ctx,
        TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: funding_txout.script_pubkey,
        },
        atx.compute_txid(),
    )?;

    let disprove_tx = disprove_txs
        .get(&assert_tx.disprove_scripts[distored_idx])
        .unwrap();
    client.send_raw_transaction(txconv!(disprove_tx))?;

    let hexed = hex!(disprove_tx);
    println!("Txid: {}", disprove_tx.compute_txid());
    println!("DisproveSize: {}", hexed.len() / 2);

    if env::var("NERO_TESTS_TX_FILE").is_ok() {
        fs::write("./disprove.txt", hexed)?;
    }

    client.generate_to_address(6, &funder_address)?;

    Ok(())
}

#[test]
#[ignore = "Stack size limit exceeded"]
fn test_u254_mul_disprove() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt().init();
    test_script_disprove_distorted::<
        { U254MulScript::INPUT_SIZE },
        { U254MulScript::OUTPUT_SIZE },
        U254MulScript,
    >()
}

#[test]
fn test_u254_mul_payout() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt().init();
    test_script_payout_spending::<
        { U254MulScript::INPUT_SIZE },
        { U254MulScript::OUTPUT_SIZE },
        U254MulScript,
    >()
}

#[test]
fn test_square_fibonachi() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt().init();
    test_script_disprove_distorted::<
        { SquareFibonacciScript::<1024>::INPUT_SIZE },
        { SquareFibonacciScript::<1024>::OUTPUT_SIZE },
        SquareFibonacciScript<1024>,
    >()
}

#[test]
fn test_u32mul_disprove() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt().init();
    test_script_disprove_distorted::<
        { U32MulScript::INPUT_SIZE },
        { U32MulScript::OUTPUT_SIZE },
        U32MulScript,
    >()
}
