use std::{collections::BTreeMap, fs, path::PathBuf, str::FromStr as _};

use bitcoin::{
    address::NetworkUnchecked,
    consensus::{Decodable, Encodable},
    hashes::Hash,
    io::Cursor,
    key::rand::{rngs::SmallRng, thread_rng},
    secp256k1::SecretKey,
    Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey,
};
use bitcoin_splitter::split::script::{IOPair, SplitableScript};
use bitcoin_testscripts::square_fibonacci::SquareFibonacciScript;
use bitcoincore_rpc::{
    bitcoin::{
        consensus::{Decodable as _, Encodable as _},
        hashes::Hash as _,
    },
    RpcApi,
};
use bitvm2_core::{
    assert::{payout_script::PayoutScript, AssertTransaction, Options},
    disprove::DisproveScript,
};
use clap::Args;

use crate::context::Context;

#[derive(Args, Debug, Clone)]
pub struct AssertTxArgs {
    #[arg(long)]
    pub input: PathBuf,
    #[arg(long)]
    pub amount: Amount,
    #[arg(long)]
    pub pubkey: XOnlyPublicKey,
    #[arg(long)]
    pub distort: bool,
}

pub fn assert_tx(ctx: Context, args: AssertTxArgs) -> eyre::Result<()> {
    let input_script: ScriptBuf = hex::decode(fs::read_to_string(args.input)?)?.into();

    let opts = Options::default();

    // FIXME(Velnbur): make this optionally valid
    let (assert, invalid_chunk_idx) = AssertTransaction::<
        SquareFibonacciScript<1024>,
    >::with_options_distorted::<[u8; 32], SmallRng>(
        input_script,
        args.pubkey,
        args.amount,
        opts,
        [1; 32],
    );

    let assert_output_address = Address::from_script(
        &assert.txout(ctx.secp_ctx()).script_pubkey,
        Network::Regtest,
    )?;

    let assert_txid = ctx.client().send_to_address(
        &bitcoincore_rpc::bitcoin::Address::from_str(&assert_output_address.to_string())
            .unwrap()
            .assume_checked(),
        bitcoincore_rpc::bitcoin::Amount::from_sat(args.amount.to_sat()),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;

    let assert_tx = fetch_tx(&ctx, assert_txid)?;

    let output = assert_tx
        .output
        .iter()
        .position(|out| out.script_pubkey == assert_output_address.script_pubkey())
        .unwrap();

    println!("{assert_txid}:{output}");
    if args.distort {
        println!("{invalid_chunk_idx}");
    }

    fs::write(
        "payout.txt",
        assert.payout_script.to_script().to_hex_string(),
    )?;

    let base_path = PathBuf::from("disproves");
    if base_path.exists() {
        // TODO(Velnbur): we should ask about that later
        fs::remove_dir_all(&base_path)?;
    }

    for (idx, disprove_script) in assert.disprove_scripts.iter().enumerate() {
        let disprove_base_path = base_path.join(format!("{:06}", idx));
        fs::create_dir_all(&disprove_base_path)?;
        fs::write(
            disprove_base_path.join("script_pubkey.txt"),
            disprove_script.script_pubkey.to_hex_string(),
        )?;
        fs::write(
            disprove_base_path.join("witness.txt"),
            disprove_script.script_witness.to_hex_string(),
        )?;
    }

    Ok(())
}

fn fetch_tx(
    ctx: &Context,
    assert_txid: bitcoincore_rpc::bitcoin::Txid,
) -> Result<Transaction, eyre::Error> {
    let tx = ctx.client().get_raw_transaction(&assert_txid, None)?;
    let mut buf = Vec::with_capacity(tx.size());
    tx.consensus_encode(&mut buf)?;
    let mut cursor = Cursor::new(buf);
    Ok(Transaction::consensus_decode(&mut cursor)?)
}

#[derive(Args, Debug, Clone)]
pub struct PayoutSpendArgs {
    #[arg(long)]
    assert: bitcoincore_rpc::bitcoin::OutPoint,
    #[arg(long)]
    address: Address<NetworkUnchecked>,
    #[arg(long)]
    seckey: SecretKey,
}

pub fn spend_payout(ctx: Context, args: PayoutSpendArgs) -> eyre::Result<()> {
    let base_path = PathBuf::from("disproves");

    let dirs = fs::read_dir(base_path)?;
    let mut disprove_scripts = BTreeMap::new();

    for dir in dirs.filter_map(Result::ok) {
        let dir_name = dir.file_name().into_string().unwrap();

        let Ok(disprove_script_num) = dir_name.parse::<usize>() else {
            continue;
        };

        let script_pubkey: ScriptBuf =
            hex::decode(fs::read_to_string(dir.path().join("script_pubkey.txt"))?)?.into();
        let script_witness: ScriptBuf =
            hex::decode(fs::read_to_string(dir.path().join("witness.txt"))?)?.into();

        disprove_scripts.insert(
            disprove_script_num,
            DisproveScript {
                script_witness,
                script_pubkey,
            },
        );
    }

    let disprove_scripts = disprove_scripts.values().cloned().collect::<Vec<_>>();
    // let payout_script: ScriptBuf = hex::decode(fs::read_to_string("input.txt")?)?.into();

    let assert_tx = ctx.client().get_raw_transaction(&args.assert.txid, None)?;

    let assert_txout = {
        let mut buf = Vec::new();
        assert_tx.output[args.assert.vout as usize].consensus_encode(&mut buf)?;
        let mut cursor = Cursor::new(buf);
        TxOut::consensus_decode(&mut cursor)?
    };
    let operator_pubkey = args.seckey.public_key(ctx.secp_ctx()).x_only_public_key().0;
    let payout = PayoutScript::new(operator_pubkey);

    let assert = AssertTransaction::<SquareFibonacciScript<1024>>::from_scripts(
        operator_pubkey,
        payout,
        disprove_scripts,
        assert_txout.value,
    );

    let tx = assert.payout_transaction(
        ctx.secp_ctx(),
        TxOut {
            script_pubkey: args.address.assume_checked().script_pubkey(),
            value: assert_txout.value.unchecked_sub(Amount::from_sat(80_000)),
        },
        OutPoint::new(
            Txid::from_byte_array(args.assert.txid.to_byte_array()),
            args.assert.vout,
        ),
        &args.seckey,
    )?;

    let tx = {
        let mut buf = Vec::new();
        tx.consensus_encode(&mut buf)?;
        let mut cursor = std::io::Cursor::new(buf);
        bitcoincore_rpc::bitcoin::Transaction::consensus_decode(&mut cursor)?
    };

    ctx.client().send_raw_transaction(&tx)?;

    println!("{}", tx.txid());

    Ok(())
}

#[derive(Args, Debug, Clone)]
pub struct DisproveSpendArgs {
    #[arg(long)]
    assert: bitcoincore_rpc::bitcoin::OutPoint,
    #[arg(long)]
    address: Address<NetworkUnchecked>,
    #[arg(long)]
    disprove: usize,
}

pub fn spend_disprove(ctx: Context, args: DisproveSpendArgs) -> eyre::Result<()> {
    let base_path = PathBuf::from("disproves");

    let dirs = fs::read_dir(base_path)?;
    let mut disprove_scripts = BTreeMap::new();

    for dir in dirs.filter_map(Result::ok) {
        let dir_name = dir.file_name().into_string().unwrap();

        let Ok(disprove_script_num) = dir_name.parse::<usize>() else {
            continue;
        };

        let script_pubkey: ScriptBuf =
            hex::decode(fs::read_to_string(dir.path().join("script_pubkey.txt"))?)?.into();
        let script_witness: ScriptBuf =
            hex::decode(fs::read_to_string(dir.path().join("witness.txt"))?)?.into();

        disprove_scripts.insert(
            disprove_script_num,
            DisproveScript {
                script_witness,
                script_pubkey,
            },
        );
    }

    let disprove_scripts = disprove_scripts.values().cloned().collect::<Vec<_>>();
    let payout_script: ScriptBuf = hex::decode(fs::read_to_string("payout.txt")?)?.into();

    let assert_tx = ctx.client().get_raw_transaction(&args.assert.txid, None)?;

    let assert_txout = {
        let mut buf = Vec::new();
        assert_tx.output[args.assert.vout as usize].consensus_encode(&mut buf)?;
        let mut cursor = Cursor::new(buf);
        TxOut::consensus_decode(&mut cursor)?
    };

    let disprove_script = &disprove_scripts[args.disprove];
    let tx = &AssertTransaction::<SquareFibonacciScript<1024>>::form_disprove_transactions(
        payout_script,
        &disprove_scripts,
        ctx.secp_ctx(),
        TxOut {
            script_pubkey: args.address.assume_checked().script_pubkey(),
            value: assert_txout.value.unchecked_sub(Amount::from_sat(80_000)),
        },
        OutPoint::new(
            Txid::from_byte_array(*args.assert.txid.as_raw_hash().as_byte_array()),
            args.assert.vout,
        ),
    )?[disprove_script];

    let tx = {
        let mut buf = Vec::new();
        tx.consensus_encode(&mut buf)?;
        let mut cursor = std::io::Cursor::new(buf);
        bitcoincore_rpc::bitcoin::Transaction::consensus_decode(&mut cursor)?
    };

    println!("{}", tx.txid());

    ctx.client().send_raw_transaction(&tx)?;

    Ok(())
}

const DEFAULT_OUTPUT_FILE: &str = "input.txt";

#[derive(Args, Debug, Clone)]
pub struct GenerateInputArgs {
    #[arg(long)]
    output: Option<PathBuf>,
}

pub fn generate_input(_ctx: Context, args: GenerateInputArgs) -> eyre::Result<()> {
    let output = args.output.unwrap_or_else(|| DEFAULT_OUTPUT_FILE.into());

    let IOPair { input, .. } = SquareFibonacciScript::<1024>::generate_valid_io_pair();

    println!("{}", input.to_asm_string());

    fs::write(output, input.to_hex_string())?;

    Ok(())
}

pub fn generate_keys(ctx: Context) -> eyre::Result<()> {
    let (seckey, pubkey) = ctx.secp_ctx().generate_keypair(&mut thread_rng());

    println!("{}", seckey.display_secret());
    println!("{}", pubkey.x_only_public_key().0);

    Ok(())
}
