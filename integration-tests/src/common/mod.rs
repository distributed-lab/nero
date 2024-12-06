use std::collections::HashMap;

use bitcoin::{
    address::{NetworkChecked, NetworkUnchecked},
    consensus::{Decodable, Encodable},
    io::Cursor,
    Address, Amount, Denomination, Transaction, Txid,
};
use ini::Ini;
use jsonrpc::{error::RpcError, Client};
use once_cell::sync::Lazy;
use serde_json::{json, value::to_raw_value};

/// Store at compile time the configuration file of local Bitcoind
/// node, and parse it at start of the runtime.
pub(crate) static BITCOIN_CONFIG: Lazy<Ini> =
    Lazy::new(|| Ini::load_from_str(include_str!("../../../configs/bitcoind.conf")).unwrap());

/// Bitcoin params client to local node.
///
/// Parameters are read from local ./configs/bitcoind.conf file.
pub(crate) static BITCOIN_CLIENT_PARAMS: Lazy<(String, String, String)> = Lazy::new(|| {
    let config = &BITCOIN_CONFIG;

    let regtest_section = config.section(Some("regtest")).unwrap();
    let port = regtest_section.get("rpcport").unwrap();
    let url = format!("http://127.0.0.1:{port}");

    let username = regtest_section.get("rpcuser").unwrap();
    let password = regtest_section.get("rpcpassword").unwrap();

    (url, username.to_owned(), password.to_owned())
});

/// initialize bitcoin client from params
pub(crate) fn init_client() -> eyre::Result<Client> {
    let (mut url, username, password) = BITCOIN_CLIENT_PARAMS.clone();

    url.push_str(&format!("/wallet/{}", WALLET_NAME));

    Client::simple_http(&url, Some(username), Some(password)).map_err(Into::into)
}

/// Wallet name which will be used in tests.
pub(crate) const WALLET_NAME: &str = "nero-tests-wallet";

/// Address label which will be used in tests.
pub(crate) const ADDRESS_LABEL: &str = "nero-tests-label";

/// Init wallet if one is not initialized.
pub(crate) fn init_wallet() -> eyre::Result<Address> {
    let client = init_client()?;

    // init wallet
    tracing::info!("Initilizing wallet...");
    match create_wallet(&client, WALLET_NAME) {
        Ok(_) => {}
        // Was already created, so let's skip it
        Err(jsonrpc::Error::Rpc(RpcError { code: -4, .. })) => {
            tracing::info!("Wallet was already created");
        }
        Err(err) => return Err(err.into()),
    };

    // Get existing address, create one if is there is none.
    let address = match get_addresses_by_label(&client)? {
        Some(addrs) => addrs.0.into_keys().next().unwrap(),
        None => get_new_address(&client, ADDRESS_LABEL)?,
    }
    .assume_checked();
    tracing::info!(%address, "Got balance for funding");

    fund_address(&address)?;

    Ok(address)
}

pub(crate) const MIN_REQUIRED_AMOUNT: Amount = Amount::ONE_BTC;

/// Fund address with minimum required amount of BTC.
pub(crate) fn fund_address(address: &Address<NetworkChecked>) -> eyre::Result<()> {
    let client = init_client()?;

    // if already has enough, leave
    if get_balance(&client)? >= MIN_REQUIRED_AMOUNT {
        return Ok(());
    }

    let block_count = get_block_count(&client)?;

    // if it's only the fresh instance, generate initial 101 blocks
    if block_count <= 2 {
        tracing::info!(
            block_num = 101,
            "Bitcoin blockchain is fresh, genereting initial blocks..."
        );
        generate_to_address(&client, 101, address.clone())?;
        return Ok(());
    }

    // otherwise geneate blocks until address would have anough
    tracing::info!(%block_count, "Generating blocks one by one");
    for i in 0..101 {
        generate_to_address(&client, i, address.clone())?;
        let current_balance = get_balance(&client)?;
        if current_balance >= MIN_REQUIRED_AMOUNT {
            return Ok(());
        }
        tracing::info!(
            block_count = { block_count + i },
            "Generated, still not enough {} < {}",
            current_balance,
            MIN_REQUIRED_AMOUNT
        );
    }

    Ok(())
}

/* Let's fork bitcoincore-rpc instead for BitVM branch compatability */

pub(crate) fn create_wallet(
    client: &Client,
    name: &str,
) -> Result<serde_json::Value, jsonrpc::Error> {
    client.call("createwallet", Some(&to_raw_value(&[name]).unwrap()))
}

pub(crate) fn get_new_address(
    client: &Client,
    label: &str,
) -> Result<Address<NetworkUnchecked>, jsonrpc::Error> {
    client.call(
        "getnewaddress",
        Some(&to_raw_value(&[label, "bech32m"]).unwrap()),
    )
}

pub(crate) fn get_balance(client: &Client) -> Result<Amount, jsonrpc::Error> {
    let number: f64 = client.call("getbalance", None)?;

    Ok(Amount::from_float_in(number, Denomination::Bitcoin).unwrap())
}

pub(crate) fn get_block_count(client: &Client) -> Result<usize, jsonrpc::Error> {
    client.call("getblockcount", None)
}

pub(crate) fn generate_to_address(
    client: &Client,
    blocks: usize,
    address: Address,
) -> Result<serde_json::Value, jsonrpc::Error> {
    client.call(
        "generatetoaddress",
        Some(
            &to_raw_value(&[
                to_raw_value(&blocks).unwrap(),
                to_raw_value(&address).unwrap(),
            ])
            .unwrap(),
        ),
    )
}

pub(crate) fn fund_raw_transaction(
    client: &Client,
    tx: &Transaction,
    change_pos: isize,
) -> Result<Transaction, jsonrpc::Error> {
    let hextx = {
        // TODO(Velnbur): only this works and not this:
        // `bitcoin::consensus::encode::serialize_hex(tx)` because
        // fuck, bitcoin, I don't know...
        let mut buff = Vec::new();
        tx.version.consensus_encode(&mut buff).unwrap();
        // 0x00.consensus_encode(&mut buff).unwrap();
        // 0x01.consensus_encode(&mut buff).unwrap();
        tx.input.consensus_encode(&mut buff).unwrap();
        tx.output.consensus_encode(&mut buff).unwrap();
        // for input in &tx.input {
        //     input.witness.consensus_encode(&mut buff).unwrap();
        // }
        tx.lock_time.consensus_encode(&mut buff).unwrap();
        hex::encode(&buff)
    };

    let options = json!({
        "changePosition": change_pos,
    });

    let params = to_raw_value(&[
        to_raw_value(&hextx).unwrap(),
        to_raw_value(&options).unwrap(),
        // to_raw_value(&false).unwrap(),
    ])
    .unwrap();

    let value: serde_json::Value = client.call("fundrawtransaction", Some(&params))?;

    let hextx = value
        .as_object()
        .unwrap()
        .get("hex")
        .unwrap()
        .as_str()
        .unwrap();
    let decoded_bytes = hex::decode(hextx).unwrap();
    let mut cursor = Cursor::new(decoded_bytes);
    let tx = Transaction::consensus_decode(&mut cursor).unwrap();

    Ok(tx)
}

pub(crate) fn sign_raw_transaction_with_wallet(
    client: &Client,
    tx: &Transaction,
) -> Result<Transaction, jsonrpc::Error> {
    let hextx = bitcoin::consensus::encode::serialize_hex(&tx);

    let params = vec![to_raw_value(&hextx).unwrap()];

    let params = to_raw_value(&params).unwrap();
    let value: serde_json::Value = client.call("signrawtransactionwithwallet", Some(&params))?;

    let hextx = value
        .as_object()
        .unwrap()
        .get("hex")
        .unwrap()
        .as_str()
        .unwrap();
    let decoded_bytes = hex::decode(hextx).unwrap();
    let mut cursor = Cursor::new(decoded_bytes);
    let tx = Transaction::consensus_decode(&mut cursor).unwrap();

    Ok(tx)
}

pub(crate) fn send_raw_transaciton(
    client: &Client,
    tx: &Transaction,
) -> Result<Txid, jsonrpc::Error> {
    let hextx = bitcoin::consensus::encode::serialize_hex(tx);
    let params = to_raw_value(&[hextx]).unwrap();
    client.call("sendrawtransaction", Some(&params))
}

#[derive(serde::Deserialize)]
struct GetAddressesByLabel(HashMap<Address<NetworkUnchecked>, serde_json::Value>);

fn get_addresses_by_label(client: &Client) -> eyre::Result<Option<GetAddressesByLabel>> {
    match client.call(
        "getaddressesbylabel",
        Some(&to_raw_value(&[ADDRESS_LABEL]).unwrap()),
    ) {
        Ok(value) => Ok(Some(value)),
        Err(jsonrpc::Error::Rpc(RpcError { code: -11, .. })) => Ok(None),
        Err(err) => Err(err.into()),
    }
}
