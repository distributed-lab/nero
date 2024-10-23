use bitcoin::{key::Secp256k1, secp256k1::All};

use crate::config::Config;

pub struct Context {
    client: bitcoincore_rpc::Client,

    secp: Secp256k1<All>,
}

impl Context {
    pub fn from_config(config: Config) -> eyre::Result<Self> {
        let client = bitcoincore_rpc::Client::new(&config.bitcoin_url, config.bitcoinrpc_auth())?;
        let secp = Secp256k1::new();

        Ok(Self { client, secp })
    }

    pub fn client(&self) -> &bitcoincore_rpc::Client {
        &self.client
    }

    pub fn secp_ctx(&self) -> &Secp256k1<All> {
        &self.secp
    }
}
