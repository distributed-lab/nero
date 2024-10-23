use std::{fs, path::PathBuf};

use dirs_next::config_dir;

#[derive(serde::Deserialize, serde::Serialize)]
pub struct Config {
    pub bitcoin_password: String,
    pub bitcoin_username: String,
    pub bitcoin_url: String,
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> eyre::Result<Self> {
        let config_file = path.unwrap_or_else(|| {
            config_dir()
                .map(|base| base.join("nero").join("config.toml"))
                .unwrap()
        });

        let src = fs::read_to_string(config_file)?;

        toml::from_str(&src).map_err(Into::into)
    }

    pub fn bitcoinrpc_auth(&self) -> bitcoincore_rpc::Auth {
        bitcoincore_rpc::Auth::UserPass(
            self.bitcoin_username.clone(),
            self.bitcoin_password.clone(),
        )
    }
}
