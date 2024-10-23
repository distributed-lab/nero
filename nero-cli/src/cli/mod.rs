use std::path::PathBuf;

use clap::{Parser, Subcommand};
use clap_verbosity::Verbosity;
use tracing_log::AsTrace as _;

use crate::{config::Config, context::Context};

use self::actions::{AssertTxArgs, DisproveSpendArgs, GenerateInputArgs, PayoutSpendArgs};

mod actions;

#[derive(Parser)]
pub struct Cli {
    #[command(flatten)]
    verbosity: Verbosity,

    #[arg(long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

impl Cli {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }

    pub fn run(self) -> eyre::Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(self.verbosity.log_level_filter().as_trace())
            .init();

        let config = Config::load(self.config.clone())?;
        let context = Context::from_config(config)?;

        match self.cmd {
            Command::AssertTx(args) => actions::assert_tx(context, args),
            Command::GenerateInput(args) => actions::generate_input(context, args),
            Command::SpendPayout(args) => actions::spend_payout(context, args),
            Command::SpendDisprove(args) => actions::spend_disprove(context, args),
            Command::GenerateKeys => actions::generate_keys(context),
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    AssertTx(AssertTxArgs),
    GenerateInput(GenerateInputArgs),
    SpendPayout(PayoutSpendArgs),
    SpendDisprove(DisproveSpendArgs),
    GenerateKeys,
}
