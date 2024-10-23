use cli::Cli;

mod cli;
mod config;
mod context;

fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    cli.run()?;

    Ok(())
}
