use crate::common::{get_balance, init_client, init_wallet, MIN_REQUIRED_AMOUNT};

#[test]
fn test_ensure_user_has_min_btc() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt().init();

    let client = init_client()?;

    let _address = init_wallet()?;
    let balance = get_balance(&client)?;

    assert!(balance > MIN_REQUIRED_AMOUNT, "current balance {}", balance);

    Ok(())
}
