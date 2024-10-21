use bitcoin::XOnlyPublicKey;
use once_cell::sync::Lazy;
pub mod assert;
pub mod disprove;

#[allow(dead_code)]
// Re-export what is needed to write treepp scripts
pub mod treepp {
    pub use bitcoin_script::{define_pushable, script};
    pub use bitcoin_utils::debug::{execute_script, run};

    define_pushable!();
    pub use bitcoin::ScriptBuf as Script;
}

// FIXME(Velnbur): Use really non spendable key. For example checkout:
// 1. https://github.com/nomic-io/nomic/blob/5ba8b661e6d9ffb6b9eb39c13247cccefa5342a9/src/babylon/mod.rs#L451
pub static UNSPENDABLE_KEY: Lazy<XOnlyPublicKey> = Lazy::new(|| {
    "1e37ec522cb319c66e1a21077a2ba05c070efa5c018d5bc8d002250f5ca0c7dc"
        .parse()
        .unwrap()
});

#[cfg(test)]
mod tests {
    use crate::UNSPENDABLE_KEY;

    #[test]
    fn test_unspendable_key() {
        let _ = *UNSPENDABLE_KEY;
    }
}
