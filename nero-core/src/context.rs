//! Provides BitVM2 flow context.

use std::{iter, marker::PhantomData, str::FromStr};

use bitcoin::{
    key::{Secp256k1, Verification},
    relative::Height,
    secp256k1::PublicKey,
    taproot::LeafVersion,
    Amount, Txid, Weight,
};
use bitcoin_splitter::split::script::SplitableScript;
use musig2::{secp::Point, KeyAggContext};

use crate::{
    assert::Assert, disprove::{
        form_disprove_scripts_distorted_with_seed, form_disprove_scripts_with_seed,
        signing::SignedIntermediateState, Disprove, DisproveScript,
    }, payout::PAYOUT_APPROX_WEIGHT, treepp::*
};

/// Global context of BitVM2 flow.
pub struct Context<S: SplitableScript, C: Verification> {
    pub(crate) secp: Secp256k1<C>,

    /// $x$ - the input of the program flow asserts.
    #[allow(dead_code)]
    pub(crate) input: Script,

    /// The splitted into disprove scripts program.
    pub(crate) disprove_scripts: Vec<DisproveScript>,

    /// Fresh secret key generated for current session.
    pub(crate) operator_pubkey: PublicKey,

    /// Fresh secret key generated for current session.
    pub(crate) operator_script_pubkey: Script,

    /// Public keys of comitte for emulating covenants.
    pub(crate) comittee: Vec<PublicKey>,

    /// Claim transaction challenge period.
    pub(crate) claim_challenge_period: Height,

    /// Assert transaction challenge period.
    pub(crate) assert_challenge_period: Height,

    /// Stacked amount mentioned in paper as $d$.
    pub(crate) staked_amount: Amount,

    /// Transaction weights of disprove transaction in the same order.
    ///
    /// It's required for calculating the fee for disprove transaction.
    pub(crate) largest_disprove_weight: Weight,

    /// Assert transaction weight.
    ///
    /// It's required to calculate it before hand as with current fee rate we
    /// can predict the fee required for assert transaction.
    pub(crate) assert_tx_weight: Weight,

    pub(crate) payout_tx_weight: Weight,

    /// Program that current flow asserts.
    __program: PhantomData<S>,
}

impl<S: SplitableScript, C: Verification> Context<S, C> {
    /// Setup context for BitVM2 flow.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_setup<Seed, Rng>(
        ctx: Secp256k1<C>,
        staked_amount: Amount,
        input: Script,
        claim_challenge_period: Height,
        assert_challenge_period: Height,
        operator_pubkey: PublicKey,
        operator_script_pubkey: Script,
        mut comittee: Vec<PublicKey>,
        seed: Seed,
    ) -> Self
    where
        Seed: Sized + Default + AsMut<[u8]> + Copy,
        Rng: rand::SeedableRng<Seed = Seed> + rand::Rng,
    {
        // Always sort the order of keys in comittee before doing anything.
        comittee.sort();
        let key_ctx =
            KeyAggContext::new(iter::once(operator_pubkey).chain(comittee.clone())).unwrap();
        let comittee_aggpubkey = key_ctx.aggregated_pubkey();

        let disprove_scripts = form_disprove_scripts_with_seed::<S, Seed, Rng>(
            input.clone(),
            comittee_aggpubkey,
            seed,
        );

        let dummy_txid =
            Txid::from_str("6ac23d25c784f97c75a0ebd5985d6db0c8c4b4c1f6d0bd684b5a2087b7abeb30")
                .expect("const valid txid");

        let assert_tx = Assert::new(
            &disprove_scripts,
            operator_pubkey.into(),
            assert_challenge_period,
            dummy_txid,
            comittee_aggpubkey,
            Amount::ZERO,
        );
        let taproot = assert_tx.taproot(&ctx);

        let disprove_txs = disprove_scripts
            .iter()
            .map(|script| {
                Disprove::new(
                    script,
                    dummy_txid,
                    taproot
                        // TODO(Velnbur): another place which generates a large chunk of memory
                        // just for getting a control block. We should create a PR in rust-bitcoin to
                        // avoid that.
                        .control_block(&(script.to_script_pubkey(), LeafVersion::TapScript))
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let assert_tx_weight = assert_tx.compute_weight(&ctx);

        Self {
            staked_amount,
            input,
            secp: ctx,
            operator_pubkey,
            operator_script_pubkey,
            largest_disprove_weight: disprove_txs.iter().map(|tx| tx.compute_weigth()).max().unwrap(),
            disprove_scripts,
            claim_challenge_period,
            assert_challenge_period,
            comittee,
            assert_tx_weight,
            payout_tx_weight: PAYOUT_APPROX_WEIGHT,
            __program: Default::default(),
        }
    }

    /// Setup context for BitVM2 flow.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_setup_distorted<Seed, Rng>(
        ctx: Secp256k1<C>,
        staked_amount: Amount,
        input: Script,
        claim_challenge_period: Height,
        assert_challenge_period: Height,
        operator_pubkey: PublicKey,
        operator_script_pubkey: Script,
        mut comittee: Vec<PublicKey>,
        seed: Seed,
    ) -> Self
    where
        Seed: Sized + Default + AsMut<[u8]> + Copy,
        Rng: rand::SeedableRng<Seed = Seed> + rand::Rng,
    {
        // Always sort the order of keys in comittee before doing anything.
        comittee.sort();
        let key_ctx =
            KeyAggContext::new(iter::once(operator_pubkey).chain(comittee.clone())).unwrap();
        let comittee_aggpubkey = key_ctx.aggregated_pubkey();

        let (disprove_scripts, _) = form_disprove_scripts_distorted_with_seed::<S, Seed, Rng>(
            input.clone(),
            comittee_aggpubkey,
            seed,
        );

        let dummy_txid =
            Txid::from_str("6ac23d25c784f97c75a0ebd5985d6db0c8c4b4c1f6d0bd684b5a2087b7abeb30")
                .expect("const valid txid");

        let assert_tx = Assert::new(
            &disprove_scripts,
            operator_pubkey.into(),
            assert_challenge_period,
            dummy_txid,
            comittee_aggpubkey,
            Amount::ZERO,
        );
        let taproot = assert_tx.taproot(&ctx);

        let disprove_txs = disprove_scripts
            .iter()
            .map(|script| {
                Disprove::new(
                    script,
                    dummy_txid,
                    taproot
                        // TODO(Velnbur): another place which generates a large chunk of memory
                        // just for getting a control block. We should create a PR in rust-bitcoin to
                        // avoid that.
                        .control_block(&(script.to_script_pubkey(), LeafVersion::TapScript))
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let assert_tx_weight = assert_tx.compute_weight(&ctx);

        Self {
            staked_amount,
            input,
            secp: ctx,
            operator_pubkey,
            operator_script_pubkey,
            largest_disprove_weight: disprove_txs.iter().map(|tx| tx.compute_weigth()).max().unwrap(),
            disprove_scripts,
            claim_challenge_period,
            assert_challenge_period,
            comittee,
            assert_tx_weight,
            payout_tx_weight: PAYOUT_APPROX_WEIGHT,
            __program: Default::default(),
        }
    }

    /// Comittee aggregated public key.
    pub(crate) fn comittee_aggpubkey<T: From<Point>>(&self) -> T {
        let ctx = self.comittee_keyaggctx();

        ctx.aggregated_pubkey()
    }

    pub(crate) fn comittee_keyaggctx(&self) -> KeyAggContext {
        let mut points = iter::once(self.operator_pubkey)
            .chain(self.comittee.clone())
            .collect::<Vec<_>>();
        points.sort();
        KeyAggContext::new(points).unwrap()
    }

    /// Return list of signed states from disprove scripts.
    pub(crate) fn signed_states(&self) -> Vec<SignedIntermediateState> {
        iter::once(self.disprove_scripts[0].from_state.clone())
            .chain(self.disprove_scripts.iter().map(|d| d.to_state.clone()))
            .collect()
    }

    pub fn comittee(&self) -> &[PublicKey] {
        &self.comittee
    }

    pub fn operator_pubkey(&self) -> PublicKey {
        self.operator_pubkey
    }
}
