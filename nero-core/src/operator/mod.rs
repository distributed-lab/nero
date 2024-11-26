use bitcoin::{
    key::Secp256k1, relative::Height, secp256k1::PublicKey, taproot::LeafVersion, Amount, FeeRate,
    Network, Transaction, TxIn, TxOut,
};
use bitcoin_splitter::split::script::SplitableScript;
use musig2::{
    aggregate_partial_signatures,
    secp::Point,
    secp256k1::{All, SecretKey},
    AggNonce, CompactSignature, PartialSignature, PubNonce, SecNonce, SecNonceBuilder,
};

use crate::{
    assert::{Assert, SignedAssert},
    challenge::{Challenge, SignedChallenge},
    claim::{Claim, FundedClaim},
    context::Context,
    disprove::{Disprove, SignedDisprove},
    payout::{Payout, PayoutOptimistic, SignedPayout, SignedPayoutOptimistic},
    treepp::*,
};

pub struct OperatorConfig<Seed> {
    /// Network which this session is working.
    pub network: Network,
    /// Stacked amount mentioned in paper as $d$.
    pub staked_amount: Amount,
    /// $x$ - the input of the program flow asserts.
    pub input: Script,
    /// Claim transaction challenge period.
    pub claim_challenge_period: Height,
    /// Assert transaction challenge period.
    pub assert_challenge_period: Height,
    /// Public keys of comitte for emulating covenants.
    pub comittee: Vec<PublicKey>,
    /// Operator's wallet address
    pub operator_script_pubkey: Script,
    /// Seed for random generator.
    pub seed: Seed,
}

/// Operator controls signing and creation of transaction for particular
/// BitVM2 session.
pub struct Operator<S: SplitableScript> {
    /// New secret key generated for this session.
    secret_key: SecretKey,

    /// Context holds all created before the session data.
    context: Context<S, All>,
}

impl<S> Operator<S>
where
    S: SplitableScript,
{
    pub fn new<Seed, Rng>(config: OperatorConfig<Seed>) -> Self
    where
        Seed: Sized + Default + AsMut<[u8]> + Copy,
        Rng: rand::SeedableRng<Seed = Seed> + rand::Rng,
    {
        // FIXME(Velnbur): This RNG is generated from seed twice later. Should be
        // fixed later.
        let mut rng = Rng::from_seed(config.seed);
        let secp_ctx = Secp256k1::new();

        let (seckey, pubkey) = secp_ctx.generate_keypair(&mut rng);

        let ctx = Context::compute_setup::<Seed, Rng>(
            secp_ctx,
            config.staked_amount,
            config.input,
            config.assert_challenge_period,
            config.claim_challenge_period,
            pubkey,
            config.operator_script_pubkey,
            config.comittee,
            config.seed,
        );

        Self {
            secret_key: seckey,
            context: ctx,
        }
    }

    /// Create new operator with one random spendable disprove script.
    pub fn new_distorted<Seed, Rng>(config: OperatorConfig<Seed>) -> Self
    where
        Seed: Sized + Default + AsMut<[u8]> + Copy,
        Rng: rand::SeedableRng<Seed = Seed> + rand::Rng,
    {
        // FIXME(Velnbur): This RNG is generated from seed twice later. Should be
        // fixed later.
        let mut rng = Rng::from_seed(config.seed);
        let secp_ctx = Secp256k1::new();

        let (seckey, pubkey) = secp_ctx.generate_keypair(&mut rng);

        let ctx = Context::compute_setup_distorted::<Seed, Rng>(
            secp_ctx,
            config.staked_amount,
            config.input,
            config.assert_challenge_period,
            config.claim_challenge_period,
            pubkey,
            config.operator_script_pubkey,
            config.comittee,
            config.seed,
        );

        Self {
            secret_key: seckey,
            context: ctx,
        }
    }

    pub fn context(&self) -> &Context<S, All> {
        &self.context
    }

    pub fn secret_key(&self) -> SecretKey {
        self.secret_key
    }
}

/* STAGE 1: */

/// Initial state before the claim transaction is funded.
///
/// From claim transaction id, will be built the next transcations, so
/// it's required to fund it from outside with some wallet before the
/// creation of other transactions as with additional input the claim
/// transaction id changes.
pub struct UnfundedOperator<S: SplitableScript> {
    inner: Operator<S>,
    claim: Claim,
}

impl<S: SplitableScript> UnfundedOperator<S> {
    pub fn from_operator(operator: Operator<S>, fee_rate: FeeRate) -> Self {
        let claim = Claim::from_context(&operator.context, fee_rate);

        Self {
            inner: operator,
            claim,
        }
    }

    /// Returns unsigned claim transcation without any inputs for funding
    /// through external wallet.
    pub fn unsigned_claim_tx(&self) -> Transaction {
        self.claim.to_unsigned_tx(&self.inner.context.secp)
    }
}

/* STAGE 3: */

/// After challenge transaction is signed by wallet, operator and comitte
/// can exchange nonces for partial schnorr signatures.
pub struct NoncesAggregationOperator<S: SplitableScript> {
    inner: Operator<S>,
    // Funded, signed by wallet claim transcation.
    claim: FundedClaim,
    challenge_tx: SignedChallenge,
    /// Secnonce generated from musig2 signature.
    operator_secnonce: SecNonce,
}

impl<S: SplitableScript> NoncesAggregationOperator<S> {
    pub fn from_unfunded_operator<Rng>(
        operator: UnfundedOperator<S>,
        funding_input: Vec<TxIn>,
        change_output: TxOut,
        fee_rate: FeeRate,
        rng: &mut Rng,
    ) -> Self
    where
        Rng: rand::RngCore + rand::CryptoRng,
    {
        let context = &operator.inner.context;
        let agg_pubkey = context.comittee_aggpubkey::<Point>();

        let funded_claim = FundedClaim::new(
            operator.claim,
            funding_input,
            change_output,
            context.input.clone(),
        );
        let claim_txid = funded_claim.compute_txid(&context.secp);

        let assert_tx_weight = context.assert_tx_weight;

        // Find the disprove transaction with largest weight,
        // so we can calculate how much fee will be payed for it
        // in worst case.
        let largest_disprove_weight = context
            .disprove_weights
            .iter()
            .max()
            .expect("At least one disprove script must be");

        let challenge_tx = Challenge::new(
            context.operator_script_pubkey.clone(),
            claim_txid,
            fee_rate
                .checked_mul_by_weight(*largest_disprove_weight + assert_tx_weight)
                .unwrap(),
        );

        let secnonce = SecNonceBuilder::new(rng)
            .with_seckey(operator.inner.secret_key)
            .with_aggregated_pubkey(agg_pubkey)
            .build();

        Self {
            challenge_tx: challenge_tx.sign(
                &context.secp,
                &funded_claim.challenge_output(&context.secp),
                operator.inner.secret_key,
            ),
            inner: operator.inner,
            claim: funded_claim,
            operator_secnonce: secnonce,
        }
    }

    /// Public nonce of the operator.
    pub fn public_nonce(&self) -> PubNonce {
        self.operator_secnonce.public_nonce()
    }
}

/* STAGE 4: */

/// After nonces are exchanged, operator can create partial signatures for
/// transaction and wait for other signatures from comittee.
pub struct SignaturesAggOperator<S: SplitableScript> {
    inner: Operator<S>,
    // Funded, signed by wallet claim transcation.
    claim_tx: FundedClaim,
    // Challenge is signed by oparator
    challenge_tx: SignedChallenge,
    /// Aggregated nonce for schnorr signing created from operator's secret
    /// nonce and comittee public nonces.
    aggnonce: AggNonce,

    /* partial signatures created by operator */
    partial_assert_sig: PartialSignature,
    partial_payout_optimistic_sig: PartialSignature,
    partial_payout_sig: PartialSignature,
    partial_disprove_sigs: Vec<PartialSignature>,

    /* Txs lower are waiting for signing from comittee. */
    assert_tx: Assert,
    payout_optimistic_tx: PayoutOptimistic,
    payout_tx: Payout,
    disprove_txs: Vec<Disprove>,
}

impl<S> SignaturesAggOperator<S>
where
    S: SplitableScript,
{
    /// Construct next stage of operator by including funding input to claim
    /// transaction.
    pub fn from_nonces_agg_operator(
        operator: NoncesAggregationOperator<S>,
        mut nonces: Vec<PubNonce>,
        fee_rate: FeeRate,
    ) -> Self {
        let context = &operator.inner.context;
        let claim_txid = operator.claim.compute_txid(&context.secp);
        nonces.push(operator.public_nonce());
        let aggnonce = AggNonce::sum(nonces);

        // Create and sign Optimistic Payout
        let payout_optimistic_tx = PayoutOptimistic::from_context(context, claim_txid);
        let partial_payout_optimistic_sig = payout_optimistic_tx.sign_partial_from_claim(
            &context.secp,
            &operator.claim,
            context.comittee.clone(),
            &aggnonce,
            operator.inner.secret_key,
            operator.operator_secnonce.clone(),
        );

        // Sign and create Assert tx.
        let assert_tx_amount = context.staked_amount
            + fee_rate
                .checked_mul_by_weight(*context.disprove_weights.iter().max().unwrap())
                .unwrap();
        let assert_tx = Assert::new(
            &context.disprove_scripts,
            context.operator_pubkey.into(),
            context.assert_challenge_period,
            claim_txid,
            context.comittee_aggpubkey(),
            assert_tx_amount,
        );
        let partial_assert_sig = assert_tx.sign_partial_from_claim(
            &context.secp,
            &operator.claim,
            context.comittee.clone(),
            &aggnonce,
            operator.inner.secret_key,
            operator.operator_secnonce.clone(),
        );
        let assert_txid = assert_tx.compute_txid(&context.secp);

        // Create and sign payout transaction.
        let payout_tx = Payout::from_context(context, assert_txid);
        let partial_payout_sig = payout_tx.sign_partial_from_assert(
            &context.secp,
            &assert_tx,
            context.comittee.clone(),
            &aggnonce,
            operator.inner.secret_key,
            operator.operator_secnonce.clone(),
        );

        // Create and sign disprove transaction.
        let assert_output = assert_tx.output(&context.secp);
        let taproot = assert_tx.taproot(&context.secp);
        let (partial_disprove_sigs, disprove_txs): (Vec<_>, Vec<_>) = context
            .disprove_scripts
            .iter()
            .map(|script| {
                let script_pubkey = script.to_script_pubkey();
                let tx = Disprove::new(
                    script,
                    assert_txid,
                    taproot
                        // TODO(Velnbur): another place which clones a
                        // large chunk of memory just for getting a
                        // control block. We should create a PR in
                        // rust-bitcoin to avoid that.
                        .control_block(&(script_pubkey, LeafVersion::TapScript))
                        .unwrap(),
                );

                (
                    tx.sign_partial(
                        &context.secp,
                        &assert_output,
                        context.comittee.clone(),
                        &aggnonce,
                        operator.inner.secret_key,
                        operator.operator_secnonce.clone(),
                    ),
                    tx,
                )
            })
            .unzip();

        Self {
            inner: operator.inner,
            claim_tx: operator.claim,
            challenge_tx: operator.challenge_tx,
            assert_tx,
            partial_assert_sig,
            partial_payout_optimistic_sig,
            partial_payout_sig,
            partial_disprove_sigs,
            payout_optimistic_tx,
            payout_tx,
            aggnonce,
            disprove_txs,
        }
    }

    pub fn unsigned_assert_tx(&self) -> &Assert {
        &self.assert_tx
    }

    pub fn unsigned_payout_optimistic(&self) -> &PayoutOptimistic {
        &self.payout_optimistic_tx
    }

    pub fn unsigned_payout_optimistic_tx(&self) -> Transaction {
        self.payout_optimistic_tx.to_unsigned_tx()
    }

    pub fn unsigned_payout_tx(&self) -> &Payout {
        &self.payout_tx
    }

    pub fn unsigned_disprove_txs(&self) -> &[Disprove] {
        &self.disprove_txs
    }

    pub fn aggnonce(&self) -> &AggNonce {
        &self.aggnonce
    }

    pub fn context(&self) -> &Context<S, All> {
        self.inner.context()
    }

    pub fn claim_tx(&self) -> &FundedClaim {
        &self.claim_tx
    }

    pub fn challenge_tx(&self) -> &SignedChallenge {
        &self.challenge_tx
    }
}

/* STAGE 5: */

/// After receiving all partial signature from comittee operator can
/// construct final "signed" versions of transaction and publish the claim
/// one.
pub struct FinalOperator<S: SplitableScript> {
    inner: Operator<S>,

    claim_tx: FundedClaim,

    challenge_tx: SignedChallenge,

    assert_tx: SignedAssert,

    payout_optimistic_tx: SignedPayoutOptimistic,

    payout_tx: SignedPayout,

    disprove_txs: Vec<SignedDisprove>,
}

pub struct PartialSignatures {
    /// Partial signatures for assert transaction.
    pub partial_assert_sigs: Vec<PartialSignature>,
    /// Partial signatures for payout optimitstic transaction.
    pub partial_payout_optimistic_sigs: Vec<PartialSignature>,
    /// Partial signatures for payout transaction.
    pub partial_payout_sigs: Vec<PartialSignature>,
    /// Partial signatures for disprove transactions.
    pub partial_disprove_sigs: Vec<Vec<PartialSignature>>,
}

impl PartialSignatures {
    /// Merge operator signatures into partial signatures got from comittee.
    pub fn merge_operator_sigs(
        &mut self,
        partial_assert_sig: PartialSignature,
        partial_payout_optimistic_sig: PartialSignature,
        partial_payout_sig: PartialSignature,
        partial_disprove_sigs: Vec<PartialSignature>,
    ) {
        self.partial_assert_sigs.push(partial_assert_sig);
        self.partial_payout_sigs.push(partial_payout_sig);
        self.partial_payout_optimistic_sigs
            .push(partial_payout_optimistic_sig);

        for (sigs, sig) in self
            .partial_disprove_sigs
            .iter_mut()
            .zip(partial_disprove_sigs)
        {
            sigs.push(sig);
        }
    }
}

impl<S: SplitableScript> FinalOperator<S> {
    /// Construct next stage of operator by including the partial signatures
    /// for all transaciton.
    pub fn from_signatures_agg_operator(
        operator: SignaturesAggOperator<S>,
        mut signatures: PartialSignatures,
    ) -> Self {
        signatures.merge_operator_sigs(
            operator.partial_assert_sig,
            operator.partial_payout_optimistic_sig,
            operator.partial_payout_sig,
            operator.partial_disprove_sigs,
        );
        //  setup variables
        let context = &operator.inner.context;
        let keyaggctx = context.comittee_keyaggctx();

        let claim_assert_script_control_block =
            operator.claim_tx.assert_script_control_block(&context.secp);

        let claim_payout_script = operator.claim_tx.optimistic_payout_script();
        let claim_payout_control_block = operator
            .claim_tx
            .optimistic_payout_script_control_block(&context.secp);

        let assert_sighash = operator.assert_tx.sighash(
            &context.secp,
            &operator.claim_tx.assert_output(&context.secp),
            operator.claim_tx.assert_script(),
        );
        let assert_aggsig: CompactSignature = aggregate_partial_signatures(
            &keyaggctx,
            &operator.aggnonce,
            signatures.partial_assert_sigs,
            assert_sighash,
        )
        .unwrap();
        let assert_txout = &operator.assert_tx.output(&context.secp);
        let assert_tx = SignedAssert::new(
            operator.assert_tx,
            assert_aggsig,
            operator.claim_tx.assert_script(),
            claim_assert_script_control_block,
        );

        let payout_sighash =
            operator
                .payout_tx
                .sighash(&context.secp, assert_txout, assert_tx.payout_script());
        let payout_aggsig: CompactSignature = aggregate_partial_signatures(
            &keyaggctx,
            &operator.aggnonce,
            signatures.partial_payout_sigs,
            payout_sighash,
        )
        .unwrap();
        let payout_operator_sig = operator.payout_tx.sign_operator(
            &context.secp,
            assert_txout,
            assert_tx.payout_script(),
            &operator.inner.secret_key,
        );
        let payout_tx = SignedPayout::new(
            operator.payout_tx,
            assert_tx.payout_script().clone(),
            assert_tx.payout_script_control_block(&context.secp),
            payout_aggsig,
            payout_operator_sig,
        );

        let disprove_txs = operator
            .disprove_txs
            .into_iter()
            .zip(signatures.partial_disprove_sigs)
            .map(|(tx, sigs)| {
                let sighash = tx.sighash(assert_txout);

                let covenants_sig: CompactSignature =
                    aggregate_partial_signatures(&keyaggctx, &operator.aggnonce, sigs, sighash)
                        .unwrap();

                SignedDisprove::new(tx, covenants_sig)
            })
            .collect::<Vec<_>>();

        let payout_optimistic_assert_output_sighash = operator.payout_optimistic_tx.assert_sighash(
            &operator.claim_tx.assert_output(&context.secp),
            &operator.claim_tx.challenge_output(&context.secp),
            &claim_payout_script,
        );
        let payout_optimistic_aggsig: CompactSignature = aggregate_partial_signatures(
            &keyaggctx,
            &operator.aggnonce,
            signatures.partial_payout_optimistic_sigs,
            payout_optimistic_assert_output_sighash,
        )
        .unwrap();

        let payout_optimistic_operator_sig = operator.payout_optimistic_tx.sign_challenge_input(
            &operator.claim_tx.assert_output(&context.secp),
            &operator.claim_tx.challenge_output(&context.secp),
            &context.secp,
            operator.inner.secret_key,
        );
        let payout_optimistic_tx = SignedPayoutOptimistic::new(
            operator.payout_optimistic_tx,
            payout_optimistic_aggsig,
            payout_optimistic_operator_sig,
            &claim_payout_script,
            claim_payout_control_block,
        );

        FinalOperator {
            inner: operator.inner,
            claim_tx: operator.claim_tx,
            challenge_tx: operator.challenge_tx,
            assert_tx,
            payout_optimistic_tx,
            payout_tx,
            disprove_txs,
        }
    }

    pub fn disprove_txs(&self) -> &[SignedDisprove] {
        &self.disprove_txs
    }

    pub fn claim_tx(&self) -> &FundedClaim {
        &self.claim_tx
    }

    pub fn challenge_tx(&self) -> &SignedChallenge {
        &self.challenge_tx
    }

    pub fn assert_tx(&self) -> &SignedAssert {
        &self.assert_tx
    }

    pub fn payout_optimistic_tx(&self) -> &SignedPayoutOptimistic {
        &self.payout_optimistic_tx
    }

    pub fn payout_tx(&self) -> &SignedPayout {
        &self.payout_tx
    }

    pub fn inner(&self) -> &Operator<S> {
        &self.inner
    }
}
