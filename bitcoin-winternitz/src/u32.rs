//! Special Winternitz implementation for u32 message.

use bitcoin_utils::treepp::*;

use bitcoin::hashes::hash160::Hash as Hash160;
use bitcoin::hashes::Hash;

/// Fixed value of $d$ specified in original doc.
///
/// This value is used to set [`BITS_PER_DIGIT`] of digits the algorithm
/// splits message by.
pub const D: usize = 15;

pub const BITS_PER_DIGIT: usize = (D + 1).ilog2() as usize;

/// Number of bits in the message.
pub const V: usize = 31;

/// The number of partitions without checksum
pub const N0: usize = V.div_ceil(BITS_PER_DIGIT);

/// The number of partinitions of checksum
pub const N1: usize = ((D * N0).ilog(D + 1) + 1) as usize;

/// The total number of partitions.
pub const N: usize = N0 + N1;

/// Secret key is array of $N$ chunks by $D$ bits, where the whole number
/// of bits is equal to $v$.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct SecretKey([Hash160; N]);

impl SecretKey {
    /// Construct new [`SecretKey`] from given secret parts.
    pub const fn new(chunks: [Hash160; N]) -> Self {
        Self(chunks)
    }

    #[cfg(feature = "rand")]
    /// Contruct new [`SecretKey`] randomly
    pub fn random<Rng>(rng: &mut Rng) -> Self
    where
        Rng: rand::Rng,
    {
        let mut buf = [Hash160::all_zeros(); N];

        for chunk in &mut buf {
            *chunk = Hash160::from_byte_array(rng.gen());
        }

        Self(buf)
    }

    #[cfg(feature = "rand")]
    /// Construct new [`SecretKey`] from seed, by generating required
    /// number of parts (chunks).
    pub fn from_seed<Seed, Rng>(seed: Seed) -> Self
    where
        Seed: Sized + Default + AsMut<[u8]>,
        Rng: rand::SeedableRng<Seed = Seed> + rand::Rng,
    {
        let mut rng = Rng::from_seed(seed);
        Self::random(&mut rng)
    }

    /// Return public key derived from secret one.
    pub fn public_key(&self) -> PublicKey {
        let mut buf = self.0;

        for element in &mut buf {
            for _ in 0..D {
                *element = Hash160::hash(element.to_byte_array().as_slice());
            }
        }

        PublicKey(buf)
    }

    /// Generate [`Signature`] from [`Message`].
    pub fn sign(&self, msg: Message) -> Signature {
        let mut buf = [Hash160::all_zeros(); N];

        for (idx, (hash, times)) in self.0.iter().zip(msg.0.iter()).enumerate() {
            let mut hash = *hash;
            for _ in 0..*times {
                hash = Hash160::hash(hash.to_byte_array().as_slice());
            }
            buf[idx] = hash;
        }

        Signature { sig: buf, msg }
    }
}

/// Public key is a hashed $D$ times each of the $n$ parts of the
/// [`SecretKey`].
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct PublicKey([Hash160; N]);

impl PublicKey {
    /// Verify signature for given message.    
    pub fn verify(&self, msg: &Message, sig: &Signature) -> bool {
        for ((pubkey, times), sig) in self.0.iter().zip(msg.0.iter()).zip(sig.sig.iter()) {
            let mut hash = *sig;

            for _ in 0..(D - *times as usize) {
                hash = Hash160::hash(hash.to_byte_array().as_slice());
            }

            if hash != *pubkey {
                return false;
            }
        }

        true
    }

    /// Construct `script_pubkey` signature verification which uses compact
    /// implementation of msg encoding (which skips zero limbs).
    pub fn checksig_verify_script_compact(&self, msg: &Message) -> Script {
        let skip = msg.count_zero_limbs_from_left();
        checksig_verify_script_compact(skip, self)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default, Copy)]
pub struct Message([u8; N]);

impl Message {
    /// Returns message partition for u32.
    ///
    /// Under the hood uses bit masked to retrieve 4 bit parts from u32
    /// message.
    pub const fn from_u32(mut msg: u32) -> Self {
        debug_assert!(msg < (1 << V));
        const MASK: u32 = 0x0000000F;

        let mut buf = [0u8; N];

        // retrieve message partition
        let mut i = 0;
        let mut sum = 0u8;
        while i < N0 {
            let masked = msg & MASK;
            buf[i] = masked as u8;

            msg >>= BITS_PER_DIGIT;
            sum += buf[i];
            i += 1;
        }

        // calculate checksum and fill the next `buf` elements with
        // first and last 4 bits of it.
        let checksum = ((D * N0) as u8) - sum;
        buf[i] = checksum & 0x0F;
        buf[i + 1] = checksum >> 4;

        Self(buf)
    }

    /// Recover the message it was created from.
    pub const fn into_u32(self) -> u32 {
        let mut result = 0u32;
        let mut i = 0;

        while i < N0 {
            result |= (self.0[i] as u32) << (4 * i);
            i += 1;
        }

        result
    }

    /// Returns Bitcoin script which recovers the message from 4 bit parts
    /// placed on the stack, assuming that checksum was already
    /// excluded. Also, assuming that the least significant 4-bit part is at
    /// the top of the stack.
    ///
    /// # Algorithm
    ///
    /// Assuming that D=15, and `u32` is splitted into eight 4-bit parts named
    /// $p$, to recover the message $m$, depending on the part position $i$,
    /// the recovering is simply:
    ///
    /// \[
    /// m = \sum_{i=0}^{8} p * 2^{4 * i}
    /// \]
    ///
    /// As the upper bound for sum is fixed, the $2^{4 * i}$ are constants,
    /// and as Bitcoin lacks the `OP_MUL` opcode, we can instead make `OP_DUP`
    /// `OP_ADD` $4i$ times for each part and then sum the results.
    pub fn recovery_script() -> Script {
        Self::recovery_script_fixed_limbs(N0)
    }

    fn recovery_script_fixed_limbs(limbs_num: usize) -> Script {
        if limbs_num == 1 {
            return script! {};
        }

        script! {
            for i in 0..limbs_num {
                for _ in 0..(BITS_PER_DIGIT * i) {
                    OP_DUP
                    OP_ADD
                }
                // TODO(Velnbur): the last `OP_TOALTSTACK` is redundant, as
                // we getting it back in the next opcode, so later we can
                // optimize it.
                OP_TOALTSTACK
            }
            OP_FROMALTSTACK
            for _ in 0..limbs_num-1 {
                OP_FROMALTSTACK
                OP_ADD
            }
        }
    }

    /// The same as [`Self::recovery_script`] but recovers only "used" limbs.
    ///
    /// Unused limbs are zero one.
    pub fn recovery_script_compact(&self) -> Script {
        let unused = self.count_zero_limbs_from_left();

        Self::recovery_script_fixed_limbs(N0 - unused)
    }

    /// Returns the number of limbs which are equal to zero from the most
    /// significant bit excluding, the checksum limbs.
    ///
    /// If all limbs are zero, this function returns `N0-1`, thus the keeping
    /// at least one limb.
    pub fn count_zero_limbs_from_left(&self) -> usize {
        self.0
            .iter()
            .rev()
            .skip(N1)
            .take_while(|limb| **limb == 0)
            .count()
            .min(N0 - 1)
    }
}

/// Winternitz signature. The array of intermidiate hashes of secret key.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Signature {
    sig: [Hash160; N],
    msg: Message,
}

impl Signature {
    /// Creates bitcoin script with pushed to stack pairs of signature and
    /// number of times it was hashed.
    pub fn to_script_sig(self) -> Script {
        self.to_script_sig_skipping(0)
    }

    /// The same as [`Signature::to_script_sig`], but converts signature to
    /// witness stack elements instead of script.
    pub fn to_witness_stack_elements(self) -> Vec<Vec<u8>> {
        self.to_witness_stack_elements_skipping(0)
    }

    fn to_witness_stack_elements_skipping(self, skipping: usize) -> Vec<Vec<u8>> {
        let mut elements = Vec::new();

        // Keep all the elements of the checksum.
        for idx in (N0..(N0 + N1)).rev() {
            elements.push(self.sig[idx].to_byte_array().to_vec());
            elements.push(self.msg.0[idx].to_le_bytes().to_vec());
        }
        // Push the stack element limbs skipping some of them.
        for idx in (0..N0).rev().skip(skipping) {
            elements.push(self.sig[idx].to_byte_array().to_vec());
            elements.push(self.msg.0[idx].to_le_bytes().to_vec());
        }

        elements
    }

    /// The same as [`Self::to_script_sig`], but skips `skipping` number of
    /// limbs and sigs for zero limbs.
    fn to_script_sig_skipping(self, skipping: usize) -> Script {
        script! {
            // Keep all the elements of the checksum.
            for idx in (N0..(N0 + N1)).rev() {
                // TODO(Velnbur): we can get rid of additional allocation
                // here by implemention Pushable for all hash types from
                // Bitcoin crate. Do that after bitcoin-execscript fork.
                { self.sig[idx].to_byte_array().to_vec() }
                { self.msg.0[idx] }
            }
            // Push the stack element limbs skipping some of them.
            for idx in (0..N0).rev().skip(skipping) {
                { self.sig[idx].to_byte_array().to_vec() }
                { self.msg.0[idx] }
            }
        }
    }

    /// The same as [`Self::to_script_sig`], but skips equal to zero limbs
    /// from the left.
    pub fn to_script_sig_compact(self) -> Script {
        let skip = self.msg.count_zero_limbs_from_left();
        self.to_script_sig_skipping(skip)
    }
}

/// Returns the script which verifies the Winternitz signature (see
/// [`Signature`]) from top of the stack.
pub fn checksig_verify_script(public_key: &PublicKey) -> Script {
    checksig_verify_script_compact(0, public_key)
}

/// The same as [`checksig_verify_script`], but checks only
/// `N0-zero_limbs` of the stack element. Thus shortening the script.
pub fn checksig_verify_script_compact(zero_limbs: usize, public_key: &PublicKey) -> Script {
    script! {
        //
        // Verify the hash chain for each digit
        //

        // Repeat this for every of the n0-zero_limbs many digits
        for digit_index in 0..(N0 - zero_limbs) {
            { checksig_verify_limb_script(&public_key.0[digit_index]) }
        }

        // Repeat this for the checksum
        for digit_index in N0..(N0+N1) {
            { checksig_verify_limb_script(&public_key.0[digit_index]) }
        }

        //
        // Verify the Checksum
        //

        // 1. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        for _ in 0..N1 - 1 {
            for _ in 0..BITS_PER_DIGIT {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }

        // 2. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..(N0 - zero_limbs) {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { D * N0 }
        OP_ADD

        // Get result from step 1 by moving it to the top
        // of the stack.
        { N0 - zero_limbs + 1 }
        OP_ROLL

        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY
    }
}

/// Script for verifying single part of the signature from top of the
/// stack.
///
/// This script expects the one signature part and limb from top of the
/// stack.
fn checksig_verify_limb_script(pubkey: &Hash160) -> Script {
    script! {
        // Verify that the digit is in the range [0, d]
        // See https://github.com/BitVM/BitVM/issues/35
        { D }
        OP_MIN

        // Push two copies of the digit onto the altstack
        OP_DUP
        OP_TOALTSTACK
        OP_TOALTSTACK

        // Hash the input hash d times and put every result on the stack
        for _ in 0..D {
            OP_DUP OP_HASH160
        }

        // Verify the signature for this digit
        OP_FROMALTSTACK
        OP_PICK
        { pubkey.as_byte_array().to_vec() }
        OP_EQUALVERIFY

        // Drop the d+1 stack items
        for _ in 0..(D+1)/2 {
            OP_2DROP
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    #[test]
    fn test_message_partition() {
        const MSG: u32 = 0x02345678;
        const EXPECTED: [u8; N] = [0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x0, 0x5, 0x5];

        let got = Message::from_u32(MSG);

        assert_eq!(EXPECTED, got.0);
        assert_eq!(MSG, got.into_u32());
    }

    #[test]
    fn test_message_recovery_script() {
        let msg = Message::from_u32(0x2FEEDDCC);

        let recovery_script = Message::recovery_script();

        let script = script! {
            for part in msg.0.iter().take(N0).rev() {
                { *part }
            }

            { recovery_script }
            0x2FEEDDCC
            OP_EQUAL
        };

        let result = execute_script(script);

        println!("{}", result);

        assert!(result.success);
    }

    #[quickcheck]
    fn test_message_recovery_script_any(msg_int: u32) -> bool {
        let msg_int = msg_int >> 1;
        let msg = Message::from_u32(msg_int);

        let script = script! {
            for part in msg.0.iter().take(N0).rev() {
                { *part }
            }

            { Message::recovery_script() }
            { msg_int }
            OP_EQUAL
        };

        let result = execute_script(script);

        result.success
    }

    #[quickcheck]
    fn test_message_recovery_any(msg_int: u32) -> bool {
        let msg_int = msg_int >> 1;
        let msg = Message::from_u32(msg_int);

        println!("{:?}", msg);

        msg.into_u32() == msg_int
    }

    #[cfg(feature = "rand")]
    mod with_rand {
        use quickcheck::{Arbitrary, Gen};
        use quickcheck_macros::quickcheck;
        use rstest::rstest;

        use super::super::*;

        use rand::rngs::SmallRng;

        #[test]
        fn test_public_key_with_ripemd_160() {
            const MESSAGE: u32 = 0xFFFFFFF;

            let message = Message::from_u32(MESSAGE);

            let secret_key = SecretKey::from_seed::<_, SmallRng>([1u8; 32]);
            let public_key = secret_key.public_key();
            let signature = secret_key.sign(message);

            assert!(public_key.verify(&message, &signature));
        }

        #[test]
        fn test_signature_verification_in_script_works() {
            const MSG: u32 = 0x2FEEDDCC;
            let msg = Message::from_u32(MSG);

            let secret_key = SecretKey::from_seed::<_, SmallRng>([1u8; 32]);
            let public_key = secret_key.public_key();
            let signature = secret_key.sign(msg);

            let checksig_script = checksig_verify_script(&public_key);
            println!("ChecksigScript: {}", checksig_script.as_bytes().len());
            let recovery_script = Message::recovery_script();
            println!("RecoveryScript: {}", recovery_script.as_bytes().len());

            let script_sig = signature.to_script_sig();
            println!("ScriptSig: {}", script_sig.as_bytes().len());
            let script_pubkey = script! {
                { checksig_script }
                { recovery_script }
                { MSG }
                OP_EQUAL
            };

            println!("ScriptPubkey: {}", script_pubkey.as_bytes().len());
            let script = script! {
                { script_sig }
                { script_pubkey }
            };
            println!("Script: {}", script.as_bytes().len());
            let result = execute_script(script);
            println!("{}", result);

            assert!(result.success);
        }

        #[rstest]
        #[case(0x0EEEDDCC)]
        #[case(0x00EDDCC)]
        #[case(0x000DDCC)]
        #[case(0x0000DCC)]
        #[case(0x00000CC)]
        #[case(0x000000C)]
        #[case(0x0000000)]
        fn test_signature_compact_verification_in_script_works(#[case] msg_raw: u32) {
            let msg = Message::from_u32(msg_raw);

            let secret_key = SecretKey::from_seed::<_, SmallRng>([1u8; 32]);
            let public_key = secret_key.public_key();
            let signature = secret_key.sign(msg);

            let checksig_script = public_key.checksig_verify_script_compact(&msg);
            println!("ChecksigScript: {}", checksig_script.as_bytes().len());
            let recovery_script = msg.recovery_script_compact();
            println!("RecoveryScript: {}", recovery_script.as_bytes().len());

            let script_sig = signature.to_script_sig_compact();
            println!("ScriptSig: {}", script_sig.as_bytes().len());
            let script_pubkey = script! {
                { checksig_script }
                { recovery_script }
                { msg_raw }
                OP_EQUAL
            };

            println!("ScriptPubkey: {}", script_pubkey.as_bytes().len());
            let script = script! {
                { script_sig }
                { script_pubkey }
            };
            println!("Script: {}", script.as_bytes().len());
            let result = execute_script(script);
            println!("{}", result);

            assert!(result.success);
        }

        #[derive(Clone, Debug)]
        struct TestInput {
            seed: [u8; 32],
            msg: u32,
        }

        impl Arbitrary for TestInput {
            fn arbitrary(g: &mut Gen) -> Self {
                TestInput {
                    seed: [(); 32].map(|_| u8::arbitrary(g)),
                    msg: u32::arbitrary(g) >> 1,
                }
            }
        }

        #[quickcheck]
        fn test_any_msg_with_any_seed_works(TestInput { seed, msg }: TestInput) -> bool {
            let message = Message::from_u32(msg);

            let secret_key = SecretKey::from_seed::<_, SmallRng>(seed);
            let public_key = secret_key.public_key();

            let signature = secret_key.sign(message);

            public_key.verify(&message, &signature)
        }

        #[quickcheck]
        fn test_signature_verification_in_script_works_any(
            TestInput { seed, msg }: TestInput,
        ) -> bool {
            let message = Message::from_u32(msg);

            let secret_key = SecretKey::from_seed::<_, SmallRng>(seed);
            let public_key = secret_key.public_key();
            let signature = secret_key.sign(message);

            let checksig_script = checksig_verify_script(&public_key);
            let recovery_script = Message::recovery_script();

            let script_sig = signature.to_script_sig();
            let script_pubkey = script! {
                { checksig_script }
                { recovery_script }
                { msg }
                OP_EQUAL
            };

            let script = script! {
                { script_sig }
                { script_pubkey }
            };
            let result = execute_script(script);
            println!("{}", result);

            result.success
        }

        #[quickcheck]
        fn test_signature_compact_verification_in_script_works_any(
            TestInput { seed, msg }: TestInput,
        ) -> bool {
            let msg_raw = msg;
            let msg = Message::from_u32(msg_raw);

            let secret_key = SecretKey::from_seed::<_, SmallRng>(seed);
            let public_key = secret_key.public_key();
            let signature = secret_key.sign(msg);

            let checksig_script = public_key.checksig_verify_script_compact(&msg);
            println!("ChecksigScript: {}", checksig_script.as_bytes().len());
            let recovery_script = msg.recovery_script_compact();
            println!("RecoveryScript: {}", recovery_script.as_bytes().len());

            let script_sig = signature.to_script_sig_compact();
            println!("ScriptSig: {}", script_sig.as_bytes().len());
            let script_pubkey = script! {
                { checksig_script }
                { recovery_script }
                { msg_raw }
                OP_EQUAL
            };

            println!("ScriptPubkey: {}", script_pubkey.as_bytes().len());
            let script = script! {
                { script_sig }
                { script_pubkey }
            };
            println!("Script: {}", script.as_bytes().len());
            let result = execute_script(script);
            println!("{}", result);

            result.success
        }
    }
}
