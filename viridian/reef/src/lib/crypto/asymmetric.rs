use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use rand::RngCore;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::bytes::ByteBuffer;
use crate::crypto::symmetric::Symmetric;
use crate::rng::get_rng;
use crate::DynResult;

const SYMMETRIC_HASH_SIZE: usize = 32;
const PUBLIC_KEY_SIZE: usize = 32;
const SEED_SIZE: usize = 8;
const N_SIZE: usize = 2;

#[inline]
fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

pub struct Asymmetric {
    public_key: PublicKey,
    seed_key: [u8; 8],
}

impl Asymmetric {
    pub fn new(key: &ByteBuffer) -> DynResult<Self> {
        let asymmetric_key = key.slice();
        let private_bytes = <[u8; PUBLIC_KEY_SIZE]>::try_from(&asymmetric_key[..PUBLIC_KEY_SIZE])?;
        let seed_key = <[u8; SEED_SIZE]>::try_from(&asymmetric_key[PUBLIC_KEY_SIZE..])?;
        Ok(Self { public_key: PublicKey::from(private_bytes), seed_key })
    }

    #[inline]
    pub fn public_key(&self) -> ByteBuffer<'_> {
        [self.public_key.as_bytes(), self.seed_key.as_ref()].concat().into()
    }

    #[inline]
    pub fn ciphertext_overhead() -> usize {
        N_SIZE + PUBLIC_KEY_SIZE + Symmetric::ciphertext_overhead()
    }

    fn compute_blake2b_hash(&self, shared_secret: &SharedSecret, client_key: &ByteBuffer, server_key: &PublicKey) -> DynResult<ByteBuffer<'_>> {
        let hash = ByteBuffer::empty(SYMMETRIC_HASH_SIZE);
        let mut state = Blake2bVar::new(SYMMETRIC_HASH_SIZE)?;
        state.update(&shared_secret.to_bytes());
        state.update(&client_key.slice());
        state.update(&server_key.to_bytes());
        state.finalize_variable(&mut hash.slice_mut())?;
        Ok(hash)
    }

    fn hide_public_key(&self, public_key: &ByteBuffer) -> DynResult<ByteBuffer<'_>> {
        let mut state = Blake2bVar::new(SYMMETRIC_HASH_SIZE)?;
        let result = ByteBuffer::empty(N_SIZE + SYMMETRIC_HASH_SIZE);
        let (n_number, hash) = result.split_buf(N_SIZE);
        get_rng().fill_bytes(&mut n_number.slice_mut());
        state.update(&n_number.slice());
        state.update(&self.seed_key);
        state.finalize_variable(&mut hash.slice_mut())?;
        xor_bytes(&mut hash.slice_mut(), &public_key.slice());
        Ok(result)
    }

    pub fn encrypt<'a>(&self, plaintext: ByteBuffer<'a>) -> DynResult<(ByteBuffer<'_>, ByteBuffer<'a>)> {
        let ephemeral_secret = EphemeralSecret::random_from_rng(get_rng());
        let ephemeral_public = ByteBuffer::from(&PublicKey::from(&ephemeral_secret).to_bytes()[..]);
        let shared_secret = ephemeral_secret.diffie_hellman(&self.public_key);
        let symm_key = self.compute_blake2b_hash(&shared_secret, &ephemeral_public, &self.public_key)?;
        let hidden_public = self.hide_public_key(&ephemeral_public)?;
        let ciphertext = Symmetric::new(&symm_key)?.encrypt(plaintext, Some(&ephemeral_public))?;
        Ok((symm_key, ciphertext.prepend_buf(&hidden_public)))
    }
}
