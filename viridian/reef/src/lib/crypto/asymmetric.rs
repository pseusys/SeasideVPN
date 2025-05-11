use rand::rngs::OsRng;
use rand::RngCore;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::DynResult;
use super::symmetric::Symmetric;


const SYMMETRIC_HASH_SIZE: usize = 32;
const PUBLIC_KEY_SIZE: usize = 32;
const SEED_SIZE: usize = 8;
const N_SIZE: usize = 2;


fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}


pub struct Asymmetric {
    public_key: PublicKey,
    seed_key: [u8; SEED_SIZE],
}

impl Asymmetric {
    pub fn new(key: &[u8; PUBLIC_KEY_SIZE + SEED_SIZE]) -> DynResult<Asymmetric> {
        let private_bytes = <[u8; 32]>::try_from(&key[..PUBLIC_KEY_SIZE])?;
        let public_key = PublicKey::from(private_bytes);
        let seed_key = <[u8; 8]>::try_from(&key[PUBLIC_KEY_SIZE..])?;
        Ok(Asymmetric {
            public_key,
            seed_key,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        [self.public_key.as_bytes(), self.seed_key.as_ref()].concat()
    }

    pub fn ciphertext_overhead() -> usize {
        N_SIZE + PUBLIC_KEY_SIZE + Symmetric::ciphertext_overhead()
    }

    fn compute_blake2b_hash(&self, shared_secret: &[u8], client_key: &[u8], server_key: &[u8]) -> DynResult<[u8; SYMMETRIC_HASH_SIZE]> {
        let mut hash = [0u8; SYMMETRIC_HASH_SIZE];
        let mut state = Blake2bVar::new(SYMMETRIC_HASH_SIZE)?;
        state.update(shared_secret);
        state.update(client_key);
        state.update(server_key);
        state.finalize_variable(&mut hash)?;
        Ok(hash)
    }

    fn hide_public_key(&self, public_key: &[u8]) -> DynResult<Vec<u8>> {
        let mut number_n = [0u8; N_SIZE];
        OsRng.fill_bytes(&mut number_n);
        let mut blake = [0u8; SYMMETRIC_HASH_SIZE];
        let mut state = Blake2bVar::new(SYMMETRIC_HASH_SIZE)?;
        state.update(&number_n);
        state.update(&self.seed_key);
        state.finalize_variable(&mut blake)?;
        Ok([number_n.as_ref(), &xor_bytes(public_key, &blake)].concat())
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> DynResult<(Vec<u8>, Vec<u8>)> {
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
        let shared_secret = ephemeral_secret.diffie_hellman(&self.public_key);
        let symm_key = self.compute_blake2b_hash(shared_secret.as_bytes(), &ephemeral_public, self.public_key.as_bytes())?;
        let hidden_public = self.hide_public_key(&ephemeral_public)?;
        let ciphertext = Symmetric::new(&symm_key).encrypt(plaintext, Some(&ephemeral_public))?;
        Ok((symm_key.to_vec(), [hidden_public, ciphertext].concat()))
    }
}
