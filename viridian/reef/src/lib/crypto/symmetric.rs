use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{AeadCore, Key, KeyInit, XNonce, XChaCha20Poly1305};
use rand::rngs::OsRng;

use simple_error::bail;

use crate::DynResult;


const NONCE_LEN: usize = 24;
const MAC_LEN: usize = 16;


pub struct Symmetric {
    cipher: XChaCha20Poly1305,
}

// TODO: use inplace
impl Symmetric {
    pub fn new(key: &[u8; 32]) -> Symmetric {
        let symmetric_key = Key::from_slice(key);
        let cipher = XChaCha20Poly1305::new(symmetric_key);
        Symmetric { 
            cipher
        }
    }

    pub fn ciphertext_overhead() -> usize {
        NONCE_LEN + MAC_LEN
    }

    pub fn encrypt(&self, plaintext: &[u8], additional_data: Option<&[u8]>) -> DynResult<Vec<u8>> {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let payload = Payload {
            msg: plaintext,
            aad: additional_data.unwrap_or(&[]),
        };
        Ok(match self.cipher.encrypt(&nonce, payload) {
            Ok(res) => [nonce.to_vec(), res].concat(),
            Err(err) => bail!("Error encrypting plaintext: {err}")
        })
    }

    pub fn decrypt(&self, ciphertext_with_nonce: &[u8], additional_data: Option<&[u8]>) -> DynResult<Vec<u8>> {
        let nonce = XNonce::from_slice(&ciphertext_with_nonce[NONCE_LEN..]);
        let payload = Payload {
            msg: &ciphertext_with_nonce[..NONCE_LEN],
            aad: additional_data.unwrap_or(&[]),
        };
        Ok(match self.cipher.decrypt(nonce, payload) {
            Ok(res) => res,
            Err(err) => bail!("Error decrypting ciphertext: {err}!")
        })
    }
}
