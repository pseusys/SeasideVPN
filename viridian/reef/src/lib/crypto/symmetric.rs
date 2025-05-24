use chacha20poly1305::aead::AeadMutInPlace;
use chacha20poly1305::{AeadCore, Key, KeyInit, XNonce, XChaCha20Poly1305};

use simple_error::bail;

use crate::bytes::ByteBuffer;
use crate::rng::get_rng;
use crate::DynResult;


// TODO: move it!
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const MAC_LEN: usize = 16;


pub struct Symmetric {
    cipher: XChaCha20Poly1305,
}

impl Symmetric {
    pub fn new(key: &ByteBuffer) -> DynResult<Symmetric> {
        let private_bytes = <[u8; KEY_LEN]>::try_from(&key.slice()[..])?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&private_bytes));
        Ok(Symmetric { 
            cipher
        })
    }

    #[inline]
    pub fn ciphertext_overhead() -> usize {
        NONCE_LEN + MAC_LEN
    }

    pub fn encrypt<'a>(&mut self, plaintext: &mut ByteBuffer<'a>, additional_data: Option<&ByteBuffer>) -> DynResult<ByteBuffer<'a>> {
        let nonce = XChaCha20Poly1305::generate_nonce(get_rng());
        let result = match additional_data {
            Some(res) => self.cipher.encrypt_in_place(&nonce, &res.slice(), plaintext),
            None => self.cipher.encrypt_in_place(&nonce, &[], plaintext),
        };
        match result {
            Ok(_) => Ok(plaintext.prepend(&nonce)),
            Err(err) => bail!("Error encrypting plaintext: {err}")
        }
    }

    pub fn decrypt<'a>(&mut self, ciphertext_with_nonce: &mut ByteBuffer<'a>, additional_data: Option<&ByteBuffer>) -> DynResult<ByteBuffer<'a>> {
        let (mut ciphertext, nonce_bytes) = ciphertext_with_nonce.split_buf(NONCE_LEN as isize);
        let nonce_slice = nonce_bytes.slice();
        let nonce = XNonce::from_slice(&nonce_slice);
        let result = match additional_data {
            Some(res) => self.cipher.decrypt_in_place(&nonce, &res.slice(), &mut ciphertext),
            None => self.cipher.decrypt_in_place(&nonce, &[], &mut ciphertext),
        };
        match result {
            Ok(_) => Ok(ciphertext),
            Err(err) => bail!("Error encrypting plaintext: {err}")
        }
    }
}

impl Clone for Symmetric {
    fn clone(&self) -> Self {
        Self { cipher: self.cipher.clone() }
    }
}
