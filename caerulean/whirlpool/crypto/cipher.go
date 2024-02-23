package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Generate XChaCha20-Poly1305 cipher AEAD and key.
// Return AEAD, key (32 bytes) and nil if AEAD is generated successfully, otherwise nil, nil and error.
func GenerateCipher() (cipher.AEAD, error) {
	// Generate random bytes for key
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("symmetrical key reading error: %v", err)
	}

	// Generate AEAD using random bytes
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("symmetrical key creation error: %v", err)
	}

	// Return AEAD, key and no error
	return aead, nil
}

// Parse XChaCha20-Poly1305 cipher AEAD from bytes.
// Accept 32 byte key.
// Return AEAD and nil if parsed successfully, otherwise nil and error.
func ParseCipher(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("symmetrical key parsing error: %v", err)
	}

	return aead, nil
}

// Encrypt bytes with given XChaCha20-Poly1305 AEAD.
// Generate nonce, composed of signature argument concatenated with some random bytes (nonce size: 24 bytes).
// Use the nonce and AEAD argument to encrypt plaintext, then concatenate nonce with ciphertext.
// Accept: plaintext (as bytes), signature (as bytes [0 <= N <= 24] or nil) and cipher AEAD.
// Return ciphertext and nil if encrypting was successful, otherwise nil and error.
func Encrypt(plaintext []byte, aead cipher.AEAD) ([]byte, error) {
	// Concatenate signature with random bytes to form nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce[:aead.NonceSize()]); err != nil {
		return nil, fmt.Errorf("symmetrical encrypting error: %v", err)
	}

	// Concatenate signature, rest of the nonce and ciphertext
	encrypted := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, encrypted...), nil
}

// Decrypt bytes with given XChaCha20-Poly1305 AEAD.
// Read nonce (first 24 bytes of ciphertext), then decrypt ciphertext.
// Accept: ciphertext (as bytes) and cipher AEAD.
// Return plaintext and nil if decrypting was successful, otherwise nil and error.
func Decrypt(ciphertext []byte, aead cipher.AEAD) ([]byte, error) {
	// Check ciphertext length is at least greater than nonce and overhead size
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("ciphertext length %d too short (less than nonce length %d + overhead %d)", len(ciphertext), aead.NonceSize(), aead.Overhead())
	}

	// Split ciphertext into ciphertext and nonce, decrypt ciphertext
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	result, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("symmetrical decrypting error: %v", err)
	}

	// Return plaintext and no error
	return result, nil
}
