package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"main/utils"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// Private node XChaCha20-Poly1305 key: used for viridian token signing.
	PRIVATE_NODE_KEY []byte

	// Private node AEAD (build from private node key).
	PRIVATE_NODE_AEAD cipher.AEAD

	// Public node XChaCha20-Poly1305 key: used for viridian control requests signing.
	PUBLIC_NODE_AEAD cipher.AEAD
)

// Initialize package variables from environment variables.
func init() {
	// Read public key hexadecimal string from environment variable
	publicKeyHex := utils.GetEnv("SEASIDE_PUBLIC")

	// Decode public key hexadecimal string to bytes
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		logrus.Fatalf("Error parsing public key bytes: %v (%s)", err, publicKeyHex)
	}

	// Create public node AEAD using parsed key
	PUBLIC_NODE_AEAD, err = ParseCipher(publicKeyBytes)
	if err != nil {
		logrus.Fatalf("Error parsing public aead: %v (%s)", err, publicKeyHex)
	}
}

// Generate XChaCha20-Poly1305 cipher AEAD and key.
// Return AEAD, key (32 bytes) and nil if AEAD is generated successfully, otherwise nil, nil and error.
func GenerateCipher() (cipher.AEAD, []byte, error) {
	// Generate random bytes for key
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("symmetrical key reading error: %v", err)
	}

	// Generate AEAD using random bytes
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("symmetrical key creation error: %v", err)
	}

	// Return AEAD, key and no error
	return aead, key, nil
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

// Encode bytes with given XChaCha20-Poly1305 AEAD.
// NB! Encoding (unlike encrypting) doesn't include neither entailing nor signing.
// Generate nonce, composed of signature argument concatenated with some random bytes (nonce size: 24 bytes).
// Use the nonce and AEAD argument to encode plaintext, then concatenate nonce with ciphertext.
// Accept: plaintext (as bytes), signature (as bytes [0 <= N <= 24] or nil) and cipher AEAD.
// Return ciphertext and nil if encoding was successful, otherwise nil and error.
func Encode(plaintext, signature []byte, aead cipher.AEAD) ([]byte, error) {
	if signature == nil {
		signature = make([]byte, 0)
	}

	// Check signature length doesn't exceed nonce length
	if len(signature) > aead.NonceSize() {
		return nil, fmt.Errorf("signature length %d should be less than nonce length %d", len(signature), aead.NonceSize())
	}

	// Concatenate signature with random bytes to form nonce
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce[len(signature):aead.NonceSize()]); err != nil {
		return nil, fmt.Errorf("symmetrical encoding error: %v", err)
	}

	// Concatenate signature, rest of the nonce and ciphertext
	copy(nonce[:len(signature)], signature)
	encrypted := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, encrypted...), nil
}

// Decode bytes with given XChaCha20-Poly1305 AEAD.
// NB! Decoding (unlike decrypting) doesn't include neither detailing nor unsigning.
// Read nonce (first 24 bytes of ciphertext), then decode ciphertext.
// Accept: ciphertext (as bytes) and cipher AEAD.
// Return plaintext and nil if decoding was successful, otherwise nil and error.
func Decode(ciphertext []byte, aead cipher.AEAD) ([]byte, error) {
	// Check ciphertext length is at least greater than nonce and overhead size
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("ciphertext length %d too short (less than nonce length %d + overhead %d)", len(ciphertext), aead.NonceSize(), aead.Overhead())
	}

	// Split ciphertext into ciphertext and nonce, decode ciphertext
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	result, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("symmetrical decoding error: %v", err)
	}

	// Return plaintext and no error
	return result, nil
}
