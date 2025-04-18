package crypto

import (
	"crypto/cipher"
	"fmt"

	"github.com/pseusys/betterbuf"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	SymmetricKeySize            = 32
	NonceSize                   = 24
	MacSize                     = 16
	SymmetricCiphertextOverhead = NonceSize + MacSize
)

type Symmetric struct {
	aead cipher.AEAD
}

// Generate symmetrical cipher.
// Accept 32 byte key or nil (key will be generated in that case).
// Return cipher and nil if AEAD is generated successfully, otherwise nil and error.
func NewSymmetric(key *betterbuf.Buffer) (*Symmetric, error) {
	var err error

	// Generate random bytes for key
	if key == nil {
		key, err = betterbuf.NewRandomBuffer(chacha20poly1305.KeySize)
		if err != nil {
			return nil, fmt.Errorf("symmetrical key reading error: %v", err)
		}
	}

	// Generate AEAD using random bytes
	aead, err := chacha20poly1305.NewX(key.Slice())
	if err != nil {
		return nil, fmt.Errorf("symmetrical key creation error: %v", err)
	}

	// Return AEAD, key and no error
	return &Symmetric{aead}, nil
}

// Encrypt bytes with given AEAD.
// Generate nonce (24 bytes) and use it and AEAD argument to encrypt plaintext.
// Concatenate ciphertext: nonce + encrypted data + tag.
// Accept: plaintext (as bytes), signature (as bytes [0 <= N <= 24] or nil) and cipher AEAD.
// Return ciphertext and nil if encrypting was successful, otherwise nil and error.
func (s *Symmetric) Encrypt(plaintext, additional *betterbuf.Buffer) (*betterbuf.Buffer, error) {
	// Concatenate signature with random bytes to form nonce
	nonce, err := betterbuf.NewRandomBuffer(s.aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("nonce generation error: %v", err)
	}

	var additionalSlice []byte
	if additional != nil {
		additionalSlice = additional.Slice()
	}

	// Concatenate signature, rest of the nonce and ciphertext
	encrypted := s.aead.Seal(plaintext.ResliceEnd(0), nonce.Slice(), plaintext.Slice(), additionalSlice)
	ciphertext, err := plaintext.EnsureSameSlice(encrypted)
	if err != nil {
		return nil, fmt.Errorf("unexpected allocation performed during symmetrical encryption: %v", err)
	}

	message, err := ciphertext.AppendBuffer(nonce)
	if err != nil {
		return nil, fmt.Errorf("appending nonce to ciphertext error: %v", err)
	}
	return message, nil
}

// Decrypt bytes with given AEAD.
// Read nonce (first 24 bytes of ciphertext), then decrypt ciphertext.
// Accept: ciphertext (as bytes) and cipher AEAD.
// Return plaintext and nil if decrypting was successful, otherwise nil and error.
func (s *Symmetric) Decrypt(ciphertext, additional *betterbuf.Buffer) (*betterbuf.Buffer, error) {
	cipherLength := ciphertext.Length()

	// Check ciphertext length is at least greater than nonce and overhead size
	if cipherLength < s.aead.NonceSize()+s.aead.Overhead() {
		return nil, fmt.Errorf("ciphertext length %d too short (less than nonce length %d + overhead %d)", cipherLength, s.aead.NonceSize(), s.aead.Overhead())
	}

	var additionalSlice []byte
	if additional != nil {
		additionalSlice = additional.Slice()
	}

	// Split ciphertext into ciphertext and nonce, decrypt ciphertext
	encryptedLength := cipherLength - s.aead.NonceSize()
	ciphertext, nonce := ciphertext.RebufferEnd(encryptedLength), ciphertext.RebufferStart(encryptedLength)
	decrypted, err := s.aead.Open(ciphertext.ResliceEnd(0), nonce.Slice(), ciphertext.Slice(), additionalSlice)
	if err != nil {
		return nil, fmt.Errorf("symmetrical decrypting error: %v", err)
	}

	plaintext, err := ciphertext.EnsureSameSlice(decrypted)
	if err != nil {
		return nil, fmt.Errorf("unexpected allocation performed during symmetrical decryption: %v", err)
	}

	// Return plaintext and no error
	return plaintext, nil
}
