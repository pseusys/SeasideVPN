package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"main/utils"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	SYMM_NODE_KEY  []byte
	SYMM_NODE_AEAD cipher.AEAD
)

func GenerateSymmetricalAlgorithm() (cipher.AEAD, []byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, utils.JoinError("symmetrical key reading error", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, utils.JoinError("symmetrical key creation error", err)
	}

	return aead, key, nil
}

func ParseSymmetricalAlgorithm(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, utils.JoinError("symmetrical key parsing error", err)
	}

	return aead, nil
}

func EncodeSymmetrical(plaintext []byte, signature []byte, aead cipher.AEAD) ([]byte, error) {
	if signature == nil {
		signature = make([]byte, 0)
	}

	if len(signature) > aead.NonceSize() {
		return nil, fmt.Errorf("signature length %d should be less than nonce length %d", len(signature), aead.NonceSize())
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce[len(signature):aead.NonceSize()]); err != nil {
		return nil, utils.JoinError("symmetrical encryption error", err)
	}

	copy(nonce[:len(signature)], signature)
	encrypted := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, encrypted...), nil
}

func DecodeSymmetrical(ciphertext []byte, signed bool, aead cipher.AEAD) ([]byte, error) {
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("ciphertext length %d too short (less than nonce length %d + overhead %d)", len(ciphertext), aead.NonceSize(), aead.Overhead())
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	result, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, utils.JoinError("symmetrical decryption error", err)
	}

	return result, nil
}
