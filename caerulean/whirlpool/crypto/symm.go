package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
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

func EncryptSymmetrical(plaintext []byte, aead cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, utils.JoinError("symmetrical encryption error", err)
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptSymmetrical(ciphertext []byte, aead cipher.AEAD) ([]byte, error) {
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	result, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, utils.JoinError("symmetrical decryption error", err)
	}

	return result, nil
}
