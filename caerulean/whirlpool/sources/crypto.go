package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

func ParsePublicKey(rawKey []byte) (*rsa.PublicKey, error) {
	decodedKey, err := x509.ParsePKIXPublicKey(rawKey)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := decodedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unexpected type of public key")
	}

	return rsaPublicKey, nil
}

func EncryptRSA(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func DecryptRSA(ciphertext []byte, key *rsa.PrivateKey) ([]byte, error) {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func GenerateSymmetricalAlgorithm() (cipher.AEAD, []byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}

	return aead, key, nil
}

func EncryptSymmetrical(plaintext []byte, aead cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
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
		return nil, err
	}

	return result, nil
}
