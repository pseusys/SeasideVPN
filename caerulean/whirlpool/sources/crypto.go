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

func EncryptRSA(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

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

func EncryptSymmetrical(aead cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptSymmetrical(aead cipher.AEAD, payload []byte) ([]byte, error) {
	if len(payload) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := payload[:aead.NonceSize()], payload[aead.NonceSize():]
	result, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}
