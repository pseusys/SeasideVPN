package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptRSA(plain []byte, key *rsa.PublicKey) ([]byte, error) {
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, plain, nil)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

func ParsePublicKey(raw []byte) (*rsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unexpected type of public key")
	}

	return rsaPublicKey, nil
}

func GenerateSymmetricalAlgorithm() (cipher.AEAD, []byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, nil, err
	}

	aead, err := chacha20poly1305.New(key) // TODO: switch to XChaCha!!
	if err != nil {
		return nil, nil, err
	}

	return aead, key, nil
}

func EncryptSymmetrical(aead cipher.AEAD, data []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, data, nil), nil
}

func DecryptSymmetrical(aead cipher.AEAD, data []byte) ([]byte, error) {
	if len(data) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encrypted := data[:aead.NonceSize()], data[aead.NonceSize():]
	result, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}
