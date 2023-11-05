package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/zenazn/pkcs7pad"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	RSA_BLOCK_DATA_SIZE = 128
	RSA_BLOCK_HASH_SIZE = 32
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

func DecryptBlockRSA(ciphertext []byte, key *rsa.PrivateKey) ([]byte, error) {
	blockSize := RSA_BIT_LENGTH / 8
	blockNum := len(ciphertext) / blockSize

	var initialVector []byte
	decrypted := make([]byte, blockNum*RSA_BLOCK_DATA_SIZE)

	for i := blockNum - 1; i >= 0; i-- {
		rl := i * blockSize
		ru := rl + blockSize
		fl := i * RSA_BLOCK_DATA_SIZE
		fu := fl + RSA_BLOCK_DATA_SIZE

		block, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext[rl:ru], nil)
		if err != nil {
			return nil, err
		}

		initialVector = block[:RSA_BLOCK_HASH_SIZE]
		copy(decrypted[fl:fu], block[RSA_BLOCK_HASH_SIZE:])
	}

	plaintext, err := pkcs7pad.Unpad(decrypted)
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write(plaintext)
	hsum := hash.Sum(nil)

	if initialVector == nil || !bytes.Equal(initialVector, hsum) {
		return nil, errors.New("plaintext damaged or changed")
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
