package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"main/utils"

	"github.com/sirupsen/logrus"
	"github.com/zenazn/pkcs7pad"
)

const (
	RSA_BIT_LENGTH      = 4096
	RSA_BLOCK_DATA_SIZE = 223
	RSA_BLOCK_HASH_SIZE = 32
)

var RSA_NODE_KEY *rsa.PrivateKey

func init() {
	var err error
	RSA_NODE_KEY, err = rsa.GenerateKey(rand.Reader, RSA_BIT_LENGTH)
	if err != nil {
		logrus.Fatalln("error generating RSA node key:", err)
	}
}

func ParsePublicKey(rawKey []byte) (*rsa.PublicKey, error) {
	decodedKey, err := x509.ParsePKIXPublicKey(rawKey)
	if err != nil {
		return nil, utils.JoinError("RSA public key parsing error", err)
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
		return nil, utils.JoinError("RSA encryption error", err)
	}

	return ciphertext, nil
}

// TODO: CBC
func DecryptBlockRSA(ciphertext []byte, key *rsa.PrivateKey) (plaintext []byte, err error) {
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
			return nil, utils.JoinError("RSA step decryption error", i, err)
		}

		initialVector = block[:RSA_BLOCK_HASH_SIZE]
		copy(decrypted[fl:fu], block[RSA_BLOCK_HASH_SIZE:])
	}

	plaintext, err = pkcs7pad.Unpad(decrypted)
	if err != nil {
		return nil, utils.JoinError("padding error", err)
	}

	hash := sha256.New()
	hash.Write(plaintext)
	hsum := hash.Sum(nil)

	if initialVector == nil || !bytes.Equal(initialVector, hsum) {
		return nil, errors.New("plaintext damaged or changed")
	}

	return plaintext, nil
}
