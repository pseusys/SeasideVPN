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
)

// TODO: read from env
const RSA_BIT_LENGTH = 4096

var (
	RSA_BYTE_LENGTH     int
	RSA_BLOCK_DATA_SIZE int
	RSA_BLOCK_HASH_SIZE int
)

var RSA_NODE_KEY *rsa.PrivateKey

func init() {
	var err error
	RSA_NODE_KEY, err = rsa.GenerateKey(rand.Reader, RSA_BIT_LENGTH)
	if err != nil {
		logrus.Fatalln("error generating RSA node key:", err)
	}

	RSA_BLOCK_HASH_SIZE = sha256.Size
	RSA_BYTE_LENGTH = RSA_BIT_LENGTH / 8
	RSA_BLOCK_DATA_SIZE = RSA_BYTE_LENGTH - 2*RSA_BLOCK_HASH_SIZE - 2
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

func EncodeRSA(plaintext []byte, signature []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	if signature == nil {
		signature = make([]byte, 0)
	}

	prevCipherText := make([]byte, RSA_BLOCK_DATA_SIZE)
	encrypted := bytes.NewBuffer(make([]byte, 0, len(plaintext)))

	for len(plaintext) > 0 {
		blockSize := utils.Min(len(plaintext), RSA_BLOCK_DATA_SIZE)
		block, rest := plaintext[:blockSize], plaintext[blockSize:]

		xorResult := utils.Xor(block, prevCipherText)
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, xorResult, nil)
		if err != nil {
			return nil, err
		}

		encrypted.Write(ciphertext)
		prevCipherText = ciphertext
		plaintext = rest
	}

	return append(signature, encrypted.Bytes()...), nil
}

func DecodeRSA(ciphertext []byte, signed bool, privateKey *rsa.PrivateKey) ([]byte, error) {
	if signed {
		ciphertext = ciphertext[SIGNATURE_LENGTH:]
	}

	prevCipherText := make([]byte, RSA_BLOCK_DATA_SIZE)
	decrypted := bytes.NewBuffer(make([]byte, 0, len(ciphertext)))

	for len(ciphertext) > 0 {
		blockSize := utils.Min(len(ciphertext), RSA_BIT_LENGTH/8)
		block, rest := ciphertext[:blockSize], ciphertext[blockSize:]

		decryptedBlock, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, block, nil)
		if err != nil {
			return nil, err
		}
		decryptedBlock = utils.Xor(decryptedBlock, prevCipherText)

		decrypted.Write(decryptedBlock)
		prevCipherText = block
		ciphertext = rest
	}

	return decrypted.Bytes(), nil
}
