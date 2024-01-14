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
	PRIVATE_NODE_KEY  []byte
	PRIVATE_NODE_AEAD cipher.AEAD
	PUBLIC_NODE_AEAD  cipher.AEAD
)

func init() {
	publicKeyHex := utils.GetEnv("SEASIDE_PUBLIC", nil)

	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		logrus.Fatalf("error parsing public key bytes: %v (%s)", err, publicKeyHex)
	}

	PUBLIC_NODE_AEAD, err = ParseCipher(publicKeyBytes)
	if err != nil {
		logrus.Fatalf("error parsing public aead: %v (%s)", err, publicKeyHex)
	}
}

func GenerateCipher() (cipher.AEAD, []byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, fmt.Errorf("symmetrical key reading error: %v", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("symmetrical key creation error: %v", err)
	}

	return aead, key, nil
}

func ParseCipher(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("symmetrical key parsing error: %v", err)
	}

	return aead, nil
}

func Encode(plaintext, signature []byte, aead cipher.AEAD) ([]byte, error) {
	if signature == nil {
		signature = make([]byte, 0)
	}

	if len(signature) > aead.NonceSize() {
		return nil, fmt.Errorf("signature length %d should be less than nonce length %d", len(signature), aead.NonceSize())
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce[len(signature):aead.NonceSize()]); err != nil {
		return nil, fmt.Errorf("symmetrical encryption error: %v", err)
	}

	copy(nonce[:len(signature)], signature)
	encrypted := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, encrypted...), nil
}

func Decode(ciphertext []byte, signed bool, aead cipher.AEAD) ([]byte, error) {
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, fmt.Errorf("ciphertext length %d too short (less than nonce length %d + overhead %d)", len(ciphertext), aead.NonceSize(), aead.Overhead())
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	result, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("symmetrical decryption error: %v", err)
	}

	return result, nil
}
