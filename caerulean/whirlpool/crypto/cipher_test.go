package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

const (
	ENCRYPTION_CYCLE_MESSAGE_LENGTH = 8

	GENERATE_CIPHER_KEY_LENGTH = 32
)

func testEncryptCycle(test *testing.T, aead cipher.AEAD) {
	message := make([]byte, ENCRYPTION_CYCLE_MESSAGE_LENGTH)
	err := binary.Read(rand.Reader, binary.BigEndian, &message)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("bytes generated: %v", message)

	ciphertext, err := Encrypt(message, aead)
	if err != nil {
		test.Fatalf("error encrypting message: %v", err)
	}
	test.Logf("message ciphertext: %v", ciphertext)

	plaintext, err := Decrypt(ciphertext, aead)
	if err != nil {
		test.Fatalf("error decrypting message: %v", err)
	}
	test.Logf("bytes plaintext: %v", plaintext)

	if !bytes.Equal(plaintext, message) {
		test.Fatalf("encrypted bytes (%v) don't match decrypted bytes (%v)", plaintext, message)
	}
}

func TestGenerateCipher(test *testing.T) {
	aead, err := GenerateCipher()
	if err != nil {
		test.Fatalf("error generating cipher: %v", err)
	}
	test.Logf("cipher generated: %v", aead)

	testEncryptCycle(test, aead)
}

func TestParseCipher(test *testing.T) {
	key := make([]byte, GENERATE_CIPHER_KEY_LENGTH)
	err := binary.Read(rand.Reader, binary.BigEndian, &key)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("key generated: %v", key)

	aead, err := ParseCipher(key)
	if err != nil {
		test.Fatalf("error parsing cipher: %v", err)
	}
	test.Logf("aead parsed: nonce size: %d, overhead: %d", aead.NonceSize(), aead.Overhead())

	testEncryptCycle(test, aead)
}
