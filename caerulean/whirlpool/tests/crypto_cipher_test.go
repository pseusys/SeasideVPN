package tests

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"main/crypto"
	"testing"
)

const (
	ENCODE_CYCLE_MESSAGE_LENGTH = 8

	GENERATE_CIPHER_KEY_LENGTH = 32
)

func testEncodeCycle(test *testing.T, aead cipher.AEAD) {
	message := make([]byte, ENCRYPTION_CYCLE_MESSAGE_LENGTH)
	err := binary.Read(rand.Reader, binary.BigEndian, &message)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("bytes generated: %v", message)

	encoded, err := crypto.Encode(message, nil, aead)
	if err != nil {
		test.Fatalf("error encoding message: %v", err)
	}
	test.Logf("message encoded: %v", encoded)

	decoded, err := crypto.Decode(encoded, false, aead)
	if err != nil {
		test.Fatalf("error decoding message: %v", err)
	}
	test.Logf("bytes decoded: %v", decoded)

	if !bytes.Equal(decoded, message) {
		test.Fatalf("encoded bytes (%v) don't match decoded bytes (%v)", decoded, message)
	}
}

func TestGenerateCipher(test *testing.T) {
	aead, key, err := crypto.GenerateCipher()
	if err != nil {
		test.Fatalf("error generating cipher: %v", err)
	}
	test.Logf("key generated: %v", key)

	expectedKeyLength := GENERATE_CIPHER_KEY_LENGTH
	if len(key) != expectedKeyLength {
		test.Fatalf("key length mismatching: %d != %d", len(key), expectedKeyLength)
	}
	test.Logf("key length: %d", len(key))

	testEncodeCycle(test, aead)
}

func TestParseCipher(test *testing.T) {
	key := make([]byte, GENERATE_CIPHER_KEY_LENGTH)
	err := binary.Read(rand.Reader, binary.BigEndian, &key)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("key generated: %v", key)

	aead, err := crypto.ParseCipher(key)
	if err != nil {
		test.Fatalf("error parsing cipher: %v", err)
	}
	test.Logf("aead parsed: nonce size: %d, overhead: %d", aead.NonceSize(), aead.Overhead())

	testEncodeCycle(test, aead)
}
