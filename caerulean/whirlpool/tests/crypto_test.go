package tests

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"main/crypto"
	"main/utils"
	"testing"
)

func TestEncryptSymmetrical(test *testing.T) {
	message := make([]byte, 8)
	err := binary.Read(rand.Reader, binary.BigEndian, &message)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("bytes generated: %v", message)

	aead, key, err := crypto.GenerateSymmetricalAlgorithm()
	if err != nil {
		test.Fatalf("error generating AEAD: %v", err)
	}
	test.Logf("cipher generated, key: %v", key)

	userEncode := uint16(utils.RandInt())
	test.Logf("user id generated: %d", userEncode)

	ciphertext, err := crypto.EncryptSymmetrical(message, aead, &userEncode, true)
	if err != nil {
		test.Fatalf("error encrypting bytes: %v", err)
	}
	test.Logf("bytes encrypted: %v", ciphertext)

	plaintext, userDecode, err := crypto.DecryptSymmetrical(ciphertext, aead, true)
	if err != nil {
		test.Fatalf("error decrypting bytes: %v", err)
	}
	test.Logf("user id decrypted: %d, bytes decrypted: %v", *userDecode, plaintext)

	if userEncode != *userDecode {
		test.Fatalf("encoded user id (%d) doesn't match decoded user id (%d)", userEncode, *userDecode)
	}

	if !bytes.Equal(message, plaintext) {
		test.Fatalf("encoded bytes (%v) don't match decoded bytes (%v)", message, plaintext)
	}
}
