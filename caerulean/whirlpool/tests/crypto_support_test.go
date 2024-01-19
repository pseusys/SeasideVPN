package tests

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"main/crypto"
	"math"
	"testing"
)

const ENCRYPTION_CYCLE_MESSAGE_LENGTH = 8

func generateRandomUserID(test *testing.T) uint16 {
	var randomInt int
	err := binary.Read(rand.Reader, binary.BigEndian, &randomInt)
	if err != nil {
		test.Fatalf("error generating random int: %v", err)
	}
	return uint16((randomInt % (math.MaxUint16 - 3)) + 2)
}

func testEncryptionCycle(test *testing.T, subscribe, tailed bool) {
	message := make([]byte, ENCRYPTION_CYCLE_MESSAGE_LENGTH)
	err := binary.Read(rand.Reader, binary.BigEndian, &message)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("bytes generated: %v", message)

	aead, key, err := crypto.GenerateCipher()
	if err != nil {
		test.Fatalf("error generating AEAD: %v", err)
	}
	test.Logf("cipher generated, key: %v", key)

	var userEncode *uint16
	if subscribe {
		userID := generateRandomUserID(test)
		userEncode = &userID
		test.Logf("user id generated: %d", userID)
	} else {
		userEncode = nil
		test.Log("message will not be subscribed")
	}

	ciphertext, err := crypto.Encrypt(message, aead, userEncode, tailed)
	if err != nil {
		test.Fatalf("error encrypting bytes: %v", err)
	}
	test.Logf("bytes encrypted: %v", ciphertext)

	plaintext, userDecode, err := crypto.Decrypt(ciphertext, aead, tailed)
	if err != nil {
		test.Fatalf("error decrypting bytes: %v", err)
	}

	if subscribe {
		test.Logf("user id decrypted: %d, bytes decrypted: %v", *userDecode, plaintext)
		if *userEncode != *userDecode {
			test.Fatalf("encoded user id (%d) doesn't match decoded user id (%d)", *userEncode, *userDecode)
		}
	} else {
		test.Logf("anonymous message, bytes decrypted: %v", plaintext)
		if userEncode != userDecode {
			test.Fatalf("anonymous user ID address (nil, %d) doesn't match decoded ID address (nil, %d)", userEncode, userDecode)
		}
	}

	if !bytes.Equal(message, plaintext) {
		test.Fatalf("encoded bytes (%v) don't match decoded bytes (%v)", message, plaintext)
	}
}

func TestEncrytptionCycleSubscribedTailed(test *testing.T) {
	testEncryptionCycle(test, true, true)
}

func TestEncrytptionCycleSubscribedUntailed(test *testing.T) {
	testEncryptionCycle(test, true, false)
}

func TestEncrytptionCycleUnsubscribedTailed(test *testing.T) {
	testEncryptionCycle(test, false, true)
}

func TestEncrytptionCycleUnsubscribedUntailed(test *testing.T) {
	testEncryptionCycle(test, false, false)
}
