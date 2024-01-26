package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

const ENCRYPTION_CYCLE_MESSAGE_LENGTH = 8

func testEncryptCycle(test *testing.T, subscribe, tailed bool) {
	message := make([]byte, ENCRYPTION_CYCLE_MESSAGE_LENGTH)
	err := binary.Read(rand.Reader, binary.BigEndian, &message)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("bytes generated: %v", message)

	aead, key, err := GenerateCipher()
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

	ciphertext, err := Encrypt(message, aead, userEncode, tailed)
	if err != nil {
		test.Fatalf("error encrypting bytes: %v", err)
	}
	test.Logf("bytes encrypted: %v", ciphertext)

	plaintext, userDecode, err := Decrypt(ciphertext, aead, tailed)
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

	if !bytes.Equal(plaintext, message) {
		test.Fatalf("encoded bytes (%v) don't match decoded bytes (%v)", message, plaintext)
	}
}

func TestEncryptCycleSubscribedTailed(test *testing.T) {
	testEncryptCycle(test, true, true)
}

func TestEncryptCycleSubscribedUntailed(test *testing.T) {
	testEncryptCycle(test, true, false)
}

func TestEncryptCycleUnsubscribedTailed(test *testing.T) {
	testEncryptCycle(test, false, true)
}

func TestEncryptCycleUnsubscribedUntailed(test *testing.T) {
	testEncryptCycle(test, false, false)
}
