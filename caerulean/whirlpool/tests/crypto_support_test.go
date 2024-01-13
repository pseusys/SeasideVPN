package tests

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"main/crypto"
	"main/utils"
	"math"
	"testing"
)

const (
	RANDOM_MESSAGE_LENGTH = 8
	RSA_KEY_LENGTH        = 1024
)

func testSymmetricalCycle(test *testing.T, subscribe bool, tailed bool) {
	message := make([]byte, RANDOM_MESSAGE_LENGTH)
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

	var userEncode *uint16
	if subscribe {
		userID := uint16((utils.RandInt() % (math.MaxUint16 - 3)) + 2)
		userEncode = &userID
		test.Logf("user id generated: %d", userID)
	} else {
		userEncode = nil
		test.Log("message will not be subscribed")
	}

	ciphertext, err := crypto.EncryptSymmetrical(message, aead, userEncode, tailed)
	if err != nil {
		test.Fatalf("error encrypting bytes: %v", err)
	}
	test.Logf("bytes encrypted: %v", ciphertext)

	plaintext, userDecode, err := crypto.DecryptSymmetrical(ciphertext, aead, tailed)
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

func TestSymmetricalCycleSubscribedTailed(test *testing.T) {
	testSymmetricalCycle(test, true, true)
}

func TestSymmetricalCycleSubscribedUntailed(test *testing.T) {
	testSymmetricalCycle(test, true, false)
}

func TestSymmetricalCycleUnsubscribedTailed(test *testing.T) {
	testSymmetricalCycle(test, false, true)
}

func TestSymmetricalCycleUnsubscribedUntailed(test *testing.T) {
	testSymmetricalCycle(test, false, false)
}

func testRSACycle(test *testing.T, subscribe bool, tailed bool) {
	message := make([]byte, RANDOM_MESSAGE_LENGTH)
	err := binary.Read(rand.Reader, binary.BigEndian, &message)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("bytes generated: %v", message)

	key, err := rsa.GenerateKey(rand.Reader, RSA_KEY_LENGTH)
	if err != nil {
		test.Fatalf("error generating RSA node key: %v", err)
	}
	test.Logf("cipher generated, key: %v", key)

	var userEncode *uint16
	if subscribe {
		userID := uint16((utils.RandInt() % (math.MaxUint16 - 3)) + 2)
		userEncode = &userID
		test.Logf("user id generated: %d", userID)
	} else {
		userEncode = nil
		test.Log("message will not be subscribed")
	}

	ciphertext, err := crypto.EncryptRSA(message, &key.PublicKey, userEncode, tailed)
	if err != nil {
		test.Fatalf("error encrypting bytes: %v", err)
	}
	test.Logf("bytes encrypted: %v", ciphertext)

	plaintext, userDecode, err := crypto.DecryptRSA(ciphertext, key, tailed)
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

func TestRSACycleSubscribedTailed(test *testing.T) {
	testRSACycle(test, true, true)
}

func TestRSACycleSubscribedUntailed(test *testing.T) {
	testRSACycle(test, true, false)
}

func TestRSACycleUnsubscribedTailed(test *testing.T) {
	testRSACycle(test, false, true)
}

func TestRSACycleUnsubscribedUntailed(test *testing.T) {
	testRSACycle(test, false, false)
}
