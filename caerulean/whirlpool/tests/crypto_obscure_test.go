package tests

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"main/crypto"
	"testing"
)

const (
	RANDOM_PERMUTE_EXACT_MULTIPLIER        = uint64(10)
	RANDOM_PERMUTE_EXACT_MULTIPLIER_1      = uint64(12912720851596686090)
	RANDOM_PERMUTE_EXACT_ZERO_USER_ID      = uint64(42)
	RANDOM_PERMUTE_EXACT_ADDITION          = uint64(5)
	RANDOM_PERMUTE_EXACT_USER_ID           = uint16(10)
	RANDOM_PERMUTE_EXACT_EXPECTED_IDENTITY = uint64(525)

	GET_TAIL_LENGTH_ZERO_USER_ID = uint64(42)

	ENTAIL_MESSAGE_CYCLE_MESSAGE_LENGTH = 8
)

func getMessageForTailLengthCalculationRepeating() []byte {
	data := make([]byte, 8)
	for i := 0; i < 8; i++ {
		data[i] = byte(i + 1)
	}
	return data
}

func TestRandomPermuteExact(test *testing.T) {
	crypto.MULTIPLIER = RANDOM_PERMUTE_EXACT_MULTIPLIER
	crypto.MULTIPLIER_1 = RANDOM_PERMUTE_EXACT_MULTIPLIER_1
	crypto.ZERO_USER_ID = RANDOM_PERMUTE_EXACT_ZERO_USER_ID

	addition := RANDOM_PERMUTE_EXACT_ADDITION
	userID := RANDOM_PERMUTE_EXACT_USER_ID

	expectedIdentity := RANDOM_PERMUTE_EXACT_EXPECTED_IDENTITY
	identity := crypto.RandomPermute(addition, &userID)
	if identity != expectedIdentity {
		test.Fatalf("calculated identity does not match expected: %d != %d", identity, expectedIdentity)
	}
	test.Logf("calculated identity: %d, expected identity: %d", identity, expectedIdentity)

	receivedUserID := crypto.RandomUnpermute(addition, identity)
	if *receivedUserID != userID {
		test.Fatalf("calculated user ID does not match expected: %d != %d", *receivedUserID, userID)
	}
}

func TestRandomPermuteCycle(test *testing.T) {
	var addition uint64
	err := binary.Read(rand.Reader, binary.BigEndian, &addition)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("generated addition: %d", addition)

	var userID uint16
	err = binary.Read(rand.Reader, binary.BigEndian, &userID)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("generated user ID: %d", userID)

	identity := crypto.RandomPermute(addition, &userID)
	test.Logf("calculated identity: %d", identity)

	receivedUserID := crypto.RandomUnpermute(addition, identity)
	if *receivedUserID != userID {
		test.Fatalf("calculated user ID does not match expected: %d != %d", *receivedUserID, userID)
	}
	test.Logf("calculated user ID: %d", *receivedUserID)
}

func TestSubscribeMessageCycle(test *testing.T) {
	var userID uint16
	err := binary.Read(rand.Reader, binary.BigEndian, &userID)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("generated user ID: %d", userID)

	subscription, err := crypto.SubscribeMessage(&userID)
	if err != nil {
		test.Fatalf("error subscribing message: %v", err)
	}
	test.Logf("calculated subscription: %v", subscription)

	receivedUserID, err := crypto.UnsubscribeMessage(subscription)
	if err != nil {
		test.Fatalf("error unsubscribing message: %v", err)
	}
	test.Logf("calculated user ID: %d", *receivedUserID)

	if *receivedUserID != userID {
		test.Fatalf("calculated user ID does not match expected: %d != %d", *receivedUserID, userID)
	}
}

func TestGetTailLength(test *testing.T) {
	crypto.ZERO_USER_ID = GET_TAIL_LENGTH_ZERO_USER_ID
	message := getMessageForTailLengthCalculationRepeating()

	expectedTailLength := 14
	tailLength := crypto.GetTailLength(message)
	test.Logf("calculated tail length: %d", tailLength)

	if tailLength != expectedTailLength {
		test.Fatalf("calculated tail length does not match expected: %d != %d", tailLength, expectedTailLength)
	}
}

func TestEntailMessageCycle(test *testing.T) {
	message := make([]byte, ENTAIL_MESSAGE_CYCLE_MESSAGE_LENGTH)
	err := binary.Read(rand.Reader, binary.BigEndian, &message)
	if err != nil {
		test.Fatalf("error generating random bytes: %v", err)
	}
	test.Logf("generated message: %v", message)

	entailedMessage, err := crypto.EntailMessage(message)
	if err != nil {
		test.Fatalf("error entailing message: %v", err)
	}
	test.Logf("entailed message: %v", entailedMessage)

	detailedMessage, err := crypto.DetailMessage(entailedMessage)
	if err != nil {
		test.Fatalf("error detailing message: %v", err)
	}
	test.Logf("detailed message: %v", detailedMessage)

	if !bytes.Equal(detailedMessage, message) {
		test.Fatalf("calculated message does not match expected: %d != %d", detailedMessage, message)
	}
}
