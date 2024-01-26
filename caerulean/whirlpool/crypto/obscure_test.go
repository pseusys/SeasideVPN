package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math"
	"testing"
)

const (
	OBSCURE_TEST_ZERO_USER_ID = uint64(42)

	RANDOM_PERMUTE_EXACT_MULTIPLIER        = uint64(10)
	RANDOM_PERMUTE_EXACT_MULTIPLIER_1      = uint64(12912720851596686090)
	RANDOM_PERMUTE_EXACT_ADDITION          = uint64(5)
	RANDOM_PERMUTE_EXACT_USER_ID           = uint16(10)
	RANDOM_PERMUTE_EXACT_EXPECTED_IDENTITY = uint64(525)

	GET_TAIL_LENGTH_EXPECTED_TAIL_LENGTH = 14

	ENTAIL_MESSAGE_CYCLE_MESSAGE_LENGTH = 8
)

func generateRandomUserID(test *testing.T) uint16 {
	var randomInt uint16
	err := binary.Read(rand.Reader, binary.BigEndian, &randomInt)
	if err != nil {
		test.Fatalf("error generating random int: %v", err)
	}
	return uint16((randomInt % (math.MaxUint16 - 3)) + 2)
}

func getMessageForTailLengthCalculationRepeating() []byte {
	data := make([]byte, 8)
	for i := 0; i < 8; i++ {
		data[i] = byte(i + 1)
	}
	return data
}

func TestRandomPermuteExact(test *testing.T) {
	MULTIPLIER = RANDOM_PERMUTE_EXACT_MULTIPLIER
	MULTIPLIER_1 = RANDOM_PERMUTE_EXACT_MULTIPLIER_1
	ZERO_USER_ID = OBSCURE_TEST_ZERO_USER_ID

	addition := RANDOM_PERMUTE_EXACT_ADDITION
	userID := RANDOM_PERMUTE_EXACT_USER_ID

	expectedIdentity := RANDOM_PERMUTE_EXACT_EXPECTED_IDENTITY
	identity := randomPermute(addition, &userID)
	if identity != expectedIdentity {
		test.Fatalf("calculated identity does not match expected: %d != %d", identity, expectedIdentity)
	}
	test.Logf("calculated identity: %d, expected identity: %d", identity, expectedIdentity)

	receivedUserID := randomUnpermute(addition, identity)
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

	identity := randomPermute(addition, &userID)
	test.Logf("calculated identity: %d", identity)

	receivedUserID := randomUnpermute(addition, identity)
	if *receivedUserID != userID {
		test.Fatalf("calculated user ID does not match expected: %d != %d", *receivedUserID, userID)
	}
	test.Logf("calculated user ID: %d", *receivedUserID)
}

func TestSubscribeMessageCycle(test *testing.T) {
	userID := generateRandomUserID(test)
	test.Logf("generated user ID: %d", userID)

	subscription, err := subscribeMessage(&userID)
	if err != nil {
		test.Fatalf("error subscribing message: %v", err)
	}
	test.Logf("calculated subscription: %v", subscription)

	receivedUserID, err := UnsubscribeMessage(subscription)
	if err != nil {
		test.Fatalf("error unsubscribing message: %v", err)
	}
	test.Logf("calculated user ID: %d", *receivedUserID)

	if *receivedUserID != userID {
		test.Fatalf("calculated user ID does not match expected: %d != %d", *receivedUserID, userID)
	}
}

func TestGetTailLength(test *testing.T) {
	ZERO_USER_ID = OBSCURE_TEST_ZERO_USER_ID
	message := getMessageForTailLengthCalculationRepeating()

	expectedTailLength := GET_TAIL_LENGTH_EXPECTED_TAIL_LENGTH
	tailLength := getTailLength(message)
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

	entailedMessage, err := entailMessage(message)
	if err != nil {
		test.Fatalf("error entailing message: %v", err)
	}
	test.Logf("entailed message: %v", entailedMessage)

	detailedMessage, err := detailMessage(entailedMessage)
	if err != nil {
		test.Fatalf("error detailing message: %v", err)
	}
	test.Logf("detailed message: %v", detailedMessage)

	if !bytes.Equal(detailedMessage, message) {
		test.Fatalf("calculated message does not match expected: %d != %d", detailedMessage, message)
	}
}
