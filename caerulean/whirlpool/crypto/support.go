package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/sirupsen/logrus"
)

const (
	// Largest prime number before 2^64, will be used for signature calculation.
	LARGEST_PRIME_UINT64 = uint64((1 << 64) - 59)

	// Signature length (in bytes), namely 2 64-bit integers.
	SIGNATURE_LENGTH = 4

	MAXIMUM_TAIL_LENGTH = 64
)

var (
	// 64-bit addition to real ser ID.
	ZERO_USER_ID uint16
)

// Initialize package variables, read random integers and calculate mod inverse.
func init() {
	// Read random 64-bit integer into zero user ID
	if binary.Read(rand.Reader, binary.BigEndian, &ZERO_USER_ID) != nil {
		logrus.Fatal("Error reading random 64bit integer")
	}
}

// Encrypt bytes with given XChaCha20-Poly1305 AEAD.
// NB! Encrypting (unlike encoding) includes entailing and signing.
// First, subscription is calculated, then message is encoded (using this subscription).
// Afterwards, the encoded message is entailed (if needed).
// If key is not provided, message is just concatenated with signature instead.
// Accept message to encrypt (bytes), AEAD (or nil), user ID (or nil) and flag for adding tail.
// Return encrypted message (bytes array) and nil if encrypted successfully, otherwise nil and error.
func Encrypt(message []byte, key cipher.AEAD, userID *uint16, addTail bool) ([]byte, error) {
	// Read random addition integer
	var secret uint16
	if binary.Read(rand.Reader, binary.BigEndian, &secret) != nil {
		return nil, errors.New("error reading integer secret")
	}

	// Reset user ID if it is nil
	var userIdentity uint16
	if userID == nil {
		userIdentity = 0
	} else {
		userIdentity = *userID
	}

	// Calculate identity
	identity := uint16((int(userIdentity)+int(ZERO_USER_ID))%math.MaxUint16) ^ secret
	signature := make([]byte, SIGNATURE_LENGTH)
	binary.BigEndian.PutUint16(signature[:2], secret)
	binary.BigEndian.PutUint16(signature[2:], identity)

	// Encode signature ciphertext
	signatureCiphertext, err := Encode(signature, PUBLIC_NODE_AEAD)
	if err != nil {
		return nil, fmt.Errorf("error encoding signature: %v", err)
	}

	// Calculate message ciphertext
	messageCiphertext, err := Encode(message, key)
	if err != nil {
		return nil, fmt.Errorf("error encoding message: %v", err)
	}

	// Calculate global ciphertext
	ciphertext := append(signatureCiphertext, messageCiphertext...)

	// Add tail if addTail flag is set
	if addTail {
		entailed := make([]byte, secret%MAXIMUM_TAIL_LENGTH)
		if binary.Read(rand.Reader, binary.BigEndian, entailed) != nil {
			return nil, errors.New("error reading random tail")
		}
		return append(ciphertext, entailed...), nil
	} else {
		return ciphertext, nil
	}
}

func UnsubscribeMessage(message []byte) (*uint16, error) {
	// Calculate signature length
	signatureLength := 4 + PUBLIC_NODE_AEAD.NonceSize() + PUBLIC_NODE_AEAD.Overhead()
	signature, err := Decode(message[:signatureLength], PUBLIC_NODE_AEAD)
	if err != nil {
		return nil, fmt.Errorf("error decoding signature: %v", err)
	}

	// Calculate secret and identity
	secret := binary.BigEndian.Uint16(signature[:2])
	identity := binary.BigEndian.Uint16(signature[2:4])

	// Calculate user ID from the message
	var userID *uint16
	userIdentity := uint16((int(secret^identity) + math.MaxUint16 - int(ZERO_USER_ID)) % math.MaxUint16)
	if userIdentity == 0 {
		userID = nil
	} else {
		userID = &userIdentity
	}

	return userID, nil
}

// Decrypt bytes with given XChaCha20-Poly1305 AEAD.
// NB! Decrypting (unlike decoding) includes detailing and unsigning.
// First, subscription is calculated, then tail is removed (if expected).
// Afterwards, the message is decoded (using this subscription).
// If key is not provided, message is just separated from signature instead.
// Accept message to decrypt (bytes), AEAD (or nil) and flag for removing tail.
// Return decrypted message (bytes array), user ID pointer (if one is calculated) and nil if encrypted successfully, otherwise nil, nil and error.
func Decrypt(message []byte, key cipher.AEAD, expectTail bool) ([]byte, *uint16, error) {
	// Calculate signature length
	signatureLength := 4 + PUBLIC_NODE_AEAD.NonceSize() + PUBLIC_NODE_AEAD.Overhead()
	signature, err := Decode(message[:signatureLength], PUBLIC_NODE_AEAD)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding signature: %v", err)
	}

	// Calculate secret and identity
	secret := binary.BigEndian.Uint16(signature[:2])
	identity := binary.BigEndian.Uint16(signature[2:4])

	// Calculate user ID from the message
	var userID *uint16
	userIdentity := uint16((int(secret^identity) + math.MaxUint16 - int(ZERO_USER_ID)) % math.MaxUint16)
	if userIdentity == 0 {
		userID = nil
	} else {
		userID = &userIdentity
	}

	// Remove tail from the message (if tail is expected)
	var ciphertext []byte
	if expectTail {
		tailLength := secret % MAXIMUM_TAIL_LENGTH
		ciphertext = message[signatureLength : len(message)-int(tailLength)]
	} else {
		ciphertext = message[signatureLength:]
	}

	// Decode message
	plaintext, err := Decode(ciphertext, key)
	if err != nil {
		return nil, nil, fmt.Errorf("error decoding message: %v", err)
	}

	// Return no error
	return plaintext, userID, nil
}
