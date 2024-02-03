package crypto

import (
	"crypto/cipher"
	"fmt"
)

// Encrypt bytes with given XChaCha20-Poly1305 AEAD.
// NB! Encrypting (unlike encoding) includes entailing and signing.
// First, subscription is calculated, then message is encoded (using this subscription).
// Afterwards, the encoded message is entailed (if needed).
// If key is not provided, message is just concatenated with signature instead.
// Accept message to encrypt (bytes), AEAD (or nil), user ID (or nil) and flag for adding tail.
// Return encrypted message (bytes array) and nil if encrypted successfully, otherwise nil and error.
func Encrypt(message []byte, key cipher.AEAD, userID *uint16, addTail bool) ([]byte, error) {
	// Calculate message signature
	signature, err := subscribeMessage(userID)
	if err != nil {
		return nil, fmt.Errorf("error signing message: %v", err)
	}

	// Calculate ciphertext if key is not nil
	var ciphertext []byte
	if key != nil {
		ciphertext, err = Encode(message, signature, key)
		if err != nil {
			return nil, fmt.Errorf("error encoding message: %v", err)
		}
	} else {
		ciphertext = append(signature, message...)
	}

	// Add tail if addTail flag is set
	if addTail {
		encrypted, err := entailMessage(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("error entailing message: %v", err)
		}
		return encrypted, nil
	} else {
		return ciphertext, nil
	}
}

// Decrypt bytes with given XChaCha20-Poly1305 AEAD.
// NB! Decrypting (unlike decoding) includes detailing and unsigning.
// First, subscription is calculated, then tail is removed (if expected).
// Afterwards, the message is decoded (using this subscription).
// If key is not provided, message is just separated from signature instead.
// Accept message to decrypt (bytes), AEAD (or nil) and flag for removing tail.
// Return decrypted message (bytes array), user ID pointer (if one is calculated) and nil if encrypted successfully, otherwise nil, nil and error.
func Decrypt(message []byte, key cipher.AEAD, expectTail bool) ([]byte, *uint16, error) {
	// Calculate user ID from the message
	userID, err := UnsubscribeMessage(message)
	if err != nil {
		return nil, nil, fmt.Errorf("error unsigning message: %v", err)
	}

	// Remove tail from the message (if tail is expected)
	var ciphertext []byte
	if expectTail {
		ciphertext, err = detailMessage(message)
		if err != nil {
			return nil, nil, fmt.Errorf("error entailing message: %v", err)
		}
	} else {
		ciphertext = message
	}

	// Decode message
	var plaintext []byte
	if key != nil {
		plaintext, err = Decode(ciphertext, key)
		if err != nil {
			return nil, nil, fmt.Errorf("error decoding message: %v", err)
		}
	} else {
		plaintext = ciphertext[16:]
	}

	// Return no error
	return plaintext, userID, nil
}
