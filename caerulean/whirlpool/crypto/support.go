package crypto

import (
	"crypto/cipher"
	"fmt"
)

func Encrypt(message []byte, key cipher.AEAD, userID *uint16, addTail bool) ([]byte, error) {
	signature, err := SubscribeMessage(userID)
	if err != nil {
		return nil, fmt.Errorf("error signing message: %v", err)
	}

	var ciphertext []byte
	if key != nil {
		ciphertext, err = Encode(message, signature, key)
		if err != nil {
			return nil, fmt.Errorf("error encoding message: %v", err)
		}
	} else {
		ciphertext = append(signature, message...)
	}

	if addTail {
		encrypted, err := EntailMessage(ciphertext)
		if err != nil {
			return nil, fmt.Errorf("error entailing message: %v", err)
		}
		return encrypted, nil
	} else {
		return ciphertext, nil
	}
}

func Decrypt(message []byte, key cipher.AEAD, expectTail bool) ([]byte, *uint16, error) {
	userID, err := UnsubscribeMessage(message)
	if err != nil {
		return nil, nil, fmt.Errorf("error unsigning message: %v", err)
	}

	var ciphertext []byte
	if expectTail {
		ciphertext, err = DetailMessage(message)
		if err != nil {
			return nil, nil, fmt.Errorf("error entailing message: %v", err)
		}
	} else {
		ciphertext = message
	}

	var plaintext []byte
	if key != nil {
		plaintext, err = Decode(ciphertext, true, key)
		if err != nil {
			return nil, nil, fmt.Errorf("error decoding message: %v", err)
		}
	} else {
		plaintext = ciphertext[16:]
	}

	return plaintext, userID, nil
}
