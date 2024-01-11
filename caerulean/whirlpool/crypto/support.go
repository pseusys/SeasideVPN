package crypto

import (
	"crypto/cipher"
	"crypto/rsa"
	"fmt"
)

type encode[T any] func([]byte, []byte, T) ([]byte, error)
type decode[T any] func([]byte, bool, T) ([]byte, error)

func encryptAny[T any](message []byte, key *T, userID *uint16, addTail bool, encoder encode[T]) ([]byte, error) {
	signature, err := SubscribeMessage(userID)
	if err != nil {
		return nil, fmt.Errorf("error signing message: %v", err)
	}

	var ciphertext []byte
	if key != nil {
		ciphertext, err = encoder(message, signature, *key)
		if err != nil {
			return nil, fmt.Errorf("error encoding message: %v", err)
		}
	} else {
		ciphertext = append(signature, message...)
	}

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

func decryptAny[T any](message []byte, key *T, expectTail bool, decoder decode[T]) ([]byte, *uint16, error) {
	userID, err := UnsubscribeMessage(message)
	if err != nil {
		return nil, nil, fmt.Errorf("error unsigning message: %v", err)
	}

	var ciphertext []byte
	if expectTail {
		ciphertext, err = detailMessage(message)
		if err != nil {
			return nil, nil, fmt.Errorf("error entailing message: %v", err)
		}
	} else {
		ciphertext = message
	}

	var plaintext []byte
	if key != nil {
		plaintext, err = decoder(ciphertext, true, *key)
		if err != nil {
			return nil, nil, fmt.Errorf("error decoding message: %v", err)
		}
	} else {
		plaintext = ciphertext[16:]
	}

	return plaintext, userID, nil
}

func EncryptRSA(message []byte, publicKey *rsa.PublicKey, userID *uint16, addTail bool) ([]byte, error) {
	return encryptAny(message, &publicKey, userID, addTail, EncodeRSA)
}

func DecryptRSA(message []byte, privateKey *rsa.PrivateKey, expectTail bool) ([]byte, *uint16, error) {
	return decryptAny(message, &privateKey, expectTail, DecodeRSA)
}

func EncryptSymmetrical(message []byte, aead cipher.AEAD, userID *uint16, addTail bool) ([]byte, error) {
	return encryptAny(message, &aead, userID, addTail, EncodeSymmetrical)
}

func DecryptSymmetrical(message []byte, aead cipher.AEAD, expectTail bool) ([]byte, *uint16, error) {
	return decryptAny(message, &aead, expectTail, DecodeSymmetrical)
}
