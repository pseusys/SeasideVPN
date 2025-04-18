package crypto

import (
	"fmt"

	"github.com/pseusys/betterbuf"
	"github.com/pseusys/monocypher-go"
)

const (
	PublicKeySize               = 32
	PrivateKeySize              = 32
	SymmetricHashSize           = 32
	AymmetricCiphertextOverhead = SymmetricCiphertextOverhead + PublicKeySize
)

func computeBlake2Hash(shared_secret, client_key, server_key []byte) ([]byte, error) {
	hashSize := SymmetricHashSize
	hash, err := monocypher.NewBlake2bHash(nil, &hashSize)
	if err != nil {
		return nil, fmt.Errorf("error generating Blake2 hash: %v", err)
	}

	hash = hash.Update(shared_secret).Update(client_key).Update(server_key)
	return hash.Finalize()[:hashSize], nil
}

type Asymmetric struct {
	privateKey, publicKey *betterbuf.Buffer
}

func NewAsymmetric(key *betterbuf.Buffer, private bool) (*Asymmetric, error) {
	var priv, pub *betterbuf.Buffer
	if key == nil {
		privBytes, pubBytes, err := monocypher.GenerateKeyExchangeKeyPair()
		if err != nil {
			return nil, fmt.Errorf("asymmetrical keypair generating error: %v", err)
		}
		priv, pub = betterbuf.NewBufferFromSlice(privBytes), betterbuf.NewBufferFromSlice(pubBytes)
	} else if private {
		if key.Length() != PrivateKeySize+PublicKeySize {
			return nil, fmt.Errorf("invalid private key length: %d != %d", key.Length(), PrivateKeySize+PublicKeySize)
		}
		priv, pub = key.RebufferEnd(PrivateKeySize), key.RebufferStart(PrivateKeySize)
	} else {
		if key.Length() != PublicKeySize {
			return nil, fmt.Errorf("invalid public key length: %d != %d", key.Length(), PublicKeySize)
		}
		priv, pub = nil, key
	}
	return &Asymmetric{privateKey: priv, publicKey: pub}, nil
}

func (a *Asymmetric) PublicKey() *betterbuf.Buffer {
	return a.publicKey
}

func (a *Asymmetric) Encrypt(plaintext *betterbuf.Buffer) (*betterbuf.Buffer, *betterbuf.Buffer, error) {
	hiddenPub, ephemeralPriv, err := monocypher.ElligatorKeyPair(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating ephemeral key: %v", err)
	}

	sharedSecret := monocypher.KeyExchange(ephemeralPriv, a.publicKey.Slice())
	symmetricKey, err := computeBlake2Hash(sharedSecret, hiddenPub, a.publicKey.Slice())
	if err != nil {
		return nil, nil, fmt.Errorf("error calculating Blake2 hash: %v", err)
	}
	symmetricBuffer, hiddenBuffer := betterbuf.NewBufferFromSlice(symmetricKey), betterbuf.NewBufferFromSlice(hiddenPub)

	cipher, err := NewSymmetric(symmetricBuffer)
	if err != nil {
		return nil, nil, fmt.Errorf("symmetrical cipher creation error: %v", err)
	}

	ciphertext, err := cipher.Encrypt(plaintext, hiddenBuffer)
	if err != nil {
		return nil, nil, fmt.Errorf("error encrypting plaintext with symmetrical cypher: %v", err)
	}

	message, err := ciphertext.AppendBuffer(hiddenBuffer)
	if err != nil {
		return nil, nil, fmt.Errorf("error appending hidden buffer to ciphertext: %v", err)
	}

	return symmetricBuffer, message, nil
}

func (a *Asymmetric) Decrypt(ciphertext *betterbuf.Buffer) (*betterbuf.Buffer, *betterbuf.Buffer, error) {
	cipherLength := ciphertext.Length()

	if cipherLength < PublicKeySize {
		return nil, nil, fmt.Errorf("ciphertext too short: %d < %d", cipherLength, PublicKeySize)
	}

	encryptedLength := cipherLength - PublicKeySize
	ciphertext, hiddenPub := ciphertext.RebufferEnd(encryptedLength), ciphertext.RebufferStart(encryptedLength)
	ephemeralPub, err := monocypher.ElligatorMap(hiddenPub.Slice())
	if err != nil {
		return nil, nil, fmt.Errorf("error performing elligator on public key: %v", err)
	}

	sharedSecret := monocypher.KeyExchange(a.privateKey.Slice(), ephemeralPub)
	symmetricKey, err := computeBlake2Hash(sharedSecret, hiddenPub.Slice(), a.publicKey.Slice())
	if err != nil {
		return nil, nil, fmt.Errorf("error calculating Blake2 hash: %v", err)
	}
	symmetricBuffer := betterbuf.NewBufferFromSlice(symmetricKey)

	cipher, err := NewSymmetric(symmetricBuffer)
	if err != nil {
		return nil, nil, fmt.Errorf("symmetrical cipher creation error: %v", err)
	}

	plaintext, err := cipher.Decrypt(ciphertext, hiddenPub)
	if err != nil {
		return nil, nil, fmt.Errorf("error decrypting plaintext with symmetrical cypher: %v", err)
	}

	return symmetricBuffer, plaintext, nil
}
