package crypto

import (
	"fmt"
	"main/utils"

	"github.com/pseusys/betterbuf"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
)

const (
	NumberN                     = 2
	SeedKeySize                 = 8
	PublicKeySize               = 32
	PrivateKeySize              = 32
	SymmetricHashSize           = 32
	AymmetricCiphertextOverhead = SymmetricCiphertextOverhead + PublicKeySize + NumberN
)

func multiplyKeyPair(private, public *betterbuf.Buffer) (*betterbuf.Buffer, *betterbuf.Buffer, error) {
	var err error
	if private == nil {
		private, err = betterbuf.NewRandomBuffer(PrivateKeySize)
		if err != nil {
			return nil, nil, fmt.Errorf("error generating private curve key: %v", err)
		}
	}

	if public == nil {
		public = betterbuf.NewBufferFromSlice(curve25519.Basepoint[:])
	}

	result, err := curve25519.X25519(private.Slice(), public.Slice())
	if err != nil {
		return nil, nil, fmt.Errorf("error generating public curve key: %v", err)
	}
	return private, betterbuf.NewBufferFromSlice(result), nil
}

func computeBlake2Hash(sharedSecret, clientKey, serverKey *betterbuf.Buffer) (*betterbuf.Buffer, error) {
	hash, err := blake2b.New256(nil)
	if err != nil {
		return nil, fmt.Errorf("error generating Blake2 hash: %v", err)
	}
	hash.Write(sharedSecret.Slice())
	hash.Write(clientKey.Slice())
	hash.Write(serverKey.Slice())
	sum := hash.Sum(nil)[:SymmetricHashSize]
	return betterbuf.NewBufferFromSlice(sum), nil
}

type Asymmetric struct {
	privateKey, publicKey, seedKey *betterbuf.Buffer
}

func NewAsymmetric(key *betterbuf.Buffer, private bool) (*Asymmetric, error) {
	var err error
	var priv, pub, seed *betterbuf.Buffer
	if key == nil {
		priv, pub, err = multiplyKeyPair(nil, nil)
		if err != nil {
			return nil, fmt.Errorf("asymmetrical keypair generating error: %v", err)
		}
		seed, err = betterbuf.NewRandomBuffer(SeedKeySize)
		if err != nil {
			return nil, fmt.Errorf("random seed generating error: %v", err)
		}
	} else if private {
		if key.Length() != PrivateKeySize+SeedKeySize {
			return nil, fmt.Errorf("invalid private key length: %d != %d", key.Length(), PrivateKeySize+SeedKeySize)
		}
		priv, seed = key.RebufferEnd(PrivateKeySize), key.RebufferStart(PrivateKeySize)
		_, pub, err = multiplyKeyPair(priv, nil)
		if err != nil {
			return nil, fmt.Errorf("public key generating error: %v", err)
		}
	} else {
		if key.Length() != PublicKeySize+SeedKeySize {
			return nil, fmt.Errorf("invalid public key length: %d != %d", key.Length(), PublicKeySize+SeedKeySize)
		}
		pub, seed = key.RebufferEnd(PublicKeySize), key.RebufferStart(PublicKeySize)
		priv = nil
	}
	return &Asymmetric{privateKey: priv, publicKey: pub, seedKey: seed}, nil
}

func (a *Asymmetric) PublicKey() *betterbuf.Buffer {
	result := betterbuf.NewClearBuffer(0, a.publicKey.Length()+a.seedKey.Length(), 0)
	copy(result.ResliceEnd(a.publicKey.Length()), a.publicKey.Slice())
	copy(result.ResliceStart(a.publicKey.Length()), a.seedKey.Slice())
	return result
}

func (a *Asymmetric) revealPublicKey(publicKey *betterbuf.Buffer) (*betterbuf.Buffer, error) {
	hash, err := blake2b.New256(nil)
	if err != nil {
		return nil, fmt.Errorf("error generating Blake2 hash: %v", err)
	}
	hash.Write(publicKey.ResliceEnd(NumberN))
	hash.Write(a.seedKey.Slice())
	hashData := betterbuf.NewBufferFromSlice(hash.Sum(nil)).ResliceEnd(SymmetricHashSize)
	return betterbuf.NewBufferFromSlice(utils.XORSlices(publicKey.ResliceStart(NumberN), hashData)), nil
}

func (a *Asymmetric) Decrypt(ciphertext *betterbuf.Buffer) (*betterbuf.Buffer, *betterbuf.Buffer, error) {
	cipherLength := ciphertext.Length()

	if cipherLength < PublicKeySize+NumberN {
		return nil, nil, fmt.Errorf("ciphertext too short: %d < %d", cipherLength, PublicKeySize+NumberN)
	}

	hiddenPublicKeyLength := PublicKeySize + NumberN
	hiddenPub, ciphertext := ciphertext.RebufferEnd(hiddenPublicKeyLength), ciphertext.RebufferStart(hiddenPublicKeyLength)
	ephemeralPub, err := a.revealPublicKey(hiddenPub)
	if err != nil {
		return nil, nil, fmt.Errorf("error revealing public key: %v", err)
	}

	_, sharedSecret, err := multiplyKeyPair(a.privateKey, ephemeralPub)
	if err != nil {
		return nil, nil, fmt.Errorf("error calculating shared secret: %v", err)
	}

	symmetricKey, err := computeBlake2Hash(sharedSecret, ephemeralPub, a.publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error calculating Blake2 hash: %v", err)
	}

	cipher, err := NewSymmetric(symmetricKey)
	if err != nil {
		return nil, nil, fmt.Errorf("symmetrical cipher creation error: %v", err)
	}

	plaintext, err := cipher.Decrypt(ciphertext, ephemeralPub)
	if err != nil {
		return nil, nil, fmt.Errorf("error decrypting plaintext with symmetrical cypher: %v", err)
	}

	return symmetricKey, plaintext, nil
}
