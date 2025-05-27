package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"math/big"
)

// ECCKeyPair is a DTO that holds ECC private and public keys.
type ECCKeyPair struct {
	Public  *ecdsa.PublicKey
	Private *ecdsa.PrivateKey
}

func (k *ECCKeyPair) GetPublicKey() crypto.PublicKey {
	return k.Public
}

func (k *ECCKeyPair) GetPrivateKey() crypto.PrivateKey {
	return k.Private
}

func (k *ECCKeyPair) GetAlgorithm() domain.Algorithm {
	return domain.ECC
}

// ECCGenerator generates an ECC key pair.
type ECCGenerator struct{}

// Generate generates a new ECCKeyPair.
func (g *ECCGenerator) Generate() (KeyPair, error) {
	// Security has been ignored for the sake of simplicity.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECCKeyPair{
		Public:  &key.PublicKey,
		Private: key,
	}, nil
}

// ECCMarshaler can encode and decode an ECC key pair.
type ECCMarshaler struct{}

// NewECCMarshaler creates a new ECCMarshaler.
func NewECCMarshaler() ECCMarshaler {
	return ECCMarshaler{}
}

// Encode takes an ECCKeyPair and encodes it to be written on disk.
// It returns the public and the private key as a byte slice.
func (m ECCMarshaler) Encode(keyPair ECCKeyPair) ([]byte, []byte, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(keyPair.Private)
	if err != nil {
		return nil, nil, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(keyPair.Public)
	if err != nil {
		return nil, nil, err
	}

	encodedPrivate := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE_KEY",
		Bytes: privateKeyBytes,
	})

	encodedPublic := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC_KEY",
		Bytes: publicKeyBytes,
	})

	return encodedPublic, encodedPrivate, nil
}

// Decode assembles an ECCKeyPair from an encoded private key.
func (m ECCMarshaler) Decode(privateKeyBytes []byte) (*ECCKeyPair, error) {
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &ECCKeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}

type ECCSigner struct {
	keyPair *ECCKeyPair
}

func NewECCSigner(keyPair *ECCKeyPair) *ECCSigner {
	return &ECCSigner{
		keyPair: keyPair,
	}
}

func (e *ECCSigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	hashedData := sha256.Sum256(dataToBeSigned)

	r, s, err := ecdsa.Sign(rand.Reader, e.keyPair.Private, hashedData[:])
	if err != nil {
		return nil, err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

func (e *ECCSigner) VerifySignature(dataToBeSigned []byte, signature []byte) bool {
	hashedData := sha256.Sum256(dataToBeSigned)

	// Split the signature into r and s components
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	return ecdsa.Verify(e.keyPair.Public, hashedData[:], r, s)
}
