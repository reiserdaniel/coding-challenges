package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

// RSAKeyPair is a DTO that holds RSA private and public keys.
type RSAKeyPair struct {
	Public  *rsa.PublicKey
	Private *rsa.PrivateKey
}

func (k *RSAKeyPair) GetPublicKey() crypto.PublicKey {
	return k.Public
}

func (k *RSAKeyPair) GetPrivateKey() crypto.PrivateKey {
	return k.Private
}

func (k *RSAKeyPair) GetAlgorithm() domain.Algorithm {
	return domain.RSA
}

// RSAGenerator generates a RSA key pair.
type RSAGenerator struct{}

// Generate generates a new RSAKeyPair.
func (g *RSAGenerator) Generate() (KeyPair, error) {
	// Security has been ignored for the sake of simplicity.
	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, err
	}

	return &RSAKeyPair{
		Public:  &key.PublicKey,
		Private: key,
	}, nil
}

// RSAMarshaler can encode and decode an RSA key pair.
type RSAMarshaler struct{}

// NewRSAMarshaler creates a new RSAMarshaler.
func NewRSAMarshaler() RSAMarshaler {
	return RSAMarshaler{}
}

// Marshal takes an RSAKeyPair and encodes it to be written on disk.
// It returns the public and the private key as a byte slice.
func (m *RSAMarshaler) Marshal(keyPair RSAKeyPair) ([]byte, []byte, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(keyPair.Private)
	publicKeyBytes := x509.MarshalPKCS1PublicKey(keyPair.Public)

	encodedPrivate := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA_PRIVATE_KEY",
		Bytes: privateKeyBytes,
	})

	encodePublic := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA_PUBLIC_KEY",
		Bytes: publicKeyBytes,
	})

	return encodePublic, encodedPrivate, nil
}

// Unmarshal takes an encoded RSA private key and transforms it into a rsa.PrivateKey.
func (m *RSAMarshaler) Unmarshal(privateKeyBytes []byte) (*RSAKeyPair, error) {
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &RSAKeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}

type RSASigner struct {
	keyPair *RSAKeyPair
}

func NewRSASigner(keyPair *RSAKeyPair) *RSASigner {
	return &RSASigner{
		keyPair: keyPair,
	}
}

func (r *RSASigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	hashedData := sha256.Sum256(dataToBeSigned)
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.keyPair.Private, crypto.SHA256, hashedData[:])

	return signature, err
}

func (r *RSASigner) VerifySignature(dataToBeSigned []byte, signature []byte) bool {
	hashedData := sha256.Sum256(dataToBeSigned)
	err := rsa.VerifyPKCS1v15(r.keyPair.Public, crypto.SHA256, hashedData[:], signature)

	return err == nil
}
