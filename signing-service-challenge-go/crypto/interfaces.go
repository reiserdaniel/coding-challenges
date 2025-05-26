package crypto

import (
	"crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

type KeyPair interface {
	GetPublicKey() crypto.PublicKey
	GetPrivateKey() crypto.PrivateKey
	GetAlgorithm() domain.Algorithm
}

type KeyGenerator interface {
	Generate() (KeyPair, error)
}

// Signer defines a contract for different types of signing implementations.
type Signer interface {
	Sign(dataToBeSigned []byte) ([]byte, error)
}
