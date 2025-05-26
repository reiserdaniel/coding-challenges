package crypto

import (
	"fmt"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

// KeyGeneratorFactory creates KeyGenerator based on the specified algorithm.
type KeyGeneratorFactory struct {
}

func NewKeyGeneratorFactory() *KeyGeneratorFactory {
	return &KeyGeneratorFactory{}
}

func (f *KeyGeneratorFactory) CreateGenerator(algorithm domain.Algorithm) (KeyGenerator, error) {
	switch algorithm {
	case domain.RSA:
		return &RSAGenerator{}, nil
	case domain.ECC:
		return &ECCGenerator{}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// SignerFactory creates KeyMarshaller based on the specified algorithm.
type SignerFactory struct {
}

func NewSignerFactory() *SignerFactory {
	return &SignerFactory{}
}

func (f *SignerFactory) CreateSigner(keyPair KeyPair) (Signer, error) {
	switch keyPair.GetAlgorithm() {
	case domain.RSA:
		rsaKeyPair, ok := keyPair.(*RSAKeyPair)
		if !ok {
			return nil, fmt.Errorf("invalid key pair type for RSA: %T", keyPair)
		}
		return NewRSASigner(rsaKeyPair.Private), nil
	case domain.ECC:
		eccKeyPair, ok := keyPair.(*ECCKeyPair)
		if !ok {
			return nil, fmt.Errorf("invalid key pair type for ECC: %T", keyPair)
		}
		return NewECCSigner(eccKeyPair.Private), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", keyPair.GetAlgorithm())
	}
}

func MarshalKeyPair(keyPair KeyPair) ([]byte, []byte, error) {
	switch keyPair.GetAlgorithm() {
	case domain.RSA:
		marshaler := NewRSAMarshaler()
		return marshaler.Marshal(*keyPair.(*RSAKeyPair))
	case domain.ECC:
		marshaler := NewECCMarshaler()
		return marshaler.Encode(*keyPair.(*ECCKeyPair))
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", keyPair.GetAlgorithm())
	}
}

func UnmarshalKeyPair(algorithm domain.Algorithm, privateKeyBytes []byte) (KeyPair, error) {
	switch algorithm {
	case domain.RSA:
		marshaler := NewRSAMarshaler()
		return marshaler.Unmarshal(privateKeyBytes)
	case domain.ECC:
		marshaler := NewECCMarshaler()
		return marshaler.Decode(privateKeyBytes)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}
