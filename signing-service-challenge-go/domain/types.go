package domain

type Algorithm string

const (
	RSA Algorithm = "RSA"
	ECC Algorithm = "ECC"
)

type Device struct {
	ID               string    `json:"id"`
	Algorithm        Algorithm `json:"algorithm"`
	Label            string    `json:"label"`
	SignatureCounter int       `json:"signature_counter"`
	LastSignature    string    `json:"last_signature"`
}

type SignatureResult struct {
	SignedData []byte `json:"signed_data"`
	Signature  []byte `json:"signature"`
}
