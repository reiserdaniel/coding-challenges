package persistence

// DeviceRecord represents a device record in the persistence layer.
type DeviceRecord struct {
	ID               string `json:"id"`
	Algorithm        string `json:"algorithm"`
	Label            string `json:"label,omitempty"`
	SignatureCounter int    `json:"signature_counter"`
	LastSignature    string `json:"last_signature"`
	PublicKey        []byte `json:"public_key"`
	PrivateKey       []byte `json:"private_key"`
}
