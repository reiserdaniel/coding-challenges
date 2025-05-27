package service

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"github.com/stretchr/testify/assert"
)

func setupService() *DeviceService {
	return NewDeviceService(
		persistence.NewInMemoryDeviceRepository(),
		crypto.NewKeyGeneratorFactory(),
		crypto.NewSignerFactory(),
	)
}

func TestCreateDevice(t *testing.T) {
	service := setupService()

	tests := []struct {
		name      string
		algorithm domain.Algorithm
		label     string
	}{
		{"ECC with label", domain.ECC, "ecc label"},
		{"RSA with label", domain.RSA, "rsa label"},
		{"ECC without label", domain.ECC, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device, err := service.CreateDevice(tt.algorithm, tt.label)
			assert.NoError(t, err)
			assert.NotEmpty(t, device.ID)
			assert.Equal(t, tt.label, device.Label)
			assert.Equal(t, tt.algorithm, device.Algorithm)
			assert.Equal(t, 0, device.SignatureCounter)
			expectedLastSig := base64.StdEncoding.EncodeToString([]byte(device.ID))
			assert.Equal(t, expectedLastSig, device.LastSignature)
		})
	}
}

func TestGetDeviceByID(t *testing.T) {
	service := setupService()
	device, _ := service.CreateDevice(domain.ECC, "ecc label")

	got, err := service.GetDeviceByID(device.ID)
	assert.NoError(t, err)
	assert.Equal(t, device, got)

	_, err = service.GetDeviceByID("doesnotexist")
	assert.Error(t, err, "should error for non-existent device")
}

func TestGetAllDevices(t *testing.T) {
	service := setupService()
	device1, _ := service.CreateDevice(domain.ECC, "ecc label")
	device2, _ := service.CreateDevice(domain.RSA, "rsa label")

	devices, err := service.GetAllDevices()
	assert.NoError(t, err)
	assert.Len(t, devices, 2)
	assert.Contains(t, devices, device1)
	assert.Contains(t, devices, device2)
}

func TestSignDataAndCounter(t *testing.T) {
	service := setupService()
	device, _ := service.CreateDevice(domain.ECC, "ecc label")

	// First signature
	data1 := "foo"
	sig1, err := service.SignData(device.ID, data1)
	assert.NoError(t, err)
	assert.NotNil(t, sig1)

	expectedSecuredData1 := fmt.Sprintf("%d_%s_%s", 0, data1, base64.StdEncoding.EncodeToString([]byte(device.ID)))
	assert.Equal(t, expectedSecuredData1, sig1.SignedData)
	assert.NotEmpty(t, sig1.Signature)

	// Use the service's keypair and signer to verify the signature
	deviceWithKeys, err := service.getDeviceWithKeys(device.ID)
	assert.NoError(t, err)
	signer, err := service.signerFactory.CreateSigner(deviceWithKeys.KeyPair)
	assert.NoError(t, err)

	sigBytes1, err := base64.StdEncoding.DecodeString(sig1.Signature)
	assert.NoError(t, err)
	valid := signer.VerifySignature([]byte(sig1.SignedData), sigBytes1)
	assert.True(t, valid, "Signature should be valid")

	// Check counter incremented and lastSignature updated
	got, _ := service.GetDeviceByID(device.ID)
	assert.Equal(t, 1, got.SignatureCounter)
	assert.Equal(t, sig1.Signature, got.LastSignature)

	// Second signature
	data2 := "bar"
	sig2, err := service.SignData(device.ID, data2)
	assert.NoError(t, err)
	assert.NotNil(t, sig2)

	expectedSecuredData2 := fmt.Sprintf("%d_%s_%s", 1, data2, sig1.Signature)
	assert.Equal(t, expectedSecuredData2, sig2.SignedData)

	sigBytes2, err := base64.StdEncoding.DecodeString(sig2.Signature)
	assert.NoError(t, err)
	valid = signer.VerifySignature([]byte(sig2.SignedData), sigBytes2)
	assert.True(t, valid, "Signature should be valid")

	// Verify final state
	got, _ = service.GetDeviceByID(device.ID)
	assert.Equal(t, 2, got.SignatureCounter)
	assert.Equal(t, sig2.Signature, got.LastSignature)
}

func TestSignDataErrors(t *testing.T) {
	service := setupService()
	// Non-existent device
	_, err := service.SignData("doesnotexist", "foo")
	assert.Error(t, err, "should error for non-existent device")
}
