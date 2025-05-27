package service

import (
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"github.com/google/uuid"
)

type DeviceService struct {
	deviceRepository persistence.DeviceRepository
	keyGenFactory    *crypto.KeyGeneratorFactory
	signerFactory    *crypto.SignerFactory
	deviceMutexes    map[string]*sync.Mutex
	mapMutex         sync.RWMutex
}

type DeviceWithKeys struct {
	*domain.Device
	KeyPair crypto.KeyPair
}

func NewDeviceService(deviceRepository persistence.DeviceRepository, keyGenFactory *crypto.KeyGeneratorFactory, signerFactory *crypto.SignerFactory) *DeviceService {
	return &DeviceService{
		deviceRepository: deviceRepository,
		keyGenFactory:    keyGenFactory,
		signerFactory:    signerFactory,
		deviceMutexes:    make(map[string]*sync.Mutex),
		mapMutex:         sync.RWMutex{},
	}
}

func (s *DeviceService) CreateDevice(algorithm domain.Algorithm, label string) (*domain.Device, error) {
	deviceId := uuid.New().String()
	// Initialize lastSignature with a base64 encoding of the deviceId
	lastSignature := base64.StdEncoding.EncodeToString([]byte(deviceId))

	device := &domain.Device{
		ID:               deviceId,
		Label:            label,
		Algorithm:        algorithm,
		SignatureCounter: 0,
		LastSignature:    lastSignature,
	}

	keyGenerator, err := s.keyGenFactory.CreateGenerator(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to create key generator: %w", err)
	}

	keyPair, err := keyGenerator.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	publicKey, privateKey, err := crypto.MarshalKeyPair(keyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key pair: %w", err)
	}

	deviceRecord := &persistence.DeviceRecord{
		ID:               device.ID,
		Label:            device.Label,
		Algorithm:        string(device.Algorithm),
		SignatureCounter: device.SignatureCounter,
		LastSignature:    device.LastSignature,
		PublicKey:        publicKey,
		PrivateKey:       privateKey,
	}

	err = s.deviceRepository.CreateDevice(deviceRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to create device: %w", err)
	}

	return device, nil
}

func (s *DeviceService) GetDeviceByID(deviceId string) (*domain.Device, error) {
	deviceRecord, err := s.deviceRepository.GetDeviceByID(deviceId)
	if err != nil {
		return nil, fmt.Errorf("failed to get device by id: %w", err)
	}

	return s.recordToDevice(deviceRecord), nil
}

func (s *DeviceService) recordToDevice(deviceRecord *persistence.DeviceRecord) *domain.Device {
	return &domain.Device{
		ID:               deviceRecord.ID,
		Label:            deviceRecord.Label,
		Algorithm:        domain.Algorithm(deviceRecord.Algorithm),
		SignatureCounter: deviceRecord.SignatureCounter,
		LastSignature:    deviceRecord.LastSignature,
	}
}

func (s *DeviceService) GetAllDevices() ([]*domain.Device, error) {
	devices, err := s.deviceRepository.GetAllDevices()
	if err != nil {
		return nil, err
	}

	domainDevices := make([]*domain.Device, 0, len(devices))
	for _, deviceRecord := range devices {
		domainDevices = append(domainDevices, s.recordToDevice(deviceRecord))
	}

	return domainDevices, nil
}

func (s *DeviceService) SignData(deviceId string, dataToBeSigned string) (*domain.SignatureResult, error) {
	mutex := s.getDeviceMutex(deviceId)
	mutex.Lock()
	defer mutex.Unlock()

	deviceWithKeys, err := s.getDeviceWithKeys(deviceId)
	if err != nil {
		return nil, fmt.Errorf("failed to get device with keys: %w", err)
	}

	signer, err := s.signerFactory.CreateSigner(deviceWithKeys.KeyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// Format data according to specification
	securedData := fmt.Sprintf("%d_%s_%s",
		deviceWithKeys.SignatureCounter,
		dataToBeSigned,
		deviceWithKeys.LastSignature)

	signature, err := signer.Sign([]byte(securedData))
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	encodedSignature := base64.StdEncoding.EncodeToString(signature)

	deviceWithKeys.SignatureCounter++
	deviceWithKeys.LastSignature = encodedSignature

	deviceRecord := &persistence.DeviceRecord{
		ID:               deviceWithKeys.ID,
		Label:            deviceWithKeys.Label,
		Algorithm:        string(deviceWithKeys.Algorithm),
		SignatureCounter: deviceWithKeys.SignatureCounter,
		LastSignature:    deviceWithKeys.LastSignature,
	}

	err = s.deviceRepository.UpdateDevice(deviceRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to update device: %w", err)
	}

	return &domain.SignatureResult{
		SignedData: securedData,
		Signature:  encodedSignature,
	}, nil
}

// getDeviceWithKeys retrieves a device and reconstructs its key pair
func (s *DeviceService) getDeviceWithKeys(deviceID string) (*DeviceWithKeys, error) {
	deviceRecord, err := s.deviceRepository.GetDeviceByID(deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get device by id: %w", err)
	}

	device := s.recordToDevice(deviceRecord)

	// Reconstruct key pair
	keyPair, err := crypto.UnmarshalKeyPair(device.Algorithm, deviceRecord.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal key pair: %w", err)
	}

	return &DeviceWithKeys{
		Device:  device,
		KeyPair: keyPair,
	}, nil
}

func (s *DeviceService) getDeviceMutex(deviceId string) *sync.Mutex {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()

	if mutex, exists := s.deviceMutexes[deviceId]; exists {
		return mutex
	}

	mutex := &sync.Mutex{}
	s.deviceMutexes[deviceId] = mutex
	return mutex
}
