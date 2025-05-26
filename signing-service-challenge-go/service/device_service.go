package service

import (
	"encoding/base64"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"github.com/google/uuid"
	"sync"
)

type DeviceService struct {
	deviceRepository persistence.DeviceRepository
	keyGenFactory    *crypto.KeyGeneratorFactory
	signerFactory    *crypto.SignerFactory
	deviceMutexes    map[string]*sync.Mutex
	mapMutex         sync.RWMutex
}

func NewDeviceService(deviceRepository persistence.DeviceRepository) *DeviceService {
	return &DeviceService{
		deviceRepository: deviceRepository,
		keyGenFactory:    crypto.NewKeyGeneratorFactory(),
		signerFactory:    crypto.NewSignerFactory(),
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
		return nil, err
	}

	keyPair, err := keyGenerator.Generate()
	if err != nil {
		return nil, err
	}

	publicKey, privateKey, err := crypto.MarshalKeyPair(keyPair)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return device, nil
}

func (s *DeviceService) GetDeviceByID(deviceId string) (*domain.Device, error) {
	deviceRecord, err := s.deviceRepository.GetDeviceByID(deviceId)
	if err != nil {
		return nil, err
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

func (s *DeviceService) SignData(deviceId string, dataToBeSigned []byte) (domain.SignatureResult, error) {
	device, err := s.deviceRepository.GetDeviceByID(deviceId)
	if err != nil {
		return domain.SignatureResult{}, err
	}

	keyMarshaller := crypto.NewRSAMarshaler()
	keyPair, err := keyMarshaller.Unmarshal([]byte(device.PrivateKey))
	if err != nil {
		return domain.SignatureResult{}, err
	}

	signer, err := s.signerFactory.CreateSigner(keyPair)
	if err != nil {
		return domain.SignatureResult{}, err
	}

	mutex := s.getDeviceMutex(deviceId)
	mutex.Lock()
	defer mutex.Unlock()

	signature, err := signer.Sign(dataToBeSigned)
	if err != nil {
		return domain.SignatureResult{}, err
	}

	device.SignatureCounter++
	device.LastSignature = base64.StdEncoding.EncodeToString(signature)

	deviceRecord := &persistence.DeviceRecord{
		ID:               device.ID,
		Label:            device.Label,
		Algorithm:        device.Algorithm,
		SignatureCounter: device.SignatureCounter,
		LastSignature:    device.LastSignature,
		PublicKey:        device.PublicKey,
	}

	err = s.deviceRepository.UpdateDevice(deviceRecord)
	if err != nil {
		return domain.SignatureResult{}, err
	}

	return domain.SignatureResult{
		SignedData: dataToBeSigned,
		Signature:  signature,
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
