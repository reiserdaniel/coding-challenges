package persistence

import (
	"fmt"
	"sync"
)

type InMemoryDeviceRepository struct {
	devices map[string]*DeviceRecord
	mu      sync.RWMutex
}

func NewInMemoryDeviceRepository() *InMemoryDeviceRepository {
	return &InMemoryDeviceRepository{
		devices: make(map[string]*DeviceRecord),
		mu:      sync.RWMutex{},
	}
}

func (r *InMemoryDeviceRepository) GetDeviceByID(id string) (*DeviceRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if device, exists := r.devices[id]; exists {
		// Return a copy to prevent external modification
		copy := *device
		return &copy, nil
	}
	return nil, fmt.Errorf("device with ID %s not found", id)
}

func (r *InMemoryDeviceRepository) GetAllDevices() ([]*DeviceRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	devices := make([]*DeviceRecord, 0, len(r.devices))
	for _, device := range r.devices {
		// Append a copy to prevent external modification
		copy := *device
		devices = append(devices, &copy)
	}
	return devices, nil
}

func (r *InMemoryDeviceRepository) CreateDevice(device *DeviceRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.devices[device.ID]; exists {
		return fmt.Errorf("device with ID %s already exists", device.ID)
	}
	// Store a copy to prevent external modification
	copy := *device
	r.devices[device.ID] = &copy
	return nil
}

func (r *InMemoryDeviceRepository) UpdateDevice(device *DeviceRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.devices[device.ID]; !exists {
		return fmt.Errorf("device with ID %s does not exist", device.ID)
	}
	// Store a copy to prevent external modification
	copy := *device
	r.devices[device.ID] = &copy
	return nil
}
