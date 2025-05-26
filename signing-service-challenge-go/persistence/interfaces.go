package persistence

type DeviceRepository interface {
	GetDeviceByID(id string) (*DeviceRecord, error)
	GetAllDevices() ([]*DeviceRecord, error)
	CreateDevice(device *DeviceRecord) error
	UpdateDevice(device *DeviceRecord) error
}
