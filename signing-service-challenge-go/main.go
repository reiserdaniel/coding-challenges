package main

import (
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/service"
	"log"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/api"
)

const (
	ListenAddress = ":8080"
	// TODO: add further configuration parameters here ...
)

func main() {
	deviceRepository := persistence.NewInMemoryDeviceRepository()
	deviceService := service.NewDeviceService(deviceRepository)
	deviceHandler := api.NewDeviceHandler(deviceService)
	server := api.NewServer(ListenAddress, deviceHandler)

	if err := server.Run(); err != nil {
		log.Fatal("Could not start server on ", ListenAddress)
	}
}
