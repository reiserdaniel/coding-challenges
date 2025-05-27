package main

import (
	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/service"
	"log"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/api"
)

const (
	ListenAddress = ":8080"
)

func main() {
	deviceService := service.NewDeviceService(
		persistence.NewInMemoryDeviceRepository(),
		crypto.NewKeyGeneratorFactory(),
		crypto.NewSignerFactory(),
	)
	deviceHandler := api.NewDeviceHandler(deviceService)
	server := api.NewServer(ListenAddress, deviceHandler)

	if err := server.Run(); err != nil {
		log.Fatal("Could not start server on ", ListenAddress)
	}
}
