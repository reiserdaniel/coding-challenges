package api

import (
	"encoding/json"
	"fmt"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/service"
	"net/http"
)

type DeviceHandler struct {
	deviceService *service.DeviceService
}

func NewDeviceHandler(deviceService *service.DeviceService) *DeviceHandler {
	return &DeviceHandler{
		deviceService: deviceService,
	}
}

func (h *DeviceHandler) RegisterRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("GET /devices", http.HandlerFunc(h.GetAllSignatureDevices))
	mux.Handle("POST /devices", http.HandlerFunc(h.CreateSignatureDevice))
	mux.Handle("GET /devices/{id}", http.HandlerFunc(h.GetSignatureDevice))
	mux.Handle("POST /devices/{id}/sign", http.HandlerFunc(h.SignTransaction))

	return mux
}

type CreateSignatureDeviceRequest struct {
	Algorithm string `json:"algorithm"`
	Label     string `json:"label,omitempty"`
}

type SignTransactionRequest struct {
	Data string `json:"data"`
}

func (h *DeviceHandler) CreateSignatureDevice(response http.ResponseWriter, request *http.Request) {
	var createDeviceRequest CreateSignatureDeviceRequest
	if err := json.NewDecoder(request.Body).Decode(&createDeviceRequest); err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			fmt.Sprintf("Invalid request body: %v", err),
		})
		return
	}

	device, err := h.deviceService.CreateDevice(domain.Algorithm(createDeviceRequest.Algorithm), createDeviceRequest.Label)
	if err != nil {
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			fmt.Sprintf("Failed to create device: %v", err),
		})
		return
	}

	WriteAPIResponse(response, http.StatusCreated, device)
}

func (h *DeviceHandler) GetSignatureDevice(response http.ResponseWriter, request *http.Request) {
	deviceId := request.PathValue("id")
	if deviceId == "" {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"Device ID is required",
		})
		return
	}

	device, err := h.deviceService.GetDeviceByID(deviceId)
	if err != nil {
		WriteErrorResponse(response, http.StatusNotFound, []string{
			fmt.Sprintf("Device with ID %s not found: %v", deviceId, err),
		})
		return
	}

	WriteAPIResponse(response, http.StatusOK, device)
}

func (h *DeviceHandler) GetAllSignatureDevices(response http.ResponseWriter, request *http.Request) {
	devices, err := h.deviceService.GetAllDevices()
	if err != nil {
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			fmt.Sprintf("Failed to retrieve devices: %v", err),
		})
		return
	}

	WriteAPIResponse(response, http.StatusOK, devices)
}

func (h *DeviceHandler) SignTransaction(response http.ResponseWriter, request *http.Request) {
	deviceId := request.PathValue("id")
	if deviceId == "" {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"Device ID is required",
		})
		return
	}

	var signRequest SignTransactionRequest
	if err := json.NewDecoder(request.Body).Decode(&signRequest); err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			fmt.Sprintf("Invalid request body: %v", err),
		})
		return
	}

	signature, err := h.deviceService.SignData(deviceId, signRequest.Data)
	if err != nil {
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			fmt.Sprintf("Failed to sign data: %v", err),
		})
		return
	}

	WriteAPIResponse(response, http.StatusOK, signature)
}
