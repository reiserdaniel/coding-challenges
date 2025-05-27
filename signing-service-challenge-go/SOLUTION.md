# Signature Service - Coding Challenge

## Instructions

### How to Run Locally

Follow these steps to run the API locally:

1. Make sure you have [Golang](https://golang.org/) installed (v1.23+).
2. Clone the repository and open go challenge directory:
   ```bash
   cd signing-service-challenge-go
   ```
3. Run the API service:
   ```bash
   go run main.go
   ```

The service should now be available at `http://localhost:8080`.

---

### API Collection with Postman

You can use Postman to test the API. Import the provided Postman collection file `postman_collection.json` into Postman to access preconfigured requests for all the endpoints.

---

### Testing Information

- **Tests Coverage**:  
  Tests are implemented only for the main `DeviceService` to focus on core business logic. These tests ensure the correctness of:
    - Device management.
    - Signature generation.

- **Business Logic Validation**:  
  The tests validate that:
    - Devices are created correctly with UUIDs, keys, and signature algorithms.
    - Signature generation respects the specifications (e.g., concatenated strings with signature counters).

---

### Potential Improvements

- Add detailed logging to the project for better observability and debugging.
- Extend unit test coverage to other classes, such as handlers and helpers.
- Add integration tests to validate the end-to-end behavior of the API, including all endpoints and HTTP responses.

These improvements would provide a more robust and comprehensive solution.