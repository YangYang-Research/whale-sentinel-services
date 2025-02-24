package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"time"
)

// RequestBody defines the structure of the request payload
type RequestBody struct {
	AgentID   string          `json:"agent_id"`
	Rule      map[string]bool `json:"rule"`
	Payload   Payload         `json:"payload"`
	Timestamp string          `json:"timestamp"`
}

// Payload defines the structure of the payload field in the request body
type Payload struct {
	Data Data `json:"data"`
}

// Data defines the structure of the data field in the payload
type Data struct {
	ClientInformation ClientInformation `json:"client_information"`
	HTTPRequest       HTTPRequest       `json:"http_request"`
}

// ClientInformation defines the structure of the client information field in the data
type ClientInformation struct {
	IP          string      `json:"ip"`
	DeviceType  string      `json:"device_type"`
	NetworkType string      `json:"network_type"`
	Geolocation Geolocation `json:"geolocation"`
}

// Geolocation defines the structure of the geolocation field in the client information
type Geolocation struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
}

// HTTPRequest defines the structure of the HTTP request field in the data
type HTTPRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	QueryParams string            `json:"query_parameters"`
	Body        string            `json:"body"`
}

// ResponseBody defines the structure of the response payload
type ResponseBody struct {
	Status      string       `json:"status"`
	Message     string       `json:"message"`
	Data        ResponseData `json:"data"`
	ProcessedAt string       `json:"processed_at"`
}

type ResponseData struct {
	WebAttackDetectionScore int             `json:"ws_module_web_attack_detection_score"`
	DGADetectionScore       int             `json:"ws_module_dga_detection_score"`
	CommonAttackDetection   map[string]bool `json:"ws_module_common_attack_detection"`
	Hash                    string          `json:"hash"`
}

// ErrorResponse defines the structure of the error response payload
type ErrorResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	ErrorCode int    `json:"error_code"`
}

// handleGateway processes incoming requests and routes them to the correct module
func handleGateway(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req RequestBody
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.AgentID == "" || req.Rule == nil || req.Payload.Data.ClientInformation.IP == "" || req.Payload.Data.ClientInformation.DeviceType == "" || req.Payload.Data.ClientInformation.NetworkType == "" || req.Payload.Data.HTTPRequest.Method == "" || req.Payload.Data.HTTPRequest.URL == "" || req.Payload.Data.HTTPRequest.Headers == nil || req.Timestamp == "" {
		sendErrorResponse(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Validate AgentID format
	matched, err := regexp.MatchString(`^ws_agent_.*`, req.AgentID)
	if err != nil || !matched {
		sendErrorResponse(w, "Invalid AgentID format", http.StatusBadRequest)
		return
	}

	// Validate timestamp
	_, err = time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		sendErrorResponse(w, "Invalid timestamp format", http.StatusBadRequest)
		return
	}

	// Calculate hash
	hashInput := req.Payload.Data.ClientInformation.IP + req.Payload.Data.ClientInformation.DeviceType + req.Timestamp + req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
	hash := sha256.Sum256([]byte(hashInput))
	hashString := hex.EncodeToString(hash[:])

	// Process the rules
	data := ResponseData{
		WebAttackDetectionScore: 0,
		DGADetectionScore:       0,
		CommonAttackDetection:   map[string]bool{"open_redirect": true, "large_request": false, "http_method_tampering": false, "sql_injection": false, "cross_site_scripting": false},
		Hash:                    hashString,
	}

	if req.Rule["ws_module_web_attack_detection"] {
		processWebAttackDetection(req)
	}
	if req.Rule["ws_module_dga_detection"] {
		processDGADetection(req)
	}

	response := ResponseBody{
		Status:      "success",
		Message:     "Request processed successfully",
		Data:        data,
		ProcessedAt: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// processWebAttackDetection handles requests for Web Attack Detection module
func processWebAttackDetection(req RequestBody) {
	log.Printf("Processing Web Attack Detection for Agent ID: %s", req.AgentID)
}

// processDGADetection handles requests for DGA Detection module
func processDGADetection(req RequestBody) {
	log.Printf("Processing DGA Detection for Agent ID: %s", req.AgentID)
}

// sendErrorResponse sends a JSON error response
func sendErrorResponse(w http.ResponseWriter, message string, errorCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errorCode)
	json.NewEncoder(w).Encode(ErrorResponse{
		Status:    "error",
		Message:   message,
		ErrorCode: errorCode,
	})
}

func main() {
	http.HandleFunc("/api/v1/ws/service/gateway", handleGateway)
	log.Println("WS Gateway Service is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
