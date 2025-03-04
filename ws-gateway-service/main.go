package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Error loading .env file: %v\n", err)
	}
}

// RequestBody defines the structure of the request payload
type RequestBody struct {
	AgentID   string  `json:"agent_id"`
	Rule      Rule    `json:"rule"`
	Payload   Payload `json:"payload"`
	Timestamp string  `json:"timestamp"`
}

// Rule defines the structure of the rule field in the request body
type Rule struct {
	WebAttackDetection    WebAttackDetectionRule    `json:"ws_module_web_attack_detection"`
	DGADetection          DGADetectionRule          `json:"ws_module_dga_detection"`
	CommonAttackDetection CommonAttackDetectionRule `json:"ws_module_common_attack_detection"`
}

// WebAttackDetectionRule defines the structure of the web attack detection rule
type WebAttackDetectionRule struct {
	Enable       string `json:"enable"`
	DetectHeader string `json:"detect_header"`
}

// DGADetectionRule defines the structure of the DGA detection rule
type DGADetectionRule struct {
	Enable string `json:"enable"`
}

// CommonAttackDetectionRule defines the structure of the common attack detection rule
type CommonAttackDetectionRule struct {
	Enable                    string `json:"enable"`
	DetectUnvalidatedRedirect string `json:"detect_unvalidated_redirect"`
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
	Host        string            `json:"host"`
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
	WebAttackDetectionScore string          `json:"ws_module_web_attack_detection_score"`
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
	if req.AgentID == "" || req.Payload.Data.ClientInformation.IP == "" || req.Payload.Data.ClientInformation.DeviceType == "" || req.Payload.Data.ClientInformation.NetworkType == "" || req.Payload.Data.HTTPRequest.Method == "" || req.Payload.Data.HTTPRequest.URL == "" || req.Payload.Data.HTTPRequest.Headers == nil || req.Timestamp == "" {
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
	var score string
	if req.Rule.WebAttackDetection.Enable == "true" {
		responseData, err := processWebAttackDetection(req)
		if err != nil {
			log.Printf("Error processing web attack detection: %v", err)
			score = "0"
		} else {
			var response map[string]interface{}
			err = json.Unmarshal([]byte(responseData), &response)
			if err != nil {
				log.Printf("Failed to parse response data: %v", err)
				return
			}
			threatMetrix := response["threat_metrix"].(map[string]interface{})
			score = fmt.Sprintf("%f", threatMetrix["score"])
		}
	}

	if req.Rule.DGADetection.Enable == "true" {
		processDGADetection(req)
	}

	data := ResponseData{
		WebAttackDetectionScore: score,
		DGADetectionScore:       0,
		CommonAttackDetection:   map[string]bool{"open_redirect": true, "large_request": false, "http_method_tampering": false, "sql_injection": false, "cross_site_scripting": false},
		Hash:                    hashString,
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
func processWebAttackDetection(req RequestBody) (string, error) {
	log.Printf("Processing Web Attack Detection for Agent ID: %s", req.AgentID)
	httpRequest := req.Payload.Data.HTTPRequest
	var concatenatedData string
	if req.Rule.WebAttackDetection.DetectHeader == "true" {
		concatenatedData = fmt.Sprintf("%s %s \n Host: %s \n User-Agent: %s \n Content-Type: %s \n Content-Length: %s \n\n %s%s",
			httpRequest.Method,
			httpRequest.URL,
			httpRequest.Host,
			httpRequest.Headers["User-Agent"],
			httpRequest.Headers["Content-Type"],
			httpRequest.Headers["Content-Length"],
			httpRequest.QueryParams,
			httpRequest.Body)

	} else {
		concatenatedData = fmt.Sprintf("%s %s",
			httpRequest.QueryParams,
			httpRequest.Body)
	}

	requestBody := map[string]string{
		"payload": concatenatedData,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		log.Printf("Failed to marshal request body: %v", err)
	}

	webAttackURL := os.Getenv("WS_MODULE_WEB_ATTACK_DETECTION_URL")
	webAttackEndpoint := os.Getenv("WS_MODULE_WEB_ATTACK_DETECTION_ENDPOINT")
	fullURL := fmt.Sprintf("%s%s", webAttackURL, webAttackEndpoint)

	apiKey, err := getAPIKey()
	if err != nil {
		log.Printf("Failed to get API key: %v", err)
		return "", err
	}

	client := &http.Client{}
	webAttackReq, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return "", err
	}

	webAttackReq.Header.Set("Content-Type", "application/json")
	auth := "ws:" + apiKey
	webAttackReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	resp, err := client.Do(webAttackReq)
	if err != nil {
		log.Printf("Failed to call Web Attack Detection module: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		return "", err
	}

	log.Printf("Web Attack Detection module responded with status: %d", resp.StatusCode)
	return string(body), nil
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

// decryptAPIKeyWithKMS decrypts the API key value using AWS KMS
func decryptAPIKeyWithKMS(encryptedAPIKey string) (string, error) {
	sess := session.Must(session.NewSession())
	svc := kms.New(sess, aws.NewConfig().WithRegion(os.Getenv("AWS_REGION")))

	decodedAPIKey, err := base64.StdEncoding.DecodeString(encryptedAPIKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted API key: %v", err)
	}

	input := &kms.DecryptInput{
		CiphertextBlob: decodedAPIKey,
	}

	result, err := svc.Decrypt(input)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt API key: %v", err)
	}

	return string(result.Plaintext), nil
}

// getAPIKey retrieves the API key based on the configuration
func getAPIKey() (string, error) {
	if os.Getenv("AWS_KMS_ENABLE") == "true" {
		encryptedAPIKey := os.Getenv("API_KEY")
		return decryptAPIKeyWithKMS(encryptedAPIKey)
	}

	return os.Getenv("API_KEY"), nil
}

// apiKeyAuthMiddleware is a middleware that handles API Key authentication
func apiKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey, err := getAPIKey()
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Decode the Base64-encoded Authorization header
		authHeader = authHeader[len("Basic "):]
		decodedAuthHeader, err := base64.StdEncoding.DecodeString(authHeader)
		if err != nil {
			sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		expectedAuthValue := fmt.Sprintf("ws:%s", apiKey)
		if string(decodedAuthHeader) != expectedAuthValue {
			sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	http.Handle("/api/v1/ws/services/gateway", apiKeyAuthMiddleware(http.HandlerFunc(handleGateway)))
	log.Println("WS Gateway Service is running on port 5000...")
	log.Fatal(http.ListenAndServe(":5000", nil))
}
