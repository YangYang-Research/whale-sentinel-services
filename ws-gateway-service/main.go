package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/joho/godotenv"
)

// Load environment variables
func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

// Structs for request and response
type (
	RequestBody struct {
		AgentID          string  `json:"agent_id"`
		Rules            Rules   `json:"rules"`
		Payload          Payload `json:"payload"`
		RequestCreatedAt string  `json:"request_created_at"`
	}

	Rules struct {
		WebAttackDetection    WebAttackDetectionRule    `json:"ws_module_web_attack_detection"`
		DGADetection          DGADetectionRule          `json:"ws_module_dga_detection"`
		CommonAttackDetection CommonAttackDetectionRule `json:"ws_module_common_attack_detection"`
	}

	WebAttackDetectionRule struct {
		Enable       string `json:"enable"`
		DetectHeader string `json:"detect_header"`
	}

	DGADetectionRule struct {
		Enable string `json:"enable"`
	}

	CommonAttackDetectionRule struct {
		Enable                   string `json:"enable"`
		DetectCrossSiteScripting string `json:"detect_cross_site_scripting"`
		DetectLargeRequest       string `json:"detect_large_request"`
		DetectSqlInjection       string `json:"detect_sql_injection"`
		DetectHTTPVerbTampering  string `json:"detect_http_verb_tampering"`
		DetectHTTPLargeRequest   string `json:"detect_http_large_request"`
	}

	Payload struct {
		Data Data `json:"data"`
	}

	Data struct {
		ClientInformation ClientInformation `json:"client_information"`
		HTTPRequest       HTTPRequest       `json:"http_request"`
	}

	ClientInformation struct {
		IP          string      `json:"ip"`
		DeviceType  string      `json:"device_type"`
		NetworkType string      `json:"network_type"`
		Geolocation Geolocation `json:"geolocation"`
	}

	Geolocation struct {
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
		Country   string  `json:"country"`
		City      string  `json:"city"`
	}

	HTTPRequest struct {
		Method      string            `json:"method"`
		URL         string            `json:"url"`
		Host        string            `json:"host"`
		Headers     HTTPRequestHeader `json:"headers"`
		QueryParams string            `json:"query_parameters"`
		Body        string            `json:"body"`
	}

	HTTPRequestHeader struct {
		UserAgent     string `json:"user-agent"`
		ContentType   string `json:"content-type"`
		ContentLength int    `json:"content-length"`
		Referer       string `json:"referer"`
	}

	ResponseBody struct {
		Status             string       `json:"status"`
		Message            string       `json:"message"`
		Data               ResponseData `json:"data"`
		EventID            string       `json:"event_id"`
		RequestCreatedAt   string       `json:"request_created_at"`
		RequestProcessedAt string       `json:"request_processed_at"`
	}

	ResponseData struct {
		WebAttackDetectionScore float64         `json:"ws_module_web_attack_detection_score"`
		DGADetectionScore       float64         `json:"ws_module_dga_detection_score"`
		CommonAttackDetection   map[string]bool `json:"ws_module_common_attack_detection"`
	}

	ErrorResponse struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		ErrorCode int    `json:"error_code"`
	}
)

// handleGateway processes incoming requests
func handleGateway(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req RequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := validateRequest(req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	eventID := generateEventID(req)

	var (
		webAttackDetectionScore                                          float64
		DGADetectionScore                                                float64
		crossSiteScriptingDetection                                      bool
		sqlInjectionDetection                                            bool
		httpVerbTamperingDetection                                       bool
		httpLargeRequestDetection                                        bool
		wg                                                               sync.WaitGroup
		webAttackDetectionErr, commonAttackDetectionErr, dgaDetectionErr error
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		if req.Rules.WebAttackDetection.Enable == "true" {
			webAttackDetectionScore, webAttackDetectionErr = processWebAttackDetection(req, eventID)
		} else {
			webAttackDetectionScore = 0
		}
	}()

	go func() {
		defer wg.Done()
		if req.Rules.CommonAttackDetection.Enable == "true" {
			crossSiteScriptingDetection, sqlInjectionDetection, httpVerbTamperingDetection, httpLargeRequestDetection, commonAttackDetectionErr = processCommonAttackDetection(req, eventID)
		}
	}()

	go func() {
		defer wg.Done()
		if req.Rules.DGADetection.Enable == "true" {
			DGADetectionScore, dgaDetectionErr = processDGADetection(req, eventID)
		} else {
			DGADetectionScore = 0
		}
	}()

	wg.Wait()

	if webAttackDetectionErr != nil || commonAttackDetectionErr != nil || dgaDetectionErr != nil {
		log.Printf("Errors: Web Attack Detection: %v, Common Attack Detection: %v, DGA Detection %v", webAttackDetectionErr, commonAttackDetectionErr, dgaDetectionErr)
	}

	data := ResponseData{
		WebAttackDetectionScore: webAttackDetectionScore,
		DGADetectionScore:       DGADetectionScore,
		CommonAttackDetection: map[string]bool{
			"cross_site_scripting_detection": crossSiteScriptingDetection,
			"sql_injection_detection":        sqlInjectionDetection,
			"http_verb_tampering_detection":  httpVerbTamperingDetection,
			"http_large_request_detection":   httpLargeRequestDetection,
		},
	}

	response := ResponseBody{
		Status:             "success",
		Message:            "Request processed successfully",
		Data:               data,
		EventID:            eventID,
		RequestCreatedAt:   req.RequestCreatedAt,
		RequestProcessedAt: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper functions
func validateRequest(req RequestBody) error {
	if req.Payload.Data.ClientInformation.IP == "" || req.Payload.Data.ClientInformation.DeviceType == "" || req.Payload.Data.ClientInformation.NetworkType == "" || req.Payload.Data.HTTPRequest.Method == "" || req.Payload.Data.HTTPRequest.URL == "" || req.Payload.Data.HTTPRequest.Headers.UserAgent == "" || req.Payload.Data.HTTPRequest.Headers.ContentType == "" {
		return fmt.Errorf("missing required fields")
	}

	if matched, _ := regexp.MatchString(`^ws_agent_.*`, req.AgentID); !matched {
		return fmt.Errorf("invalid AgentID format")
	}

	if _, err := time.Parse(time.RFC3339, req.RequestCreatedAt); err != nil {
		return fmt.Errorf("invalid timestamp format")
	}
	return nil
}

func generateEventID(req RequestBody) string {
	hashInput := req.Payload.Data.ClientInformation.IP + req.Payload.Data.ClientInformation.DeviceType + req.Payload.Data.HTTPRequest.Method + req.Payload.Data.HTTPRequest.Host + req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
	hash := sha256.Sum256([]byte(hashInput))
	eventID := req.AgentID + "|" + "WS_GATEWAY_SERVICE" + "|" + hex.EncodeToString(hash[:])
	return eventID
}

func makeHTTPRequest(url, endpoint string, body interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	apiKey, err := getAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %v", err)
	}

	req, err := http.NewRequest("POST", url+endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	auth := "ws:" + apiKey
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %v", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// Module processing functions
func processWebAttackDetection(req RequestBody, eventID string) (float64, error) {
	log.Printf("Processing Web Attack Detection for Event ID: %s", eventID)

	httpRequest := req.Payload.Data.HTTPRequest
	var concatenatedData string
	if req.Rules.WebAttackDetection.DetectHeader == "true" {
		concatenatedData = fmt.Sprintf("%s %s \n Host: %s \n User-Agent: %s \n Content-Type: %s \n Content-Length: %d \n\n %s%s",
			httpRequest.Method, httpRequest.URL, httpRequest.Host, httpRequest.Headers.UserAgent, httpRequest.Headers.ContentType, httpRequest.Headers.ContentLength, httpRequest.QueryParams, httpRequest.Body)
	} else {
		concatenatedData = fmt.Sprintf("%s %s",
			httpRequest.QueryParams,
			httpRequest.Body)
	}

	requestBody := map[string]interface{}{
		"event_id":           eventID,
		"payload":            concatenatedData,
		"request_created_at": time.Now().Format(time.RFC3339),
	}

	responseData, err := makeHTTPRequest(os.Getenv("WS_MODULE_WEB_ATTACK_DETECTION_URL"), os.Getenv("WS_MODULE_WEB_ATTACK_DETECTION_ENDPOINT"), requestBody)
	if err != nil {
		return 0, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseData, &response); err != nil {
		return 0, fmt.Errorf("failed to parse response data: %v", err)
	}

	//Debug: Log the response JSON
	// log.Printf("Response JSON: %+v", response)
	log.Printf("Processed Web Attack Detection for Event ID: %s", response["event_id"])

	// Check if the "data" key exists and is not nil
	dataValue, ok := response["data"]
	if !ok || dataValue == nil {
		return 0, fmt.Errorf("key 'data' is missing or nil in the response")
	}

	// Perform type assertion for the "data" key
	data, ok := dataValue.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid type for 'data': expected map[string]interface{}")
	}

	// Check if the "threat_metrix" key exists and is not nil
	threatMetrixValue, ok := data["threat_metrix"]
	if !ok || threatMetrixValue == nil {
		return 0, fmt.Errorf("key 'threat_metrix' is missing or nil in the response")
	}

	// Perform type assertion for the "threat_metrix" key
	threatMetrix, ok := threatMetrixValue.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid type for 'threat_metrix': expected map[string]interface{}")
	}

	// Check if the "score" key exists and is not nil
	scoreValue, ok := threatMetrix["score"]
	if !ok || scoreValue == nil {
		return 0, fmt.Errorf("key 'score' is missing or nil in the response")
	}

	// Perform type assertion for the "score" key
	score, ok := scoreValue.(float64)
	if !ok {
		return 0, fmt.Errorf("invalid type for 'score': expected float64, got %T", scoreValue)
	}

	return score, nil
}

func processCommonAttackDetection(req RequestBody, eventID string) (bool, bool, bool, bool, error) {
	log.Printf("Processing Common Attack Detection for Event ID: %s", eventID)

	requestBody := map[string]interface{}{
		"event_id": eventID,
		"rules": map[string]string{
			"detect_cross_site_scripting": req.Rules.CommonAttackDetection.DetectCrossSiteScripting,
			"detect_large_request":        req.Rules.CommonAttackDetection.DetectLargeRequest,
			"detect_sql_injection":        req.Rules.CommonAttackDetection.DetectSqlInjection,
			"detect_http_verb_tampering":  req.Rules.CommonAttackDetection.DetectHTTPVerbTampering,
			"detect_http_large_request":   req.Rules.CommonAttackDetection.DetectHTTPLargeRequest,
		},
		"payload": map[string]interface{}{
			"data": map[string]interface{}{
				"client_information": map[string]interface{}{
					"ip":           req.Payload.Data.ClientInformation.IP,
					"device_type":  req.Payload.Data.ClientInformation.DeviceType,
					"network_type": req.Payload.Data.ClientInformation.NetworkType,
					"geolocation": map[string]interface{}{
						"latitude":  req.Payload.Data.ClientInformation.Geolocation.Latitude,
						"longitude": req.Payload.Data.ClientInformation.Geolocation.Longitude,
						"country":   req.Payload.Data.ClientInformation.Geolocation.Country,
						"city":      req.Payload.Data.ClientInformation.Geolocation.City,
					},
				},
				"http_request": map[string]interface{}{
					"method": req.Payload.Data.HTTPRequest.Method,
					"url":    req.Payload.Data.HTTPRequest.URL,
					"host":   req.Payload.Data.HTTPRequest.Host,
					"headers": map[string]interface{}{
						"user-agent":     req.Payload.Data.HTTPRequest.Headers.UserAgent,
						"content-type":   req.Payload.Data.HTTPRequest.Headers.ContentType,
						"content-length": req.Payload.Data.HTTPRequest.Headers.ContentLength,
						"referer":        req.Payload.Data.HTTPRequest.Headers.Referer,
					},
					"query_parameters": req.Payload.Data.HTTPRequest.QueryParams,
					"body":             req.Payload.Data.HTTPRequest.Body,
				},
			},
		},
		"request_created_at": time.Now().Format(time.RFC3339),
	}

	responseData, err := makeHTTPRequest(os.Getenv("WS_MODULE_COMMON_ATTACK_DETECTION_URL"), os.Getenv("WS_MODULE_COMMON_ATTACK_DETECTION_ENDPOINT"), requestBody)
	if err != nil {
		return false, false, false, false, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseData, &response); err != nil {
		return false, false, false, false, fmt.Errorf("failed to parse response data: %v", err)
	}

	//Debug: Log the response JSON
	//log.Printf("Response JSON: %+v", response)
	log.Printf("Processed Common Attack Detection for Event ID: %s", response["event_id"])

	data := response["data"].(map[string]interface{})
	return data["cross_site_scripting_detection"].(bool),
		data["sql_injection_detection"].(bool),
		data["http_verb_tampering_detection"].(bool),
		data["http_large_request_detection"].(bool),
		nil
}

func getDomain(fullUrl string) (string, error) {
	parsedUrl, err := url.Parse(fullUrl)
	if err != nil {
		return "", err
	}
	return parsedUrl.Host, nil
}

func processDGADetection(req RequestBody, eventID string) (float64, error) {
	log.Printf("Processing DGA Detection for Event ID: %s", eventID)

	refererURL := req.Payload.Data.HTTPRequest.Headers.Referer

	domain, err := getDomain(refererURL)
	if err != nil {
		return 0, err
	}

	RequestBody := map[string]string{
		"event_id":           eventID,
		"payload":            domain,
		"request_created_at": time.Now().Format(time.RFC3339),
	}

	responseData, err := makeHTTPRequest(os.Getenv("WS_MODULE_DGA_DETECTION_URL"), os.Getenv("WS_MODULE_DGA_DETECTION_ENDPOINT"), RequestBody)
	if err != nil {
		return 0, err
	}

	var response map[string]interface{}
	if err := json.Unmarshal(responseData, &response); err != nil {
		return 0, fmt.Errorf("failed to parse response data: %v", err)
	}

	//Debug: Log the response JSON
	// log.Printf("Response JSON: %+v", response)
	log.Printf("Processed DGA Detection for Event ID: %s", response["event_id"])

	// Check if the "data" key exists and is not nil
	dataValue, ok := response["data"]
	if !ok || dataValue == nil {
		return 0, fmt.Errorf("key 'data' is missing or nil in the response")
	}

	// Perform type assertion for the "data" key
	data, ok := dataValue.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid type for 'data': expected map[string]interface{}")
	}

	// Check if the "threat_metrix" key exists and is not nil
	threatMetrixValue, ok := data["threat_metrix"]
	if !ok || threatMetrixValue == nil {
		return 0, fmt.Errorf("key 'threat_metrix' is missing or nil in the response")
	}

	// Perform type assertion for the "threat_metrix" key
	threatMetrix, ok := threatMetrixValue.(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("invalid type for 'threat_metrix': expected map[string]interface{}")
	}

	// Check if the "score" key exists and is not nil
	scoreValue, ok := threatMetrix["score"]
	if !ok || scoreValue == nil {
		return 0, fmt.Errorf("key 'score' is missing or nil in the response")
	}

	// Perform type assertion for the "score" key
	score, ok := scoreValue.(float64)
	if !ok {
		return 0, fmt.Errorf("invalid type for 'score': expected float64, got %T", scoreValue)
	}

	return score, nil
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

// getAPIKey retrieves the API key based on the configuration
func getAPIKey() (string, error) {
	awsRegion := os.Getenv("AWS_REGION")
	awsAPIKeyName := os.Getenv("AWS_API_KEY_NAME")

	config, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(awsRegion))
	if err != nil {
		log.Fatal(err)
	}

	// Create Secrets Manager client
	svc := secretsmanager.NewFromConfig(config)

	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(awsAPIKeyName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := svc.GetSecretValue(context.TODO(), input)
	if err != nil {
		// For a list of exceptions thrown, see
		// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
		log.Fatal(err.Error())
	}

	// Decrypts secret using the associated KMS key.
	var secretString string = *result.SecretString

	// Parse the JSON string to extract the apiKey
	var secretData map[string]string
	if err := json.Unmarshal([]byte(secretString), &secretData); err != nil {
		log.Fatalf("Failed to parse secret string: %v", err)
	}

	apiKey, exists := secretData["apiKey"]
	if !exists {
		log.Fatalf("apiKey not found in secret string")
	}

	return apiKey, nil
}

// apiKeyAuthMiddleware is a middleware that handles API Key authentication
func apiKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey, err := getAPIKey()
		if err != nil {
			sendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
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

// Main function
func main() {
	// Wrap the handler with a 30-second timeout
	timeoutHandler := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(handleGateway)), 30*time.Second, "Request timed out")

	// Register the timeout handler
	http.Handle("/api/v1/ws/services/gateway", timeoutHandler)
	log.Println("WS Gateway Service is running on port 5000...")
	log.Fatal(http.ListenAndServe(":5000", nil))
}
