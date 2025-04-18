package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/opensearch-project/opensearch-go"
)

type (
	WSGate_LogEntry struct {
		Name             string `json:"name"`
		AgentID          string `json:"agent_id"`
		Source           string `json:"source"`
		Destination      string `json:"destination"`
		EventID          string `json:"event_id"`
		Level            string `json:"level"`
		Type             string `json:"type"`
		RequestCreatedAt string `json:"request_created_at"`
		Message          string `json:"message"`
		Timestamp        string `json:"timestamp"`
	}

	WSCommonAttack_LogEntry struct {
		Name                  string                    `json:"name"`
		AgentID               string                    `json:"agent_id"`
		Source                string                    `json:"source"`
		Destination           string                    `json:"destination"`
		EventID               string                    `json:"event_id"`
		Level                 string                    `json:"level"`
		Type                  string                    `json:"type"`
		CommonAttackDetection CommonAttackDetectionRule `json:"common_attack_detection"`
		RequestCreatedAt      string                    `json:"request_created_at"`
		Message               string                    `json:"message"`
		Timestamp             string                    `json:"timestamp"`
	}

	CommonAttackDetectionRule struct {
		CrossSiteScripting string `json:"cross_site_scripting"`
		LargeRequest       string `json:"large_request"`
		SqlInjection       string `json:"sql_injection"`
		HTTPVerbTampering  string `json:"http_verb_tampering"`
		HTTPLargeRequest   string `json:"http_large_request"`
	}

	WSDGA_LogEntry struct {
		Name             string `json:"name"`
		AgentID          string `json:"agent_id"`
		Source           string `json:"source"`
		Destination      string `json:"destination"`
		EventID          string `json:"event_id"`
		Level            string `json:"level"`
		Type             string `json:"type"`
		Score            string `json:"score"`
		RequestCreatedAt string `json:"request_created_at"`
		Message          string `json:"message"`
		Timestamp        string `json:"timestamp"`
	}

	WSWebAttack_LogEntry struct {
		Name             string `json:"name"`
		AgentID          string `json:"agent_id"`
		Source           string `json:"source"`
		Destination      string `json:"destination"`
		EventID          string `json:"event_id"`
		Level            string `json:"level"`
		Type             string `json:"type"`
		Score            string `json:"score"`
		RequestCreatedAt string `json:"request_created_at"`
		Message          string `json:"message"`
		Timestamp        string `json:"timestamp"`
	}

	ErrorResponse struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		ErrorCode int    `json:"error_code"`
	}
)

var osClient *opensearch.Client

func initOpensearch() {
	username := os.Getenv("OPENSEARCH_USERNAME")
	password := os.Getenv("OPENSEARCH_PASSWORD")

	cfg := opensearch.Config{
		Addresses: []string{
			os.Getenv("OPENSEARCH_ENDPOINT"),
		},
		Username: username,
		Password: password,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	client, err := opensearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("Error creating the OpenSearch client: %s", err)
	}
	osClient = client
	log.Println("Connected to OpenSearch (via opensearch-go)")
}

func logHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse the incoming body into a generic map to detect type
	var generic map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&generic); err != nil {
		sendErrorResponse(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Get `name` to determine the index
	name, ok := generic["name"].(string)
	if !ok || name == "" {
		sendErrorResponse(w, "`name` field is required to determine log type", http.StatusBadRequest)
		return
	}

	// Add missing timestamp if not provided
	if _, ok := generic["timestamp"]; !ok {
		generic["timestamp"] = time.Now().Format(time.RFC3339)
	}

	// Marshal back to JSON
	docBytes, err := json.Marshal(generic)
	if err != nil {
		sendErrorResponse(w, "Failed to serialize log", http.StatusInternalServerError)
		return
	}

	log.Printf("Received log entry: %s", docBytes)

	indexName := getIndexName(name)
	if indexName == "" {
		sendErrorResponse(w, "Unknown log name", http.StatusBadRequest)
		return
	}

	if err := indexLog(indexName, docBytes); err != nil {
		log.Printf("Failed to index log: %v", err)
		sendErrorResponse(w, "Failed to index log", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Helper function to determine the index name based on the destination
func getIndexName(name string) string {
	dateSuffix := time.Now().Format("2006.01.02")
	switch name {
	case "ws-gateway-service":
		return "ws-gateway-logs-" + dateSuffix
	case "ws-web-attack-detection":
		return "ws-web-attack-detection-logs-" + dateSuffix
	case "ws-dga-detection":
		return "ws-dga-detection-logs-" + dateSuffix
	case "ws-common-attack-detection":
		return "ws-common-attack-detection-logs-" + dateSuffix
	default:
		log.Printf("Unknown name: %s", name)
		return ""
	}
}

// Helper function to index a log entry in OpenSearch
func indexLog(indexName string, docBytes []byte) error {
	res, err := osClient.Index(
		indexName,
		bytes.NewReader(docBytes),
		osClient.Index.WithContext(context.Background()),
	)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error indexing document: %s", res.String())
	}
	return nil
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

	svc := secretsmanager.NewFromConfig(config)
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(awsAPIKeyName),
		VersionStage: aws.String("AWSCURRENT"),
	}

	result, err := svc.GetSecretValue(context.TODO(), input)
	if err != nil {
		log.Fatal(err.Error())
	}

	var secretString string = *result.SecretString

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
	initOpensearch()
	timeoutHandler := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(logHandler)), 30*time.Second, "Request timed out")
	http.Handle("/api/v1/logg-collector", timeoutHandler)
	log.Printf("WS Logg Service running on port 5555...")
	log.Fatal(http.ListenAndServe(":5555", nil))
}
