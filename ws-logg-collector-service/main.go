package main

import (
	"context"
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
	"github.com/elastic/go-elasticsearch"
)

type (
	LogEntry struct {
		Timestamp        string `json:"timestamp"`
		AgentID          string `json:"agent_id"`
		Level            string `json:"level"`
		Source           string `json:"source"`
		Destination      string `json:"destination"`
		EventID          string `json:"event_id"`
		RequestCreatedAt string `json:"request_created_at"`
		Message          string `json:"message"`
	}

	ErrorResponse struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		ErrorCode int    `json:"error_code"`
	}
)

type customHeaderTransport struct {
	Authorization string
	Transport     http.RoundTripper
}

func (t *customHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", t.Authorization)
	return t.Transport.RoundTrip(req)
}

var esClient *elasticsearch.Client

func initElasticsearch() {
	cfg := elasticsearch.Config{
		Addresses: []string{
			os.Getenv("OPENSEARCH_ENDPOINT"),
		},
		Transport: &customHeaderTransport{
			Authorization: "ApiKey " + os.Getenv("OPENSEARCH_API_KEY"),
			Transport:     http.DefaultTransport,
		},
	}

	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("Error creating the OpenSearch client: %s", err)
	}
	esClient = client
	log.Println("Connected to OpenSearch")
}

func logHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var entry LogEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		sendErrorResponse(w, "Invalid log format", http.StatusBadRequest)
		return
	}

	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().Format(time.RFC3339)
	}

	docBytes, err := json.Marshal(entry)
	if err != nil {
		sendErrorResponse(w, "Failed to serialize log", http.StatusInternalServerError)
		return
	}

	log.Printf("Received log entry: %s", docBytes)
	// indexName := "ws-gateway-logs-" + time.Now().Format("2006.01.02")
	// res, err := esClient.Index(
	// 	indexName,
	// 	bytes.NewReader(docBytes),
	// 	esClient.Index.WithContext(context.Background()),
	// )
	// if err != nil {
	// 	log.Printf("Failed to index log: %v", err)
	// 	http.Error(w, "Failed to send log", http.StatusInternalServerError)
	// 	return
	// }
	// defer res.Body.Close()

	// w.WriteHeader(http.StatusOK)
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

func main() {
	initElasticsearch()
	// Wrap the handler with a 30-second timeout
	timeoutHandler := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(logHandler)), 30*time.Second, "Request timed out")

	// Register the timeout handler
	http.Handle("/api/v1/logg-collector", timeoutHandler)
	log.Printf("WS Logg Service running on port 5555...")
	log.Fatal(http.ListenAndServe(":5555", nil))
}
