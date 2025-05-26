package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/YangYang-Research/whale-sentinel-services/ws-gateway-service/helper"
	"github.com/YangYang-Research/whale-sentinel-services/ws-gateway-service/logger"
	"github.com/YangYang-Research/whale-sentinel-services/ws-gateway-service/shared"
	"github.com/YangYang-Research/whale-sentinel-services/ws-gateway-service/validation"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var (
	ctx         = context.Background()
	log         *logrus.Logger
	redisClient *redis.Client
)

// Load environment variables
func init() {
	// Initialize the application logger
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.DebugLevel)

	if err := godotenv.Load(); err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error loading .env file")
	} else {
		log.Info("Loaded environment variables from .env file")
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_HOST") + ":" + os.Getenv("REDIS_PORT"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	// Check Redis connection
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error connecting to Redis")
	} else {
		log.Info("Connected to Redis")
	}
}

// handlerRedis set and get value from Redis
func handlerRedis(key string, value string) (string, error) {
	if value == "" {
		// Get value from Redis
		val, err := redisClient.Get(ctx, key).Result()
		if err != nil {
			log.WithFields(logrus.Fields{
				"msg": err,
			}).Error("Error getting value from Redis")
		}
		return val, nil
	} else {
		// Set value in Redis
		err := redisClient.Set(ctx, key, value, 0).Err()
		if err != nil {
			log.WithFields(logrus.Fields{
				"msg": err,
			}).Error("Error setting value in Redis")
		}
		return key, nil
	}
}

// handleGateway processes incoming requests
func handleGateway(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		helper.SendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req shared.GWRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.SendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := validation.ValidateGWRequest(req); err != nil {
		helper.SendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	eventInfo, eventID := helper.GenerateGWEventInfo(req)

	agentProfile, err := processAgentProfile(req.AgentID, "")
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error processing Agent Profile")
	}

	var agent shared.AgentProfileRaw

	err = json.Unmarshal([]byte(agentProfile), &agent)
	if err != nil {
		log.WithField("msg", err).Error("Failed to parse agent configuration from Redis")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	wad := agent.Profile["ws_module_web_attack_detection"].(map[string]interface{})
	dgad := agent.Profile["ws_module_dga_detection"].(map[string]interface{})
	cad := agent.Profile["ws_module_common_attack_detection"].(map[string]interface{})

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
		if wad["enable"].(bool) {
			webAttackDetectionScore, webAttackDetectionErr = processWebAttackDetection(req, eventInfo, wad)
		} else {
			webAttackDetectionScore = 0
		}
	}()

	go func() {
		defer wg.Done()
		if cad["enable"].(bool) {
			crossSiteScriptingDetection, sqlInjectionDetection, httpVerbTamperingDetection, httpLargeRequestDetection, commonAttackDetectionErr = processCommonAttackDetection(req, eventInfo, cad)
		}
	}()

	go func() {
		defer wg.Done()
		if dgad["enable"].(bool) {
			DGADetectionScore, dgaDetectionErr = processDGADetection(req, eventInfo, dgad)
		} else {
			DGADetectionScore = 0
		}
	}()

	wg.Wait()

	if webAttackDetectionErr != nil {
		log.WithFields(logrus.Fields{
			"msg": webAttackDetectionErr,
		}).Error("Error processing Web Attack Detection")
	}

	if commonAttackDetectionErr != nil {
		log.WithFields(logrus.Fields{
			"msg": commonAttackDetectionErr,
		}).Error("Error processing Common Attack Detection")
	}

	if dgaDetectionErr != nil {
		log.WithFields(logrus.Fields{
			"msg": dgaDetectionErr,
		}).Error("Error processing DGA Detection")
	}

	mapData := shared.GWResponseData{
		WebAttackDetectionScore: webAttackDetectionScore,
		DGADetectionScore:       DGADetectionScore,
		CommonAttackDetection: map[string]bool{
			"cross_site_scripting_detection": crossSiteScriptingDetection,
			"sql_injection_detection":        sqlInjectionDetection,
			"http_verb_tampering_detection":  httpVerbTamperingDetection,
			"http_large_request_detection":   httpLargeRequestDetection,
		},
	}

	response := shared.GWResponseBody{
		Status:             "success",
		Message:            "Request processed successfully",
		Data:               mapData,
		EventInfo:          eventInfo,
		RequestCreatedAt:   req.RequestCreatedAt,
		RequestProcessedAt: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	// Log the request to the logg collector
	go func(agentID string, eventInfo string, rawRequest string) {
		// Log the request to the log collector
		logData := map[string]interface{}{
			"name":                 "ws-gateway-service",
			"agent_id":             agentID,
			"agent_running_mode":   agent.Profile["running_mode"].(string),
			"source":               agentID,
			"destination":          "ws-gateway-service",
			"event_info":           eventInfo,
			"event_id":             eventID,
			"type":                 "AGENT_EVENT",
			"request_created_at":   req.RequestCreatedAt,
			"request_processed_at": time.Now().Format(time.RFC3339),
			"title":                "Received request from agent",
			"raw_request":          rawRequest,
			"timestamp":            time.Now().Format(time.RFC3339),
		}

		logger.Log("INFO", "ws-gateway-service", logData)
	}(req.AgentID, eventInfo, (req.GWPayload.GWData.HTTPRequest.QueryParams + req.GWPayload.GWData.HTTPRequest.Body))
}

// HandleAgentProfile processes incoming requests for agent profile
func HandleAgentProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		helper.SendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req shared.APRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.SendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := validation.ValidateACRequest(req); err != nil {
		helper.SendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	eventInfo, eventID := helper.GenerateACEventInfo(req)

	agentProfile, err := processAgentProfile(req.AgentID, "")
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error processing Agent Configuration")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	var agent shared.AgentProfileRaw

	err = json.Unmarshal([]byte(agentProfile), &agent)
	if err != nil {
		log.WithField("msg", err).Error("Failed to parse agent configuration from Redis")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	wad := agent.Profile["ws_module_web_attack_detection"].(map[string]interface{})
	dgad := agent.Profile["ws_module_dga_detection"].(map[string]interface{})
	cad := agent.Profile["ws_module_common_attack_detection"].(map[string]interface{})
	srh := agent.Profile["secure_response_headers"].(map[string]interface{})

	mapData := shared.AgentProfile{
		RunningMode:                   agent.Profile["running_mode"].(string),
		LastRunMode:                   agent.Profile["last_run_mode"].(string),
		LiteModeDataIsSynchronized:    agent.Profile["lite_mode_data_is_synchronized"].(bool),
		LiteModeDataSynchronizeStatus: agent.Profile["lite_mode_data_synchronize_status"].(string),
		WebAttackDetection: shared.WebAttackDetectionConfig{
			Enable:       wad["enable"].(bool),
			DetectHeader: wad["detect_header"].(bool),
			Threshold:    int(wad["threshold"].(float64)),
		},
		DGADetection: shared.DGADetectionConfig{
			Enable:    dgad["enable"].(bool),
			Threshold: int(dgad["threshold"].(float64)),
		},
		CommonAttackDetection: shared.CommonAttackDetectionConfig{
			Enable:                   cad["enable"].(bool),
			DetectCrossSiteScripting: cad["detect_cross_site_scripting"].(bool),
			DetectSqlInjection:       cad["detect_sql_injection"].(bool),
			DetectHTTPVerbTampering:  cad["detect_http_verb_tampering"].(bool),
			DetectHTTPLargeRequest:   cad["detect_http_large_request"].(bool),
		},
		SecureResponseHeaders: shared.SecureResponseHeaderConfig{
			Enable:        srh["enable"].(bool),
			SecureHeaders: srh["headers"].(map[string]interface{}),
		},
	}

	response := shared.APResponseBody{
		Status:             "success",
		Message:            "Request processed successfully",
		Profile:            mapData,
		EventInfo:          eventInfo,
		RequestCreatedAt:   req.RequestCreatedAt,
		RequestProcessedAt: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	// Log the request to the logg collector
	go func(agentID string, eventInfo string, rawRequest string) {
		// Log the request to the log collector
		logData := map[string]interface{}{
			"name":                 "ws-gateway-service",
			"agent_id":             agentID,
			"agent_running_mode":   agent.Profile["running_mode"].(string),
			"source":               agentID,
			"destination":          "ws-gateway-service",
			"event_info":           eventInfo,
			"event_id":             eventID,
			"type":                 "AGENT_EVENT",
			"request_created_at":   req.RequestCreatedAt,
			"request_processed_at": time.Now().Format(time.RFC3339),
			"title":                "Received request from agent",
			"raw_request":          rawRequest,
			"timestamp":            time.Now().Format(time.RFC3339),
		}

		logger.Log("INFO", "ws-gateway-service", logData)
	}(req.AgentID, eventInfo, (req.AgentID))
}

// HandleAgentSynchronize processes incoming requests for agent synchronization
func HandleAgentSynchronize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		helper.SendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req shared.ASRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.SendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := validation.ValidateASRequest(req); err != nil {
		helper.SendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	eventInfo, eventID := helper.GenerateASEventInfo(req)

	agentProfileStr, err := processAgentProfile(req.AgentID, "")
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error processing Agent Configuration")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	var agentProfile map[string]map[string]interface{}
	json.Unmarshal([]byte(agentProfileStr), &agentProfile)

	requestPayload := req.ASPayload
	profile := agentProfile["profile"]

	for k, v := range requestPayload {
		if _, exists := profile[k]; exists {
			profile[k] = v
		}
	}

	updatedJson, err := json.Marshal(agentProfile)
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error marshalling updated agent profile")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	updateProfifle, err := processAgentProfile(req.AgentID, string(updatedJson))
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error updating Agent Profile")
		http.Error(w, "Whale Sentinel - Internal Server Error", http.StatusInternalServerError)
		return
	}

	response := shared.ASResponseBody{
		Status:             "success",
		Message:            "Request processed successfully",
		Profile:            updateProfifle,
		EventInfo:          eventInfo,
		RequestCreatedAt:   req.RequestCreatedAt,
		RequestProcessedAt: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	// Log the request to the logg collector
	go func(agentID string, eventInfo string, rawRequest string) {
		// Log the request to the log collector
		logData := map[string]interface{}{
			"name":                 "ws-gateway-service",
			"agent_id":             agentID,
			"agent_running_mode":   profile["running_mode"].(string),
			"source":               agentID,
			"destination":          "ws-gateway-service",
			"event_info":           eventInfo,
			"event_id":             eventID,
			"type":                 "AGENT_EVENT",
			"request_created_at":   req.RequestCreatedAt,
			"request_processed_at": time.Now().Format(time.RFC3339),
			"title":                "Received request from agent",
			"raw_request":          rawRequest,
			"timestamp":            time.Now().Format(time.RFC3339),
		}

		logger.Log("INFO", "ws-gateway-service", logData)
	}(req.AgentID, eventInfo, (req.AgentID))
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
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %v", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func processWebAttackDetection(req shared.GWRequestBody, eventInfo string, wad map[string]interface{}) (float64, error) {
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processing Web Attack Detection")

	httpRequest := req.GWPayload.GWData.HTTPRequest
	var concatenatedData string
	if wad["detect_header"].(bool) {
		concatenatedData = fmt.Sprintf("%s %s \n Host: %s \n User-Agent: %s \n Content-Type: %s \n Content-Length: %d \n\n %s%s",
			httpRequest.Method, httpRequest.URL, httpRequest.Host, httpRequest.Headers.UserAgent, httpRequest.Headers.ContentType, httpRequest.Headers.ContentLength, httpRequest.QueryParams, httpRequest.Body)
	} else {
		concatenatedData = fmt.Sprintf("%s %s",
			httpRequest.QueryParams,
			httpRequest.Body)
	}

	requestBody := map[string]interface{}{
		"event_info":         eventInfo,
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
	log.WithFields(logrus.Fields{
		"msg": "Event ID: " + eventInfo,
	}).Debug("Processed Web Attack Detection")

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

func processCommonAttackDetection(req shared.GWRequestBody, eventInfo string, _ map[string]interface{}) (bool, bool, bool, bool, error) {
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processing Common Attack Detection")

	requestBody := map[string]interface{}{
		"agent_id":   req.AgentID,
		"event_info": eventInfo,
		"payload": map[string]interface{}{
			"data": map[string]interface{}{
				"client_information": map[string]interface{}{
					"ip":              req.GWPayload.GWData.ClientInformation.IP,
					"device_type":     req.GWPayload.GWData.ClientInformation.DeviceType,
					"network_type":    req.GWPayload.GWData.ClientInformation.NetworkType,
					"platform":        req.GWPayload.GWData.ClientInformation.Platform,
					"browser":         req.GWPayload.GWData.ClientInformation.Browser,
					"browser_version": req.GWPayload.GWData.ClientInformation.BrowserVersion,
				},
				"http_request": map[string]interface{}{
					"method": req.GWPayload.GWData.HTTPRequest.Method,
					"url":    req.GWPayload.GWData.HTTPRequest.URL,
					"host":   req.GWPayload.GWData.HTTPRequest.Host,
					"headers": map[string]interface{}{
						"user-agent":     req.GWPayload.GWData.HTTPRequest.Headers.UserAgent,
						"content-type":   req.GWPayload.GWData.HTTPRequest.Headers.ContentType,
						"content-length": req.GWPayload.GWData.HTTPRequest.Headers.ContentLength,
						"referer":        req.GWPayload.GWData.HTTPRequest.Headers.Referer,
					},
					"query_parameters": req.GWPayload.GWData.HTTPRequest.QueryParams,
					"body":             req.GWPayload.GWData.HTTPRequest.Body,
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
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processed Common Attack Detection")

	data := response["data"].(map[string]interface{})
	return data["cross_site_scripting_detection"].(bool),
		data["sql_injection_detection"].(bool),
		data["http_verb_tampering_detection"].(bool),
		data["http_large_request_detection"].(bool),
		nil
}

func processDGADetection(req shared.GWRequestBody, eventInfo string, _ map[string]interface{}) (float64, error) {
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processing DGA Detection")

	refererURL := req.GWPayload.GWData.HTTPRequest.Headers.Referer

	domain, err := helper.GetDomain(refererURL)
	if err != nil {
		return 0, err
	}

	RequestBody := map[string]string{
		"event_info":         eventInfo,
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
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processed DGA Detection")

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

func processAgentProfile(agentId string, agentValue string) (string, error) {
	agentProfile, err := handlerRedis(agentId, agentValue)
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error getting value from Redis")
	}

	// 2. If not found in cache or failed to parse → call ws-configuration
	if agentProfile == "" {

	}

	// // 3. Store result into Redis

	return agentProfile, nil

}

// getAPIKey retrieves the API key based on the configuration
func getAPIKey() (string, error) {
	awsRegion := os.Getenv("AWS_REGION")
	awsSecretName := os.Getenv("AWS_SECRET_NAME")
	awsAPISecretKeyName := os.Getenv("AWS_API_SECRET_KEY_NAME")

	awsAPIKeyVaule, err := helper.GetAWSSecret(awsRegion, awsSecretName, awsAPISecretKeyName)

	return awsAPIKeyVaule, err
}

// apiKeyAuthMiddleware is a middleware that handles API Key authentication
func apiKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey, err := getAPIKey()
		if err != nil {
			helper.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			helper.SendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Decode the Base64-encoded Authorization header
		authHeader = authHeader[len("Basic "):]
		decodedAuthHeader, err := base64.StdEncoding.DecodeString(authHeader)
		if err != nil {
			helper.SendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		expectedAuthValue := fmt.Sprintf("ws-agent:%s", apiKey)
		if string(decodedAuthHeader) != expectedAuthValue {
			helper.SendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Main function
func main() {
	log.Info("WS Gateway Service is running on port 5000...")
	// Initialize the logger
	logMaxSize, _ := strconv.Atoi(os.Getenv("LOG_MAX_SIZE"))
	logMaxBackups, _ := strconv.Atoi(os.Getenv("LOG_MAX_BACKUPS"))
	logMaxAge, _ := strconv.Atoi(os.Getenv("LOG_MAX_AGE"))
	logCompression, _ := strconv.ParseBool(os.Getenv("LOG_COMPRESSION"))
	logger.SetupWSLogger("ws-gateway-service", logMaxSize, logMaxBackups, logMaxAge, logCompression)
	// Wrap the handler with a 30-second timeout
	timeoutHandlerGW := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(handleGateway)), 30*time.Second, "Request timed out")
	timeOutHandlerAP := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(HandleAgentProfile)), 30*time.Second, "Request timed out")
	timeOutHandlerAS := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(HandleAgentSynchronize)), 30*time.Second, "Request timed out")
	// Register the timeout handler
	http.Handle("/api/v1/ws/services/gateway", timeoutHandlerGW)
	http.Handle("/api/v1/ws/services/gateway/agent-profile", timeOutHandlerAP)
	http.Handle("/api/v1/ws/services/gateway/agent-synchronize", timeOutHandlerAS)
	log.Fatal(http.ListenAndServe(":5000", nil))
}
