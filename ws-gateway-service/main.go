package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/YangYang-Research/whale-sentinel-services/ws-gateway-service/wshelper"
	"github.com/YangYang-Research/whale-sentinel-services/ws-gateway-service/wslogger"
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

// Structs for request and response
type (
	GWRequestBody struct {
		AgentID          string  `json:"agent_id"`
		Payload          Payload `json:"payload"`
		RequestCreatedAt string  `json:"request_created_at"`
	}

	Payload struct {
		Data Data `json:"data"`
	}

	Data struct {
		ClientInformation ClientInformation `json:"client_information"`
		HTTPRequest       HTTPRequest       `json:"http_request"`
	}

	ClientInformation struct {
		IP             string `json:"ip"`
		DeviceType     string `json:"device_type"`
		NetworkType    string `json:"network_type"`
		Platform       string `json:"platform"`
		Browser        string `json:"browser"`
		BrowserVersion string `json:"browser_version"`
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

	ACRequestBody struct {
		AgentID          string `json:"agent_id"`
		RequestCreatedAt string `json:"request_created_at"`
	}

	AgentConfigurationRaw struct {
		Rules map[string]interface{} `json:"rules"`
	}

	GWResponseBody struct {
		Status             string         `json:"status"`
		Message            string         `json:"message"`
		Data               GWResponseData `json:"data"`
		EventInfo          string         `json:"event_info"`
		RequestCreatedAt   string         `json:"request_created_at"`
		RequestProcessedAt string         `json:"request_processed_at"`
	}

	GWResponseData struct {
		WebAttackDetectionScore float64         `json:"ws_module_web_attack_detection_score"`
		DGADetectionScore       float64         `json:"ws_module_dga_detection_score"`
		CommonAttackDetection   map[string]bool `json:"ws_module_common_attack_detection"`
	}

	ACResponseBody struct {
		Status             string              `json:"status"`
		Message            string              `json:"message"`
		Configurations     AgentConfigurations `json:"configurations"`
		EventInfo          string              `json:"event_info"`
		RequestCreatedAt   string              `json:"request_created_at"`
		RequestProcessedAt string              `json:"request_processed_at"`
	}

	AgentConfigurations struct {
		RunningMode                   string                      `json:"running_mode"`
		LastRunMode                   string                      `json:"last_run_mode"`
		LiteModeDataIsSynchronized    bool                        `json:"lite_mode_data_is_synchronized"`
		LiteModeDataSynchronizeStatus string                      `json:"lite_mode_data_synchronize_status"`
		WebAttackDetection            WebAttackDetectionConfig    `json:"ws_module_web_attack_detection"`
		DGADetection                  DGADetectionConfig          `json:"ws_module_dga_detection"`
		CommonAttackDetection         CommonAttackDetectionConfig `json:"ws_module_common_attack_detection"`
	}

	WebAttackDetectionConfig struct {
		Enable       bool `json:"enable"`
		DetectHeader bool `json:"detect_header"`
	}

	DGADetectionConfig struct {
		Enable bool `json:"enable"`
	}

	CommonAttackDetectionConfig struct {
		Enable                   bool `json:"enable"`
		DetectCrossSiteScripting bool `json:"detect_cross_site_scripting"`
		DetectSqlInjection       bool `json:"detect_sql_injection"`
		DetectHTTPVerbTampering  bool `json:"detect_http_verb_tampering"`
		DetectHTTPLargeRequest   bool `json:"detect_http_large_request"`
	}

	ErrorResponse struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		ErrorCode int    `json:"error_code"`
	}
)

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
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req GWRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := validateGWRequest(req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	eventInfo, eventID := generateGWEventInfo(req)

	agentConfiguration, err := processAgentConfiguration(req.AgentID)
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error processing Agent Configuration")
	}

	var agentConfig AgentConfigurationRaw

	err = json.Unmarshal([]byte(agentConfiguration), &agentConfig)
	if err != nil {
		log.WithField("msg", err).Error("Failed to parse agent configuration from Redis")
		return
	}

	wad := agentConfig.Rules["ws_module_web_attack_detection"].(map[string]interface{})
	dgad := agentConfig.Rules["ws_module_dga_detection"].(map[string]interface{})
	cad := agentConfig.Rules["ws_module_common_attack_detection"].(map[string]interface{})

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

	if agentConfig.Rules["running_mode"].(string) == "monitor" || agentConfig.Rules["running_mode"].(string) == "lite" {
		response := GWResponseBody{
			Status:             "success",
			Message:            "Request processed successfully",
			Data:               GWResponseData{},
			EventInfo:          eventInfo,
			RequestCreatedAt:   req.RequestCreatedAt,
			RequestProcessedAt: time.Now().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}

	if agentConfig.Rules["running_mode"].(string) == "protection" {
		mapData := GWResponseData{
			WebAttackDetectionScore: webAttackDetectionScore,
			DGADetectionScore:       DGADetectionScore,
			CommonAttackDetection: map[string]bool{
				"cross_site_scripting_detection": crossSiteScriptingDetection,
				"sql_injection_detection":        sqlInjectionDetection,
				"http_verb_tampering_detection":  httpVerbTamperingDetection,
				"http_large_request_detection":   httpLargeRequestDetection,
			},
		}

		response := GWResponseBody{
			Status:             "success",
			Message:            "Request processed successfully",
			Data:               mapData,
			EventInfo:          eventInfo,
			RequestCreatedAt:   req.RequestCreatedAt,
			RequestProcessedAt: time.Now().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}

	// Log the request to the logg collector
	go func(agentID string, eventInfo string, rawRequest string) {
		// Log the request to the log collector
		logData := map[string]interface{}{
			"name":                 "ws-gateway-service",
			"agent_id":             agentID,
			"agent_running_mode":   agentConfig.Rules["running_mode"].(string),
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

		wslogger.Log("INFO", "ws-gateway-service", logData)
	}(req.AgentID, eventInfo, (req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body))
}

// HandleAgentConfiguration processes incoming requests for agent rules
func HandleAgentConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var req ACRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := validateACRequest(req); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	eventInfo, eventID := generateACEventInfo(req)

	agentConfiguration, err := processAgentConfiguration(req.AgentID)
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error processing Agent Configuration")
	}

	var agentConfig AgentConfigurationRaw

	err = json.Unmarshal([]byte(agentConfiguration), &agentConfig)
	if err != nil {
		log.WithField("msg", err).Error("Failed to parse agent configuration from Redis")
		return
	}

	wad := agentConfig.Rules["ws_module_web_attack_detection"].(map[string]interface{})
	dgad := agentConfig.Rules["ws_module_dga_detection"].(map[string]interface{})
	cad := agentConfig.Rules["ws_module_common_attack_detection"].(map[string]interface{})

	mapData := AgentConfigurations{
		RunningMode:                   agentConfig.Rules["running_mode"].(string),
		LastRunMode:                   agentConfig.Rules["last_run_mode"].(string),
		LiteModeDataIsSynchronized:    agentConfig.Rules["lite_mode_data_is_synchronized"].(bool),
		LiteModeDataSynchronizeStatus: agentConfig.Rules["lite_mode_data_synchronize_status"].(string),
		WebAttackDetection: WebAttackDetectionConfig{
			Enable:       wad["enable"].(bool),
			DetectHeader: wad["detect_header"].(bool),
		},
		DGADetection: DGADetectionConfig{
			Enable: dgad["enable"].(bool),
		},
		CommonAttackDetection: CommonAttackDetectionConfig{
			Enable:                   cad["enable"].(bool),
			DetectCrossSiteScripting: cad["detect_cross_site_scripting"].(bool),
			DetectSqlInjection:       cad["detect_sql_injection"].(bool),
			DetectHTTPVerbTampering:  cad["detect_http_verb_tampering"].(bool),
			DetectHTTPLargeRequest:   cad["detect_http_large_request"].(bool),
		},
	}

	response := ACResponseBody{
		Status:             "success",
		Message:            "Request processed successfully",
		Configurations:     mapData,
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
			"agent_running_mode":   agentConfig.Rules["running_mode"].(string),
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

		wslogger.Log("INFO", "ws-gateway-service", logData)
	}(req.AgentID, eventInfo, (req.AgentID))
}

// Helper functions
func validateGWRequest(req GWRequestBody) error {
	if req.Payload.Data.ClientInformation.IP == "" || req.Payload.Data.HTTPRequest.Method == "" || req.Payload.Data.HTTPRequest.URL == "" || req.Payload.Data.HTTPRequest.Headers.UserAgent == "" || req.Payload.Data.HTTPRequest.Headers.ContentType == "" {
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

func validateACRequest(req ACRequestBody) error {
	if req.AgentID == "" {
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

func generateGWEventInfo(req GWRequestBody) (string, string) {
	hashInput := req.RequestCreatedAt + req.Payload.Data.ClientInformation.IP + req.Payload.Data.ClientInformation.DeviceType + req.Payload.Data.HTTPRequest.Method + req.Payload.Data.HTTPRequest.Host + req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
	eventID := sha256.Sum256([]byte(hashInput))
	eventInfo := req.AgentID + "|" + "WS_GATEWAY_SERVICE" + "|" + hex.EncodeToString(eventID[:])
	return eventInfo, hex.EncodeToString(eventID[:])
}

func generateACEventInfo(req ACRequestBody) (string, string) {
	hashInput := req.RequestCreatedAt + req.AgentID
	eventID := sha256.Sum256([]byte(hashInput))
	eventInfo := req.AgentID + "|" + "WS_GATEWAY_SERVICE" + "|" + hex.EncodeToString(eventID[:])
	return eventInfo, hex.EncodeToString(eventID[:])
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

func processWebAttackDetection(req GWRequestBody, eventInfo string, wad map[string]interface{}) (float64, error) {
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processing Web Attack Detection")

	httpRequest := req.Payload.Data.HTTPRequest
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

func processCommonAttackDetection(req GWRequestBody, eventInfo string, cad map[string]interface{}) (bool, bool, bool, bool, error) {
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processing Common Attack Detection")

	requestBody := map[string]interface{}{
		"agent_id":   req.AgentID,
		"event_info": eventInfo,
		"payload": map[string]interface{}{
			"data": map[string]interface{}{
				"client_information": map[string]interface{}{
					"ip":              req.Payload.Data.ClientInformation.IP,
					"device_type":     req.Payload.Data.ClientInformation.DeviceType,
					"network_type":    req.Payload.Data.ClientInformation.NetworkType,
					"platform":        req.Payload.Data.ClientInformation.Platform,
					"browser":         req.Payload.Data.ClientInformation.Browser,
					"browser_version": req.Payload.Data.ClientInformation.BrowserVersion,
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

func getDomain(fullUrl string) (string, error) {
	parsedUrl, err := url.Parse(fullUrl)
	if err != nil {
		return "", err
	}
	return parsedUrl.Host, nil
}

func processDGADetection(req GWRequestBody, eventInfo string, dgad map[string]interface{}) (float64, error) {
	log.WithFields(logrus.Fields{
		"msg": "Event Info: " + eventInfo,
	}).Debug("Processing DGA Detection")

	refererURL := req.Payload.Data.HTTPRequest.Headers.Referer

	domain, err := getDomain(refererURL)
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

func processAgentConfiguration(agentId string) (string, error) {
	fmt.Println("Agent ID:", agentId)
	agentConfiguration, err := handlerRedis(agentId, "")
	if err != nil {
		log.WithFields(logrus.Fields{
			"msg": err,
		}).Error("Error getting value from Redis")
	}

	// 2. If not found in cache or failed to parse → call ws-configuration
	if agentConfiguration == "" {

	}

	// // 3. Store result into Redis

	return agentConfiguration, nil

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
	awsSecretName := os.Getenv("AWS_SECRET_NAME")
	awsAPISecretKeyName := os.Getenv("AWS_API_SECRET_KEY_NAME")

	awsAPIKeyVaule, err := wshelper.GetAWSSecret(awsRegion, awsSecretName, awsAPISecretKeyName)

	return awsAPIKeyVaule, err
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

		expectedAuthValue := fmt.Sprintf("ws-agent:%s", apiKey)
		if string(decodedAuthHeader) != expectedAuthValue {
			sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Main function
func main() {
	log.Info("WS Gateway Service is running on port 5000...")
	// Initialize the wslogger
	logMaxSize, _ := strconv.Atoi(os.Getenv("LOG_MAX_SIZE"))
	logMaxBackups, _ := strconv.Atoi(os.Getenv("LOG_MAX_BACKUPS"))
	logMaxAge, _ := strconv.Atoi(os.Getenv("LOG_MAX_AGE"))
	logCompression, _ := strconv.ParseBool(os.Getenv("LOG_COMPRESSION"))
	wslogger.SetupWSLogger("ws-gateway-service", logMaxSize, logMaxBackups, logMaxAge, logCompression)
	// Wrap the handler with a 30-second timeout
	timeoutHandlerGW := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(handleGateway)), 30*time.Second, "Request timed out")
	timeOutHandlerAC := http.TimeoutHandler(apiKeyAuthMiddleware(http.HandlerFunc(HandleAgentConfiguration)), 30*time.Second, "Request timed out")

	// Register the timeout handler
	http.Handle("/api/v1/ws/services/gateway", timeoutHandlerGW)
	http.Handle("/api/v1/ws/services/gateway/agent-configuration", timeOutHandlerAC)
	log.Fatal(http.ListenAndServe(":5000", nil))
}
