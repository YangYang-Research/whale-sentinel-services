package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go/aws"
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
	EventID          string  `json:"event_id"`
	Rules            Rules   `json:"rules"`
	Payload          Payload `json:"payload"`
	RequestCreatedAt string  `json:"request_created_at"`
}

// Rule defines the structure of the rule field in the request body
type Rules struct {
	DetectCrossSiteScripting string `json:"detect_cross_site_scripting"`
	DetectLargeRequest       string `json:"detect_large_request"`
	DetectSqlInjection       string `json:"detect_sql_injection"`
	DetectHTTPVerbTampering  string `json:"detect_http_verb_tampering"`
	DetectHTTPLargeRequest   string `json:"detect_http_large_request"`
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
	Headers     HTTPRequestHeader `json:"headers"`
	QueryParams string            `json:"query_parameters"`
	Body        string            `json:"body"`
}

// HTTPRequestHeader defines the structure of the HTTP request headers
type HTTPRequestHeader struct {
	UserAgent     string `json:"user-agent"`
	ContentType   string `json:"content-type"`
	ContentLength int    `json:"content-length"`
	Referer       string `json:"referer"`
}

// ResponseBody defines the structure of the response payload
type ResponseBody struct {
	Status             string       `json:"status"`
	Message            string       `json:"message"`
	Data               ResponseData `json:"data"`
	EventID            string       `json:"event_id"`
	RequestCreatedAt   string       `json:"request_created_at"`
	RequestProcessedAt string       `json:"request_processed_at"`
}

type ResponseData struct {
	CrossSiteScriptingDetection bool `json:"cross_site_scripting_detection"`
	SQLInjectionDetection       bool `json:"sql_injection_detection"`
	HTTPVerbTamperingDetection  bool `json:"http_verb_tampering_detection"`
	HTTPLargeRequestDetection   bool `json:"http_large_request_detection"`
}

// ErrorResponse defines the structure of the error response payload
type ErrorResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	ErrorCode int    `json:"error_code"`
}

// extractEventID extracts the components of the event_id string.
func extractEventID(eventID string) (string, string, string, error) {
	// Split the event_id by the "|" delimiter
	parts := strings.Split(eventID, "|")

	// Ensure the split result has exactly 3 parts
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid event_id format: %s", eventID)
	}

	// Return the extracted components
	return parts[0], parts[1], parts[2], nil
}

// wsHandleDecoder decodes the input string
func wsHandleDecoder(input string) (string, error) {

	// Clean and decode the string
	cleanedString := strings.NewReplacer(`\\`, ``, `\%`, `%`, `<br/>`, ``).Replace(input)
	decodedString, err := url.QueryUnescape(cleanedString)
	if err != nil {
		return "", fmt.Errorf("failed to unescape string: %v", err)
	}
	decodedString = html.UnescapeString(decodedString)

	// Base64 decoding attempt
	base64Pattern := `( |,|;)base64,([A-Za-z0-9+/]*={0,2})`
	re := regexp.MustCompile(base64Pattern)
	matches := re.FindStringSubmatch(decodedString)
	if len(matches) > 2 {
		if decoded, err := base64.StdEncoding.DecodeString(matches[2]); err == nil {
			decodedString = strings.Replace(decodedString, matches[2], string(decoded), 1)
		}
	}

	// Convert to lowercase
	lowerString := strings.ToLower(decodedString)

	return lowerString, nil
}

func wsCrossSiteScriptingDetection(input string) (bool, error) {

	// XSS detection patterns
	xssPatterns := []string{
		`(?:https?://|//)[^\s/]+\.js`,                                                   // Detects .js files
		`((%3C)|<)((%2F)|/)*[a-z0-9%]+((%3E)|>)`,                                        // Detects <tag>
		`((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)`, // Detects <img>
		`((%3C)|<)[^\n]+((%3E)|>)`,                                                      // Detects <tag>
		`(?i)<script[^>]*>.*?</script>`,                                                 // Detects <script> tags
		`(?i)on\w+\s*=\s*["']?[^"'>]+["']?`,                                             // Detects inline event handlers like onclick=
		`(?i)javascript\s*:\s*[^"'>\s]+`,                                                // Detects javascript: in URLs
		`(?i)eval\s*\(`,                                                                 // Detects eval(
		`(?i)document\.cookie`,                                                          // Detects document.cookie
		`(?i)alert\s*\(`,                                                                // Detects alert(
		`(?i)prompt\s*\(`,                                                               // Detects prompt(
		`(?i)confirm\s*\(`,                                                              // Detects confirm(
		`(?i)onload\s*=\s*[^"'>]+`,                                                      // Detects onload=
		`(?i)onerror\s*=\s*[^"'>]+`,                                                     // Detects onerror=
		`(?i)onmouseover\s*=\s*[^"'>]+`,                                                 // Detects onmouseover=
		`(?i)onfocus\s*=\s*[^"'>]+`,                                                     // Detects onfocus=
		`(?i)onblur\s*=\s*[^"'>]+`,                                                      // Detects onblur=
		`(?i)onchange\s*=\s*[^"'>]+`,                                                    // Detects onchange=
		`(?i)onsubmit\s*=\s*[^"'>]+`,                                                    // Detects onsubmit=
		`(?i)onreset\s*=\s*[^"'>]+`,                                                     // Detects onreset=
		`(?i)onselect\s*=\s*[^"'>]+`,                                                    // Detects onselect=
		`(?i)onkeydown\s*=\s*[^"'>]+`,                                                   // Detects onkeydown=
		`(?i)onkeypress\s*=\s*[^"'>]+`,                                                  // Detects onkeypress=
		`(?i)onmousedown\s*=\s*[^"'>]+`,                                                 // Detects onmousedown=
		`(?i)onmouseup\s*=\s*[^"'>]+`,                                                   // Detects onmouseup=
		`(?i)onmousemove\s*=\s*[^"'>]+`,                                                 // Detects onmousemove=
		`(?i)onmouseout\s*=\s*[^"'>]+`,                                                  // Detects onmouseout=
		`(?i)onmouseenter\s*=\s*[^"'>]+`,                                                // Detects onmouseenter=
		`(?i)onmouseleave\s*=\s*[^"'>]+`,                                                // Detects onmouseleave=
		`(?i)oncontextmenu\s*=\s*[^"'>]+`,                                               // Detects oncontextmenu=
		`(?i)onresize\s*=\s*[^"'>]+`,                                                    // Detects onresize=
		`(?i)onscroll\s*=\s*[^"'>]+`,                                                    // Detects onscroll=
		`(?i)onwheel\s*=\s*[^"'>]+`,                                                     // Detects onwheel=
		`(?i)oncopy\s*=\s*[^"'>]+`,                                                      // Detects oncopy=
		`(?i)oncut\s*=\s*[^"'>]+`,                                                       // Detects oncut=
		`(?i)onpaste\s*=\s*[^"'>]+`,                                                     // Detects onpaste=
		`(?i)onbeforeunload\s*=\s*[^"'>]+`,                                              // Detects onbeforeunload=
		`(?i)onhashchange\s*=\s*[^"'>]+`,                                                // Detects onhashchange=
		`(?i)onmessage\s*=\s*[^"'>]+`,                                                   // Detects onmessage=
		`(?i)onoffline\s*=\s*[^"'>]+`,                                                   // Detects onoffline=
		`(?i)ononline\s*=\s*[^"'>]+`,                                                    // Detects ononline=
		`(?i)onpagehide\s*=\s*[^"'>]+`,                                                  // Detects onpagehide=
		`(?i)onpageshow\s*=\s*[^"'>]+`,                                                  // Detects onpageshow=
		`(?i)onpopstate\s*=\s*[^"'>]+`,                                                  // Detects onpopstate=
		`(?i)onstorage\s*=\s*[^"'>]+`,                                                   // Detects onstorage=
		`(?i)onunload\s*=\s*[^"'>]+`,                                                    // Detects onunload=
		`(?i)onerror\s*=\s*[^"'>]+`,                                                     // Detects onerror=
		`(?i)onhashchange\s*=\s*[^"'>]+`,                                                // Detects onhashchange=
		`(?i)onload\s*=\s*[^"'>]+`,                                                      // Detects onload=
		`(?i)onresize\s*=\s*[^"'>]+`,                                                    // Detects onresize=
		`(?i)onunload\s*=\s*[^"'>]+`,                                                    // Detects onunload=
		`(?i)onpageshow\s*=\s*[^"'>]+`,                                                  // Detects onpageshow=
		`(?i)onpagehide\s*=\s*[^"'>]+`,                                                  // Detects onpagehide=
		`(?i)onpopstate\s*=\s*[^"'>]+`,                                                  // Detects onpopstate=
		`(?i)ononline\s*=\s*[^"'>]+`,                                                    // Detects ononline=
		`(?i)onoffline\s*=\s*[^"'>]+`,                                                   // Detects onoffline=
		`(?i)onmessage\s*=\s*[^"'>]+`,                                                   // Detects onmessage=
		`(?i)onstorage\s*=\s*[^"'>]+`,                                                   // Detects onstorage=
		`(?i)onbeforeunload\s*=\s*[^"'>]+`,                                              // Detects onbeforeunload=
		`(?i)onunload\s*=\s*[^"'>]+`,                                                    // Detects onunload=
		`(?i)oninput\s*=\s*[^"'>]+`,                                                     // Detects oninput=
		`(?i)oninvalid\s*=\s*[^"'>]+`,                                                   // Detects oninvalid=
		`(?i)onsearch\s*=\s*[^"'>]+`,                                                    // Detects onsearch=
		`(?i)onkeyup\s*=\s*[^"'>]+`,                                                     // Detects onkeyup=
		`(?i)oncut\s*=\s*[^"'>]+`,                                                       // Detects oncut=
		`(?i)onpaste\s*=\s*[^"'>]+`,                                                     // Detects onpaste=
		`(?i)onabort\s*=\s*[^"'>]+`,                                                     // Detects onabort=
		`(?i)oncanplay\s*=\s*[^"'>]+`,                                                   // Detects oncanplay=
		`(?i)oncanplaythrough\s*=\s*[^"'>]+`,                                            // Detects oncanplaythrough=
		`(?i)ondurationchange\s*=\s*[^"'>]+`,                                            // Detects ondurationchange=
		`(?i)onemptied\s*=\s*[^"'>]+`,                                                   // Detects onemptied=
		`(?i)onended\s*=\s*[^"'>]+`,                                                     // Detects onended=
		`(?i)onerror\s*=\s*[^"'>]+`,                                                     // Detects onerror=
		`(?i)onloadeddata\s*=\s*[^"'>]+`,                                                // Detects onloadeddata=
		`(?i)onloadedmetadata\s*=\s*[^"'>]+`,                                            // Detects onloadedmetadata=
		`(?i)onloadstart\s*=\s*[^"'>]+`,                                                 // Detects onloadstart=
		`(?i)onpause\s*=\s*[^"'>]+`,                                                     // Detects onpause=
		`(?i)onplay\s*=\s*[^"'>]+`,                                                      // Detects onplay=
		`(?i)onplaying\s*=\s*[^"'>]+`,                                                   // Detects onplaying=
		`(?i)onprogress\s*=\s*[^"'>]+`,                                                  // Detects onprogress=
		`(?i)onratechange\s*=\s*[^"'>]+`,                                                // Detects onratechange=
		`(?i)onseeked\s*=\s*[^"'>]+`,                                                    // Detects onseeked=
		`(?i)onseeking\s*=\s*[^"'>]+`,                                                   // Detects onseeking=
		`(?i)onstalled\s*=\s*[^"'>]+`,                                                   // Detects onstalled=
		`(?i)onsuspend\s*=\s*[^"'>]+`,                                                   // Detects onsuspend=
		`(?i)ontimeupdate\s*=\s*[^"'>]+`,                                                // Detects ontimeupdate=
		`(?i)onvolumechange\s*=\s*[^"'>]+`,                                              // Detects onvolumechange=
		`(?i)onwaiting\s*=\s*[^"'>]+`,                                                   // Detects onwaiting=
		`(?i)onshow\s*=\s*[^"'>]+`,                                                      // Detects onshow=
		`(?i)onvisibilitychange\s*=\s*[^"'>]+`,                                          // Detects onvisibilitychange=
		`(?i)onanimationstart\s*=\s*[^"'>]+`,                                            // Detects onanimationstart=
		`(?i)onanimationend\s*=\s*[^"'>]+`,                                              // Detects onanimationend=
		`(?i)onanimationiteration\s*=\s*[^"'>]+`,                                        // Detects onanimationiteration=
		`(?i)ontransitionend\s*=\s*[^"'>]+`,                                             // Detects ontransitionend=
	}

	for _, pattern := range xssPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern: %v", err)
		}
		if re.MatchString(input) {
			return true, nil
		}
	}

	return false, nil
}

func wsSQLInjectionDetection(input string) (bool, error) {

	// SQL injection detection patterns
	sqlPatterns := []string{
		`(?:select\s+.+\s+from\s+.+)`, // Detects select
		`(?:insert\s+.+\s+into\s+.+)`, // Detects insert
		`(?:update\s+.+\s+set\s+.+)`,  // Detects update
		`(?:delete\s+.+\s+from\s+.+)`, // Detects delete
		`(?:drop\s+.+)`,               // Detects drop
		`(?:truncate\s+.+)`,           // Detects truncate
		`(?:alter\s+.+)`,              // Detects alter
		`(?:exec\s+.+)`,               // Detects exec
		`(\s*(all|any|not|and|between|in|like|or|some|contains|containsall|containskey)\s+.+[\=\>\<=\!\~]+.+)`, // Detects logical operators
		`(?:let\s+.+[\=]\s+.*)`,                                 // Detects let
		`(?:begin\s*.+\s*end)`,                                  // Detects begin...end
		`(?:\s*[\/\*]+\s*.+\s*[\*\/]+)`,                         // Detects /* comments */
		`(?:\s*(\-\-)\s*.+\s+)`,                                 // Detects -- comments
		`(?:\s*(contains|containsall|containskey)\s+.+)`,        // Detects contains, containsall, containskey
		`\w*((%27)|('))((%6F)|o|(%4F))((%72)|r|(%52))`,          // Detects 'or'
		`exec(\s|\+)+(s|x)p\w+`,                                 // Detects exec sp_ and xp_
		`(?i)\b(select|insert|update|delete|drop|exec|union)\b`, // Detects SQL keywords
		`(?i)(\bor\b|\band\b).*(=|>|<|!=)`,                      // Detects logical operators combined with comparison operators
		`(?i)'\s*(or|and)\s*'\s*=\s*'`,                          // Detects patterns like ' or ''='
		`(?i)'\s*(or|and)\s*'[^=]*='`,                           // Detects patterns like ' or 'a'='a
		`(?i)'\s*(or|and)\s*1=1`,                                // Detects patterns like ' or 1=1

	}

	for _, pattern := range sqlPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern: %v", err)
		}
		if re.MatchString(input) {
			return true, nil
		}
	}

	return false, nil
}

func wsHTTPVerbTamperingDetection(input string) (bool, error) {

	// HTTP verb tampering detection patterns
	httpVerbPatterns := []string{
		`(?i)(HEAD|OPTIONS|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)`, // Detects HTTP verbs
	}

	for _, pattern := range httpVerbPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern: %v", err)
		}
		if re.MatchString(input) {
			return true, nil
		}
	}

	return false, nil
}

func wsLargeRequestDetection(input int) (bool, error) {
	// Large request detection patterns
	largeRequestPatterns := 5000 * 1024 // 5MB

	if input > largeRequestPatterns {
		return true, nil
	}

	return false, nil
}

func processLoggCollection(data interface{}) error {
	log.Printf("Processing Logg Collection....")
	// Call the logg collector endpoint
	log.Printf("Logg Data: %s", data)
	_, err := makeHTTPRequest(os.Getenv("WS_MODULE_LOGG_COLLECTOR_URL"), os.Getenv("WS_MODULE_LOGG_COLLECTOR_ENDPOINT"), data)
	if err != nil {
		return err
	}
	return nil
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

// handleData processes incoming data and returns the response
func handleData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var (
		req            RequestBody
		loggCollection error
	)
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		sendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Payload.Data.ClientInformation.IP == "" || req.Payload.Data.ClientInformation.DeviceType == "" || req.Payload.Data.ClientInformation.NetworkType == "" || req.Payload.Data.HTTPRequest.Method == "" || req.Payload.Data.HTTPRequest.URL == "" || req.Payload.Data.HTTPRequest.Headers.UserAgent == "" || req.Payload.Data.HTTPRequest.Headers.ContentType == "" {
		sendErrorResponse(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Extract components from event_id
	agentID, service, _, err := extractEventID(req.EventID)
	if err != nil {
		sendErrorResponse(w, "Error extracting event_id: %v", http.StatusBadRequest)
		return
	}

	// Process the rules
	var xssFound bool
	if req.Rules.DetectCrossSiteScripting == "true" {
		payload := req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
		decodedPayload, err := wsHandleDecoder(payload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
		xssFound, err = wsCrossSiteScriptingDetection(decodedPayload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var sqlInjectionFound bool
	if req.Rules.DetectSqlInjection == "true" {
		payload := req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body
		decodedPayload, err := wsHandleDecoder(payload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
		sqlInjectionFound, err = wsSQLInjectionDetection(decodedPayload)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var httpVerbTamperingFound bool
	if req.Rules.DetectHTTPVerbTampering == "true" {
		httpVerbTamperingFound, err = wsHTTPVerbTamperingDetection(req.Payload.Data.HTTPRequest.Method)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var httpLargeRequestFound bool
	if req.Rules.DetectHTTPLargeRequest == "true" {
		httpLargeRequestFound, err = wsLargeRequestDetection(req.Payload.Data.HTTPRequest.Headers.ContentLength)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	data := ResponseData{
		CrossSiteScriptingDetection: xssFound,
		SQLInjectionDetection:       sqlInjectionFound,
		HTTPVerbTamperingDetection:  httpVerbTamperingFound,
		HTTPLargeRequestDetection:   httpLargeRequestFound,
	}

	eventID := strings.Replace(req.EventID, "WS_GATEWAY_SERVICE", "WS_COMMON_ATTACK_DETECTION", -1)
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

	// Log the request to the logg collector
	go func(agentID string, eventID string) {
		logData := map[string]interface{}{
			"name":        "ws-common-attack-detection",
			"agent_id":    agentID,
			"source":      strings.ToLower(service),
			"destination": "ws-common-attack-detection",
			"event_id":    eventID,
			"level":       "info",
			"common_attack_detection": map[string]int{
				"cross_site_scripting": func() int {
					if xssFound {
						return 1
					} else {
						return 0
					}
				}(),
				"sql_injection": func() int {
					if sqlInjectionFound {
						return 1
					} else {
						return 0
					}
				}(),
				"http_verb_tampering": func() int {
					if httpVerbTamperingFound {
						return 1
					} else {
						return 0
					}
				}(),
				"http_large_request": func() int {
					if httpLargeRequestFound {
						return 1
					} else {
						return 0
					}
				}(),
			},
			"type":                 "service_to_service",
			"message":              "Received request from service",
			"request_created_at":   req.RequestCreatedAt,
			"request_processed_at": time.Now().Format(time.RFC3339),
			"timestamp":            time.Now().Format(time.RFC3339),
		}

		loggCollection = processLoggCollection(logData)
		if loggCollection != nil {
			log.Printf("Error: Logg Collector: %v", loggCollection)
		}
	}(agentID, eventID)
}

func main() {
	// Wrap the handler with a 30-second timeout
	timeoutHandler := http.TimeoutHandler(http.HandlerFunc(handleData), 30*time.Second, "Request timed out")

	// Register the timeout handler
	http.Handle("/api/v1/ws/services/common-attack-detection", apiKeyAuthMiddleware(timeoutHandler))
	log.Println("WS Common Attack Detection is running on port 5003...")
	log.Fatal(http.ListenAndServe(":5003", nil))
}
