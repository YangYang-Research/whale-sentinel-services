package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/YangYang-Research/whale-sentinel-services/ws-common-attack-detection/wshelper"
	"github.com/YangYang-Research/whale-sentinel-services/ws-common-attack-detection/wslogger"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

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
	}
}

// RequestBody defines the structure of the request payload
type RequestBody struct {
	EventInfo        string  `json:"event_info"`
	Rules            Rules   `json:"rules"`
	Payload          Payload `json:"payload"`
	RequestCreatedAt string  `json:"request_created_at"`
}

// Rule defines the structure of the rule field in the request body
type Rules struct {
	DetectCrossSiteScripting bool `json:"detect_cross_site_scripting"`
	DetectLargeRequest       bool `json:"detect_large_request"`
	DetectSqlInjection       bool `json:"detect_sql_injection"`
	DetectHTTPVerbTampering  bool `json:"detect_http_verb_tampering"`
	DetectHTTPLargeRequest   bool `json:"detect_http_large_request"`
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
	EventInfo          string       `json:"event_info"`
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
func extractEventInfo(enventInfo string) (string, string, string, error) {
	// Split the event_id by the "|" delimiter
	parts := strings.Split(enventInfo, "|")

	// Ensure the split result has exactly 3 parts
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid event_info format: %s", enventInfo)
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
		req RequestBody
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
	agentID, serviceName, eventID, err := extractEventInfo(req.EventInfo)
	if err != nil {
		sendErrorResponse(w, "Error extracting event_id: %v", http.StatusBadRequest)
		return
	}

	// Process the rules
	var xssFound bool
	if req.Rules.DetectCrossSiteScripting {
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
	if req.Rules.DetectSqlInjection {
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
	if req.Rules.DetectHTTPVerbTampering {
		httpVerbTamperingFound, err = wsHTTPVerbTamperingDetection(req.Payload.Data.HTTPRequest.Method)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var httpLargeRequestFound bool
	if req.Rules.DetectHTTPLargeRequest {
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

	eventInfo := strings.Replace(req.EventInfo, "WS_GATEWAY_SERVICE", "WS_COMMON_ATTACK_DETECTION", -1)
	response := ResponseBody{
		Status:             "success",
		Message:            "Request processed successfully",
		Data:               data,
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
			"name":        "ws-common-attack-detection",
			"agent_id":    agentID,
			"source":      strings.ToLower(serviceName),
			"destination": "ws-common-attack-detection",
			"event_info":  eventInfo,
			"event_id":    eventID,
			"type":        "SERVICE_EVENT",
			"common_attack_detection": (map[string]bool{
				"cross_site_scripting": xssFound,
				"sql_injection":        sqlInjectionFound,
				"http_verb_tampering":  httpVerbTamperingFound,
				"http_large_request":   httpLargeRequestFound,
			}),
			"title":                "Received request from service",
			"request_created_at":   req.RequestCreatedAt,
			"request_processed_at": time.Now().Format(time.RFC3339),
			"raw_request":          rawRequest,
			"timestamp":            time.Now().Format(time.RFC3339),
		}

		wslogger.Log("info", "ws-common-attack-detection", logData)
	}(agentID, eventInfo, (req.Payload.Data.HTTPRequest.QueryParams + req.Payload.Data.HTTPRequest.Body))
}

func main() {
	log.Info("WS Common Attack Detection is running on port 5003...")
	// Initialize the logger
	logMaxSize, _ := strconv.Atoi(os.Getenv("LOG_MAX_SIZE"))
	logMaxBackups, _ := strconv.Atoi(os.Getenv("LOG_MAX_BACKUPS"))
	logMaxAge, _ := strconv.Atoi(os.Getenv("LOG_MAX_AGE"))
	logCompression, _ := strconv.ParseBool(os.Getenv("LOG_COMPRESSION"))
	wslogger.SetupWSLogger("ws-common-attack-detection", logMaxSize, logMaxBackups, logMaxAge, logCompression)

	// Wrap the handler with a 30-second timeout
	timeoutHandler := http.TimeoutHandler(http.HandlerFunc(handleData), 30*time.Second, "Request timed out")

	// Register the timeout handler
	http.Handle("/api/v1/ws/services/common-attack-detection", apiKeyAuthMiddleware(timeoutHandler))
	log.Fatal(http.ListenAndServe(":5003", nil))
}
