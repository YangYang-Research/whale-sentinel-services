package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
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
	Hash    string  `json:"hash"`
	Rule    Rule    `json:"rule"`
	Payload Payload `json:"payload"`
}

// Rule defines the structure of the rule field in the request body
type Rule struct {
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
}

// ResponseBody defines the structure of the response payload
type ResponseBody struct {
	Status      string       `json:"status"`
	Message     string       `json:"message"`
	Data        ResponseData `json:"data"`
	ProcessedAt string       `json:"processed_at"`
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

	var req RequestBody
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

	// Process the rules
	var xssFound bool
	if req.Rule.DetectCrossSiteScripting == "true" {
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
	if req.Rule.DetectSqlInjection == "true" {
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
	if req.Rule.DetectHTTPVerbTampering == "true" {
		httpVerbTamperingFound, err = wsHTTPVerbTamperingDetection(req.Payload.Data.HTTPRequest.Method)
		if err != nil {
			sendErrorResponse(w, "Error processing data", http.StatusInternalServerError)
			return
		}
	}

	var httpLargeRequestFound bool
	if req.Rule.DetectHTTPLargeRequest == "true" {
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

	response := ResponseBody{
		Status:      "success",
		Message:     "Request processed successfully",
		Data:        data,
		ProcessedAt: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.Handle("/api/v1/ws/services/common-attack-detection", apiKeyAuthMiddleware(http.HandlerFunc(handleData)))
	log.Println("WS Common Attack Detection is running on port 5003...")
	log.Fatal(http.ListenAndServe(":5003", nil))
}
