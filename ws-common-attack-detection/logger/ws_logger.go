package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var logger *logrus.Logger

// LogEntry is the standard structure for logs
type (
	Default_LogEntry struct {
		Title     string `json:"title"`
		Level     string `json:"level"`
		Timestamp string `json:"timestamp"`
	}

	WSCommonAttack_LogEntry struct {
		Name                  string                    `json:"name"`
		AgentID               string                    `json:"agent_id"`
		Source                string                    `json:"source"`
		Destination           string                    `json:"destination"`
		EventInfo             string                    `json:"event_info"`
		Level                 string                    `json:"level"`
		EventID               string                    `json:"event_id"`
		Type                  string                    `json:"type"`
		CommonAttackDetection CommonAttackDetectionRule `json:"common_attack_detection"`
		RequestCreatedAt      int64                     `json:"request_created_at"`
		RequestProcessedAt    int64                     `json:"request_processed_at"`
		Title                 string                    `json:"title"`
		RawRequest            string                    `json:"raw_request"`
		Timestamp             string                    `json:"timestamp"`
	}

	CommonAttackDetectionRule struct {
		CrossSiteScripting bool `json:"cross_site_scripting"`
		LargeRequest       bool `json:"large_request"`
		SqlInjection       bool `json:"sql_injection"`
		HTTPVerbTampering  bool `json:"http_verb_tampering"`
		HTTPLargeRequest   bool `json:"http_large_request"`
	}
)

func SetupWSLogger(serviceName string, logMaxSize int, logMaxBackups int, logMaxAge int, logCompress bool) {
	// Ensure directory exists
	logDir := "/var/log/whale-sentinel/" + serviceName
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	logFile := fmt.Sprintf("%s/app.log", logDir)

	logger = logrus.New()
	logger.SetOutput(&lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    logMaxSize,
		MaxBackups: logMaxBackups,
		MaxAge:     logMaxAge,
		Compress:   logCompress,
	})
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		PrettyPrint:     false,
	})
	logger.SetLevel(logrus.InfoLevel)
}

// SanitizeRawRequest masks sensitive fields from the raw request string
func SanitizeRawRequest(raw string) string {
	// Mask Authorization headers
	authRegex := regexp.MustCompile(`(?i)(Authorization:\s*)(\S+)`)
	raw = authRegex.ReplaceAllString(raw, `$1****MASKED****`)

	// Mask password fields in JSON or query parameters
	passwordRegex := regexp.MustCompile(`(?i)("password"\s*:\s*)"[^"]*"`)
	raw = passwordRegex.ReplaceAllString(raw, `$1"****MASKED****"`)

	passwordQueryRegex := regexp.MustCompile(`(?i)(password=)([^&\s]+)`)
	raw = passwordQueryRegex.ReplaceAllString(raw, `$1****MASKED****`)

	// Mask credential-like values
	credsRegex := regexp.MustCompile(`(?i)("?(username|email|credential|token)"?\s*:\s*)"[^"]*"`)
	raw = credsRegex.ReplaceAllString(raw, `$1"****MASKED****"`)

	// Mask credit card numbers (basic Luhn-compatible 13–19 digits)
	cardRegex := regexp.MustCompile(`(?i)\b(?:\d[ -]*?){13,19}\b`)
	raw = cardRegex.ReplaceAllString(raw, "****CARD****")

	// Trim excessive whitespace
	raw = strings.TrimSpace(raw)

	return raw
}

// Helper function to convert a timestamp string to Unix time
func toUnixTime(timestamp interface{}) int64 {
	// Check if the timestamp is a string
	timestampStr, ok := timestamp.(string)
	if !ok {
		return 0 // Return 0 if not a string
	}
	// Parse the timestamp string
	parsedTime, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return 0 // Return 0 if parsing fails
	}
	return parsedTime.Unix()
}

// Log function to create and log entries based on the service name
func Log(level string, service_name string, log_data map[string]interface{}) {

	var jsonData []byte
	var err error

	switch service_name {
	case "ws-common-attack-detection":
		cadMap, ok := log_data["common_attack_detection"].(map[string]bool)
		if !ok {
			log.Println("Warning: missing or invalid common_attack_detection map")
			return
		}
		entry := WSCommonAttack_LogEntry{
			Name:        service_name,
			AgentID:     log_data["agent_id"].(string),
			Source:      log_data["source"].(string),
			Destination: log_data["destination"].(string),
			EventInfo:   log_data["event_info"].(string),
			Level:       strings.ToUpper(level),
			EventID:     log_data["event_id"].(string),
			Type:        log_data["type"].(string),
			CommonAttackDetection: CommonAttackDetectionRule{
				CrossSiteScripting: cadMap["cross_site_scripting"],
				LargeRequest:       cadMap["large_request"],
				SqlInjection:       cadMap["sql_injection"],
				HTTPVerbTampering:  cadMap["http_verb_tampering"],
				HTTPLargeRequest:   cadMap["http_large_request"],
			},
			RequestCreatedAt:   toUnixTime(log_data["request_created_at"]),
			RequestProcessedAt: toUnixTime(log_data["request_processed_at"]),
			Title:              log_data["title"].(string),
			RawRequest:         SanitizeRawRequest(log_data["raw_request"].(string)),
			Timestamp:          log_data["timestamp"].(string),
		}
		jsonData, err = json.Marshal(entry)

	default:
		entry := Default_LogEntry{
			Title:     log_data["title"].(string),
			Level:     strings.ToUpper(level),
			Timestamp: log_data["timestamp"].(string),
		}
		jsonData, err = json.Marshal(entry)
	}

	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}

	UPPER_LOG_LEVEL := strings.ToUpper(level)

	if UPPER_LOG_LEVEL == "INFO" {
		logger.Info(string(jsonData))
	} else if UPPER_LOG_LEVEL == "WARNING" {
		logger.Warn(string(jsonData))
	} else if UPPER_LOG_LEVEL == "ERROR" {
		logger.Error(string(jsonData))
	} else if UPPER_LOG_LEVEL == "FATAL" {
		logger.Fatal(string(jsonData))
	} else if UPPER_LOG_LEVEL == "DEBUG" {
		logger.Debug(string(jsonData))
	} else if UPPER_LOG_LEVEL == "TRACE" {
		logger.Trace(string(jsonData))
	} else {
		logger.Println("Unknown log level:", string(jsonData))
	}
}
