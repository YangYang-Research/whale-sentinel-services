package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestHandleData tests the handleData function with valid and invalid requests
func TestHandleData(t *testing.T) {
	// Set up test environment
	os.Setenv("AWS_KMS_ENABLE", "false")
	os.Setenv("API_KEY", "test-api-key")

	// Test cases
	tests := []struct {
		name           string
		requestBody    RequestBody
		expectedStatus int
		expectedData   ResponseData
	}{
		{
			name: "Valid Request with XSS Detection",
			requestBody: RequestBody{
				Hash: "test-hash",
				Rule: Rule{
					DetectCrossSiteScripting: "true",
					DetectSqlInjection:       "false",
					DetectHTTPVerbTampering:  "false",
					DetectHTTPLargeRequest:   "false",
				},
				Payload: Payload{
					Data: Data{
						ClientInformation: ClientInformation{
							IP:          "192.168.1.10",
							DeviceType:  "Desktop",
							NetworkType: "WiFi",
							Geolocation: Geolocation{
								Latitude:  37.7749,
								Longitude: -122.4194,
								Country:   "USA",
								City:      "San Francisco",
							},
						},
						HTTPRequest: HTTPRequest{
							Method: "POST",
							URL:    "/api/v1/ws/service/gateway",
							Host:   "127.0.0.1:443",
							Headers: HTTPRequestHeader{
								UserAgent:     "Mozilla/5.0",
								ContentType:   "application/json",
								ContentLength: 123,
							},
							QueryParams: `"><svg>`,
							Body:        `alert('XSS')`,
						},
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedData: ResponseData{
				CrossSiteScriptingDetection: true,
				SQLInjectionDetection:       false,
				HTTPVerbTamperingDetection:  false,
				HTTPLargeRequestDetection:   false,
			},
		},
		{
			name: "Valid Request with SQL Injection Detection",
			requestBody: RequestBody{
				Hash: "test-hash",
				Rule: Rule{
					DetectCrossSiteScripting: "false",
					DetectSqlInjection:       "true",
					DetectHTTPVerbTampering:  "false",
					DetectHTTPLargeRequest:   "false",
				},
				Payload: Payload{
					Data: Data{
						ClientInformation: ClientInformation{
							IP:          "192.168.1.10",
							DeviceType:  "Desktop",
							NetworkType: "WiFi",
							Geolocation: Geolocation{
								Latitude:  37.7749,
								Longitude: -122.4194,
								Country:   "USA",
								City:      "San Francisco",
							},
						},
						HTTPRequest: HTTPRequest{
							Method: "POST",
							URL:    "/api/v1/ws/service/gateway",
							Host:   "127.0.0.1:443",
							Headers: HTTPRequestHeader{
								UserAgent:     "Mozilla/5.0",
								ContentType:   "application/json",
								ContentLength: 123,
							},
							QueryParams: `1=1`,
							Body:        `SELECT * FROM users`,
						},
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedData: ResponseData{
				CrossSiteScriptingDetection: false,
				SQLInjectionDetection:       true,
				HTTPVerbTamperingDetection:  false,
				HTTPLargeRequestDetection:   false,
			},
		},
		{
			name: "Invalid Request - Missing Required Fields",
			requestBody: RequestBody{
				Hash: "test-hash",
				Rule: Rule{
					DetectCrossSiteScripting: "true",
					DetectSqlInjection:       "false",
					DetectHTTPVerbTampering:  "false",
					DetectHTTPLargeRequest:   "false",
				},
				Payload: Payload{
					Data: Data{
						ClientInformation: ClientInformation{
							IP:          "",
							DeviceType:  "",
							NetworkType: "",
							Geolocation: Geolocation{
								Latitude:  37.7749,
								Longitude: -122.4194,
								Country:   "USA",
								City:      "San Francisco",
							},
						},
						HTTPRequest: HTTPRequest{
							Method: "",
							URL:    "",
							Host:   "",
							Headers: HTTPRequestHeader{
								UserAgent:     "",
								ContentType:   "",
								ContentLength: 0,
							},
							QueryParams: "",
							Body:        "",
						},
					},
				},
			},
			expectedStatus: http.StatusBadRequest,
			expectedData:   ResponseData{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode request body
			reqBody, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			// Create request
			req, err := http.NewRequest("POST", "/api/v1/ws/services/common-attack-detection", bytes.NewBuffer(reqBody))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			// Set Authorization header
			authHeader := base64.StdEncoding.EncodeToString([]byte("ws:test-api-key"))
			req.Header.Set("Authorization", "Basic "+authHeader)

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call the handler
			handler := apiKeyAuthMiddleware(http.HandlerFunc(handleData))
			handler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %v, got %v", tt.expectedStatus, rr.Code)
			}

			// Check response body for successful requests
			if rr.Code == http.StatusOK {
				var response ResponseBody
				err = json.NewDecoder(rr.Body).Decode(&response)
				if err != nil {
					t.Fatalf("Failed to decode response body: %v", err)
				}

				if response.Data != tt.expectedData {
					t.Errorf("Expected data %+v, got %+v", tt.expectedData, response.Data)
				}
			}
		})
	}
}
