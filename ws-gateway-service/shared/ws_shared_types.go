package shared

type (
	GWRequestBody struct {
		AgentID          string    `json:"agent_id"`
		GWPayload        GWPayload `json:"payload"`
		RequestCreatedAt string    `json:"request_created_at"`
	}

	GWPayload struct {
		GWData GWData `json:"data"`
	}

	GWData struct {
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

	APRequestBody struct {
		AgentID          string `json:"agent_id"`
		RequestCreatedAt string `json:"request_created_at"`
	}

	AgentProfileRaw struct {
		Profile map[string]interface{} `json:"profile"`
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

	APResponseBody struct {
		Status             string       `json:"status"`
		Message            string       `json:"message"`
		Profile            AgentProfile `json:"profile"`
		EventInfo          string       `json:"event_info"`
		RequestCreatedAt   string       `json:"request_created_at"`
		RequestProcessedAt string       `json:"request_processed_at"`
	}

	AgentProfile struct {
		RunningMode                   string                      `json:"running_mode"`
		LastRunMode                   string                      `json:"last_run_mode"`
		LiteModeDataIsSynchronized    bool                        `json:"lite_mode_data_is_synchronized"`
		LiteModeDataSynchronizeStatus string                      `json:"lite_mode_data_synchronize_status"`
		WebAttackDetection            WebAttackDetectionConfig    `json:"ws_module_web_attack_detection"`
		DGADetection                  DGADetectionConfig          `json:"ws_module_dga_detection"`
		CommonAttackDetection         CommonAttackDetectionConfig `json:"ws_module_common_attack_detection"`
		SecureResponseHeaders         SecureResponseHeaderConfig  `json:"secure_response_headers"`
	}

	WebAttackDetectionConfig struct {
		Enable       bool `json:"enable"`
		DetectHeader bool `json:"detect_header"`
		Threshold    int  `json:"threshold"`
	}

	DGADetectionConfig struct {
		Enable    bool `json:"enable"`
		Threshold int  `json:"threshold"`
	}

	CommonAttackDetectionConfig struct {
		Enable                   bool `json:"enable"`
		DetectCrossSiteScripting bool `json:"detect_cross_site_scripting"`
		DetectSqlInjection       bool `json:"detect_sql_injection"`
		DetectHTTPVerbTampering  bool `json:"detect_http_verb_tampering"`
		DetectHTTPLargeRequest   bool `json:"detect_http_large_request"`
	}

	SecureResponseHeaderConfig struct {
		Enable        bool                   `json:"enable"`
		SecureHeaders map[string]interface{} `json:"headers"`
	}

	ASRequestBody struct {
		AgentID          string                 `json:"agent_id"`
		ASPayload        map[string]interface{} `json:"payload"`
		RequestCreatedAt string                 `json:"request_created_at"`
	}

	ASResponseBody struct {
		Status             string `json:"status"`
		Message            string `json:"message"`
		Profile            string `json:"profile"`
		EventInfo          string `json:"event_info"`
		RequestCreatedAt   string `json:"request_created_at"`
		RequestProcessedAt string `json:"request_processed_at"`
	}

	ErrorResponse struct {
		Status    string `json:"status"`
		Message   string `json:"message"`
		ErrorCode int    `json:"error_code"`
	}
)
