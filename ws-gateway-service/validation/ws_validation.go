package validation

import (
	"fmt"
	"regexp"
	"time"

	"github.com/YangYang-Research/whale-sentinel-services/ws-gateway-service/shared"
)

// Helper functions
func ValidateGWRequest(req shared.GWRequestBody) error {
	if req.GWPayload.GWData.ClientInformation.IP == "" || req.GWPayload.GWData.HTTPRequest.Method == "" || req.GWPayload.GWData.HTTPRequest.URL == "" || req.GWPayload.GWData.HTTPRequest.Headers.UserAgent == "" || req.GWPayload.GWData.HTTPRequest.Headers.ContentType == "" {
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

func ValidateACRequest(req shared.APRequestBody) error {
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

func ValidateASRequest(req shared.ASRequestBody) error {
	if req.AgentID == "" {
		return fmt.Errorf("missing required fields")
	}

	if matched, _ := regexp.MatchString(`^ws_agent_.*`, req.AgentID); !matched {
		return fmt.Errorf("invalid AgentID format")
	}

	if req.ASPayload == nil {
		return fmt.Errorf("missing payload")
	}

	if _, err := time.Parse(time.RFC3339, req.RequestCreatedAt); err != nil {
		return fmt.Errorf("invalid timestamp format")
	}
	return nil
}
