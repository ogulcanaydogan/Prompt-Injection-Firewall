package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/ogulcanaydogan/Prompt-Injection-Firewall/pkg/detector"
)

// AnthropicRequest represents an Anthropic messages API request (subset).
type AnthropicRequest struct {
	Model    string             `json:"model"`
	System   string             `json:"system,omitempty"`
	Messages []AnthropicMessage `json:"messages"`
}

// AnthropicMessage represents a single message in an Anthropic request.
type AnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ExtractPromptsFromAnthropic parses an Anthropic request body and returns scannable inputs.
func ExtractPromptsFromAnthropic(body []byte) ([]detector.ScanInput, error) {
	var req AnthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parsing Anthropic request: %w", err)
	}

	var inputs []detector.ScanInput

	if req.System != "" {
		inputs = append(inputs, detector.ScanInput{
			Text: req.System,
			Role: "system",
		})
	}

	for _, msg := range req.Messages {
		if msg.Content == "" {
			continue
		}
		inputs = append(inputs, detector.ScanInput{
			Text: msg.Content,
			Role: msg.Role,
		})
	}

	return inputs, nil
}
