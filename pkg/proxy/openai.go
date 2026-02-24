package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/yapay-ai/prompt-injection-firewall/pkg/detector"
)

// ChatCompletionRequest represents an OpenAI chat completion request (subset).
type ChatCompletionRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

// Message represents a single message in a chat completion request.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ExtractPromptsFromOpenAI parses an OpenAI request body and returns scannable inputs.
func ExtractPromptsFromOpenAI(body []byte) ([]detector.ScanInput, error) {
	var req ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parsing OpenAI request: %w", err)
	}

	var inputs []detector.ScanInput
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
