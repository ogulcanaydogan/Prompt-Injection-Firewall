package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractPromptsFromOpenAI(t *testing.T) {
	t.Run("valid chat completion", func(t *testing.T) {
		body := []byte(`{
			"model": "gpt-4",
			"messages": [
				{"role": "system", "content": "You are a helpful assistant."},
				{"role": "user", "content": "Hello!"}
			]
		}`)

		inputs, err := ExtractPromptsFromOpenAI(body)
		require.NoError(t, err)
		assert.Len(t, inputs, 2)
		assert.Equal(t, "system", inputs[0].Role)
		assert.Equal(t, "You are a helpful assistant.", inputs[0].Text)
		assert.Equal(t, "user", inputs[1].Role)
		assert.Equal(t, "Hello!", inputs[1].Text)
	})

	t.Run("empty messages", func(t *testing.T) {
		body := []byte(`{"model": "gpt-4", "messages": []}`)
		inputs, err := ExtractPromptsFromOpenAI(body)
		require.NoError(t, err)
		assert.Empty(t, inputs)
	})

	t.Run("invalid json", func(t *testing.T) {
		_, err := ExtractPromptsFromOpenAI([]byte(`{invalid`))
		assert.Error(t, err)
	})

	t.Run("skips empty content", func(t *testing.T) {
		body := []byte(`{
			"model": "gpt-4",
			"messages": [
				{"role": "user", "content": ""},
				{"role": "user", "content": "Hello"}
			]
		}`)
		inputs, err := ExtractPromptsFromOpenAI(body)
		require.NoError(t, err)
		assert.Len(t, inputs, 1)
	})
}

func TestExtractPromptsFromAnthropic(t *testing.T) {
	t.Run("with system prompt", func(t *testing.T) {
		body := []byte(`{
			"model": "claude-sonnet-4-20250514",
			"system": "You are a helpful assistant.",
			"messages": [
				{"role": "user", "content": "Hello!"}
			]
		}`)

		inputs, err := ExtractPromptsFromAnthropic(body)
		require.NoError(t, err)
		assert.Len(t, inputs, 2)
		assert.Equal(t, "system", inputs[0].Role)
		assert.Equal(t, "user", inputs[1].Role)
	})

	t.Run("without system prompt", func(t *testing.T) {
		body := []byte(`{
			"model": "claude-sonnet-4-20250514",
			"messages": [
				{"role": "user", "content": "Hello!"}
			]
		}`)

		inputs, err := ExtractPromptsFromAnthropic(body)
		require.NoError(t, err)
		assert.Len(t, inputs, 1)
	})
}
