package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProxyCmd_Structure(t *testing.T) {
	cmd := newProxyCmd()

	assert.Equal(t, "proxy", cmd.Use)
	assert.Contains(t, cmd.Short, "prompt injection firewall proxy")
	assert.NotNil(t, cmd.RunE)
}

func TestNewProxyCmd_Flags(t *testing.T) {
	cmd := newProxyCmd()

	targetFlag := cmd.Flags().Lookup("target")
	require.NotNil(t, targetFlag)
	assert.Equal(t, "https://api.openai.com", targetFlag.DefValue)

	listenFlag := cmd.Flags().Lookup("listen")
	require.NotNil(t, listenFlag)
	assert.Equal(t, ":8080", listenFlag.DefValue)

	actionFlag := cmd.Flags().Lookup("action")
	require.NotNil(t, actionFlag)
	assert.Equal(t, "block", actionFlag.DefValue)

	modelFlag := cmd.Flags().Lookup("model")
	require.NotNil(t, modelFlag)
	assert.Equal(t, "", modelFlag.DefValue)
	assert.Equal(t, "m", modelFlag.Shorthand)
}

func TestNewProxyCmd_LongDescription(t *testing.T) {
	cmd := newProxyCmd()

	assert.Contains(t, cmd.Long, "reverse proxy")
	assert.Contains(t, cmd.Long, "OpenAI")
}
