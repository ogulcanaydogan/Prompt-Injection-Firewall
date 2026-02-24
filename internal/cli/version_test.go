package cli

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVersionCmd_Structure(t *testing.T) {
	cmd := newVersionCmd()

	assert.Equal(t, "version", cmd.Use)
	assert.Equal(t, "Print version information", cmd.Short)
	assert.NotNil(t, cmd.Run)
}

func TestNewVersionCmd_Output(t *testing.T) {
	// Set a known version for testing
	Version = "1.0.0-test"
	defer func() { Version = "dev" }()

	cmd := newVersionCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "pif version 1.0.0-test")
	assert.Contains(t, output, "go: "+runtime.Version())
	assert.Contains(t, output, "os/arch: "+runtime.GOOS+"/"+runtime.GOARCH)
}

func TestNewVersionCmd_DevVersion(t *testing.T) {
	Version = "dev"

	cmd := newVersionCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "pif version dev")
}
