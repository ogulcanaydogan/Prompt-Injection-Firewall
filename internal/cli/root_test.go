package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRootCmd_Structure(t *testing.T) {
	cmd := NewRootCmd()

	assert.Equal(t, "pif", cmd.Use)
	assert.Contains(t, cmd.Short, "Prompt Injection Firewall")
	assert.NotEmpty(t, cmd.Long)
	assert.True(t, cmd.SilenceUsage)
}

func TestNewRootCmd_HasSubcommands(t *testing.T) {
	cmd := NewRootCmd()

	subcommands := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subcommands[sub.Name()] = true
	}

	assert.True(t, subcommands["scan"], "should have scan subcommand")
	assert.True(t, subcommands["proxy"], "should have proxy subcommand")
	assert.True(t, subcommands["rules"], "should have rules subcommand")
	assert.True(t, subcommands["version"], "should have version subcommand")
}

func TestNewRootCmd_ConfigFlag(t *testing.T) {
	cmd := NewRootCmd()

	flag := cmd.PersistentFlags().Lookup("config")
	require.NotNil(t, flag)
	assert.Equal(t, "c", flag.Shorthand)
	assert.Equal(t, "string", flag.Value.Type())
}

func TestNewRootCmd_HelpDoesNotError(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--help"})

	// Help should not return an error
	err := cmd.Execute()
	assert.NoError(t, err)
}
