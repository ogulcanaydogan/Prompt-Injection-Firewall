package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAdaptiveThreshold_EWMAAndClamp(t *testing.T) {
	state := newAdaptiveThresholdState(AdaptiveThresholdOptions{
		Enabled:      true,
		MinThreshold: 0.25,
		EWMAAlpha:    0.2,
	})

	base := 0.5
	assert.Equal(t, base, state.effectiveThreshold("client", base))

	state.update("client", true) // ewma=0.2
	assert.InDelta(t, 0.46, state.effectiveThreshold("client", base), 0.0001)

	for i := 0; i < 20; i++ {
		state.update("client", true)
	}
	assert.GreaterOrEqual(t, state.effectiveThreshold("client", base), 0.25)
	assert.LessOrEqual(t, state.effectiveThreshold("client", base), base)
}

func TestAdaptiveThreshold_Disabled(t *testing.T) {
	state := newAdaptiveThresholdState(AdaptiveThresholdOptions{
		Enabled: false,
	})
	assert.Nil(t, state)
}
