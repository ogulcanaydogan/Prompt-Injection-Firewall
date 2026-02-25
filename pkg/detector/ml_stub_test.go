//go:build !ml

package detector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMLDetector_Stub_ReturnsError(t *testing.T) {
	cfg := MLConfig{
		ModelPath: "some/model/path",
		Threshold: 0.85,
	}

	d, err := NewMLDetector(cfg)
	require.Error(t, err)
	assert.Nil(t, d)
	assert.ErrorIs(t, err, ErrMLNotAvailable)
}

func TestMLDetector_Stub_ID(t *testing.T) {
	d := &MLDetector{}
	assert.Equal(t, "ml", d.ID())
}

func TestMLDetector_Stub_Scan_ReturnsError(t *testing.T) {
	d := &MLDetector{}
	result, err := d.Scan(context.Background(), ScanInput{Text: "test"})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrMLNotAvailable)
}

func TestMLDetector_Stub_Ready_ReturnsFalse(t *testing.T) {
	d := &MLDetector{}
	assert.False(t, d.Ready())
}

func TestMLDetector_Stub_Close_NoError(t *testing.T) {
	d := &MLDetector{}
	err := d.Close()
	assert.NoError(t, err)
}

func TestErrMLNotAvailable_Message(t *testing.T) {
	assert.Contains(t, ErrMLNotAvailable.Error(), "build with -tags ml")
	assert.Contains(t, ErrMLNotAvailable.Error(), "CGO_ENABLED=1")
}
