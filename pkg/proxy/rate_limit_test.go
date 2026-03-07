package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPerClientRateLimiter_Burst(t *testing.T) {
	limiter := newPerClientRateLimiter(RateLimitOptions{
		Enabled:           true,
		RequestsPerMinute: 1,
		Burst:             2,
		KeyHeader:         "X-Forwarded-For",
	})

	assert.True(t, limiter.allow("client-a"))
	assert.True(t, limiter.allow("client-a"))
	assert.False(t, limiter.allow("client-a"))
}

func TestPerClientRateLimiter_KeyFromRequest(t *testing.T) {
	limiter := newPerClientRateLimiter(RateLimitOptions{
		Enabled:           true,
		RequestsPerMinute: 120,
		Burst:             30,
		KeyHeader:         "X-Forwarded-For",
	})

	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.8, 10.0.0.1")
	assert.Equal(t, "203.0.113.8", limiter.keyFromRequest(req))

	req2 := httptest.NewRequest("GET", "http://example.com", nil)
	req2.RemoteAddr = "198.51.100.5:9999"
	assert.Equal(t, "198.51.100.5", limiter.keyFromRequest(req2))
}
