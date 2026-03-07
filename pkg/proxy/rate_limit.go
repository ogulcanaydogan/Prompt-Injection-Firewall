package proxy

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const clientLimiterTTL = 15 * time.Minute

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type perClientRateLimiter struct {
	mu          sync.Mutex
	limit       rate.Limit
	burst       int
	keyHeader   string
	clients     map[string]*clientLimiter
	lastCleanup time.Time
	now         func() time.Time
}

func newPerClientRateLimiter(opts RateLimitOptions) *perClientRateLimiter {
	if opts.RequestsPerMinute <= 0 {
		opts.RequestsPerMinute = 120
	}
	if opts.Burst <= 0 {
		opts.Burst = 30
	}
	if strings.TrimSpace(opts.KeyHeader) == "" {
		opts.KeyHeader = "X-Forwarded-For"
	}

	return &perClientRateLimiter{
		limit:     rate.Every(time.Minute / time.Duration(opts.RequestsPerMinute)),
		burst:     opts.Burst,
		keyHeader: opts.KeyHeader,
		clients:   make(map[string]*clientLimiter),
		now:       time.Now,
	}
}

func (l *perClientRateLimiter) allow(key string) bool {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	client, ok := l.clients[key]
	if !ok {
		client = &clientLimiter{
			limiter:  rate.NewLimiter(l.limit, l.burst),
			lastSeen: now,
		}
		l.clients[key] = client
	}
	client.lastSeen = now

	if now.Sub(l.lastCleanup) > clientLimiterTTL {
		l.cleanupLocked(now)
		l.lastCleanup = now
	}

	return client.limiter.Allow()
}

func (l *perClientRateLimiter) keyFromRequest(r *http.Request) string {
	return requestKeyFromRequest(r, l.keyHeader)
}

func requestKeyFromRequest(r *http.Request, keyHeader string) string {
	if r == nil {
		return "unknown"
	}

	if strings.TrimSpace(keyHeader) == "" {
		keyHeader = "X-Forwarded-For"
	}

	if key := strings.TrimSpace(r.Header.Get(keyHeader)); key != "" {
		if strings.EqualFold(keyHeader, "X-Forwarded-For") {
			parts := strings.Split(key, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
		return key
	}

	if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); fwd != "" {
		parts := strings.Split(fwd, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	host := strings.TrimSpace(r.RemoteAddr)
	if host == "" {
		return "unknown"
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil && parsedHost != "" {
		return parsedHost
	}

	return host
}

func (l *perClientRateLimiter) cleanupLocked(now time.Time) {
	for key, client := range l.clients {
		if now.Sub(client.lastSeen) > clientLimiterTTL {
			delete(l.clients, key)
		}
	}
}
