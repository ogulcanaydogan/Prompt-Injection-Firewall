package proxy

import "sync"

type adaptiveThresholdState struct {
	enabled      bool
	minThreshold float64
	alpha        float64
	mu           sync.Mutex
	ewmaByKey    map[string]float64
}

func newAdaptiveThresholdState(opts AdaptiveThresholdOptions) *adaptiveThresholdState {
	if !opts.Enabled {
		return nil
	}
	if opts.EWMAAlpha <= 0 || opts.EWMAAlpha > 1 {
		opts.EWMAAlpha = 0.2
	}
	if opts.MinThreshold <= 0 {
		opts.MinThreshold = 0.25
	}

	return &adaptiveThresholdState{
		enabled:      true,
		minThreshold: opts.MinThreshold,
		alpha:        opts.EWMAAlpha,
		ewmaByKey:    make(map[string]float64),
	}
}

func (a *adaptiveThresholdState) effectiveThreshold(key string, base float64) float64 {
	if a == nil || !a.enabled {
		return base
	}

	a.mu.Lock()
	ewma := a.ewmaByKey[key]
	a.mu.Unlock()

	effective := base - 0.2*ewma
	return clamp(effective, a.minThreshold, base)
}

func (a *adaptiveThresholdState) update(key string, isInjection bool) float64 {
	if a == nil || !a.enabled {
		return 0
	}

	value := 0.0
	if isInjection {
		value = 1.0
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	current := a.ewmaByKey[key]
	next := a.alpha*value + (1-a.alpha)*current
	a.ewmaByKey[key] = next
	return next
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
