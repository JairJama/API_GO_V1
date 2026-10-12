package passwordreset

import (
	"sync"
	"time"
)

// MemoryLimiter is process-local protection against repetitive reset requests.
// A distributed deployment should replace it with a shared implementation.
type MemoryLimiter struct {
	mu          sync.Mutex
	emailEvents map[string][]time.Time
	ipEvents    map[string][]time.Time
	emailLimit  int
	ipLimit     int
	window      time.Duration
}

func NewMemoryLimiter(emailLimit, ipLimit int, window time.Duration) *MemoryLimiter {
	return &MemoryLimiter{
		emailEvents: make(map[string][]time.Time),
		ipEvents:    make(map[string][]time.Time),
		emailLimit:  emailLimit,
		ipLimit:     ipLimit,
		window:      window,
	}
}

func (l *MemoryLimiter) Allow(ip, email string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.emailEvents[email], _ = pruneAndAllow(l.emailEvents[email], now, l.window, l.emailLimit)
	l.ipEvents[ip], _ = pruneAndAllow(l.ipEvents[ip], now, l.window, l.ipLimit)
	if len(l.emailEvents[email]) >= l.emailLimit || len(l.ipEvents[ip]) >= l.ipLimit {
		return false
	}
	l.emailEvents[email] = append(l.emailEvents[email], now)
	l.ipEvents[ip] = append(l.ipEvents[ip], now)
	return true
}

func pruneAndAllow(events []time.Time, now time.Time, window time.Duration, limit int) ([]time.Time, bool) {
	cutoff := now.Add(-window)
	kept := events[:0]
	for _, event := range events {
		if event.After(cutoff) {
			kept = append(kept, event)
		}
	}
	return kept, len(kept) < limit
}
