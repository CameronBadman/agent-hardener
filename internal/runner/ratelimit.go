package runner

import (
	"context"
	"sync"
	"time"
)

// TokenBucket is a simple token bucket rate limiter.
type TokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64 // tokens per second
	lastTime time.Time
}

// NewTokenBucket creates a rate limiter with the given capacity and refill rate.
func NewTokenBucket(capacity, ratePerSecond float64) *TokenBucket {
	return &TokenBucket{
		tokens:   capacity,
		capacity: capacity,
		rate:     ratePerSecond,
		lastTime: time.Now(),
	}
}

// Wait blocks until a token is available or ctx is cancelled.
func (b *TokenBucket) Wait(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(b.lastTime).Seconds()
		b.tokens = min(b.capacity, b.tokens+elapsed*b.rate)
		b.lastTime = now

		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}

		// Calculate wait time for next token
		waitDuration := time.Duration((1-b.tokens)/b.rate*1000) * time.Millisecond
		b.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitDuration):
		}
	}
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
