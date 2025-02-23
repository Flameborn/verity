package main

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ContextKey type for context keys
type ContextKey string

const (
	// APIKeyContextKey is the context key for API key
	APIKeyContextKey ContextKey = "apiKey"

	// RequestLimitWindow is the time window for rate limiting
	RequestLimitWindow = 10 * time.Minute

	// MaxRequestsPerIP is the maximum number of requests per IP in the time window
	MaxRequestsPerIP = 100
)

// RateLimiter implements rate limiting
type RateLimiter struct {
	ipLimits map[string]*ipRateLimit
	mutex    sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		ipLimits: make(map[string]*ipRateLimit),
	}
}

// APIKeyMiddleware validates the API key and origin
func (s *Server) APIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.URL.Query().Get("apiKey")
		if apiKey == "" {
			writeErrorResponse(w, "Missing API key", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(apiKey, "vrty_") {
			writeErrorResponse(w, "Invalid API key format", http.StatusUnauthorized)
			return
		}

		s.mutex.RLock()
		allowedOrigins, exists := s.config.APIKeys[apiKey]
		s.mutex.RUnlock()

		if !exists {
			writeErrorResponse(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		valid := false
		origin := r.Header.Get("Origin")

		if origin != "" {
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin || allowedOrigin == "*" {
					valid = true
					break
				}
			}
		}

		if !valid {
			writeErrorResponse(w, "Invalid origin", http.StatusForbidden)
			return
		}

		// Store API key in context
		ctx := context.WithValue(r.Context(), APIKeyContextKey, apiKey)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RateLimitMiddleware implements rate limiting by IP
func (rl *RateLimiter) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := GetRealIP(r)

		rl.mutex.Lock()
		allowed := LimitByIP(ip, MaxRequestsPerIP, RequestLimitWindow, rl.ipLimits)
		rl.mutex.Unlock()

		if !allowed {
			writeErrorResponse(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
