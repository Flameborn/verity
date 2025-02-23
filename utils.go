package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// ipRateLimit stores rate limiting information for an IP
type ipRateLimit struct {
	Count   int
	ResetAt time.Time
}

// GenerateAPIKey generates a new API key with the vrty_ prefix
func GenerateAPIKey() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "vrty_" + hex.EncodeToString(bytes), nil
}

// GetRealIP attempts to get the client's real IP address
func GetRealIP(r *http.Request) string {
	// Check for X-Forwarded-For first
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(ip, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}

	// Extract from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If there's an error, just return the RemoteAddr
		return r.RemoteAddr
	}
	return ip
}

// LimitByIP implements rate limiting by IP address
func LimitByIP(ip string, limit int, window time.Duration, store map[string]*ipRateLimit) bool {
	now := time.Now()

	// Create or get rate limit info for this IP
	info, exists := store[ip]
	if !exists {
		info = &ipRateLimit{
			Count:   0,
			ResetAt: now.Add(window),
		}
		store[ip] = info
	}

	// Check if we need to reset the counter
	if now.After(info.ResetAt) {
		info.Count = 0
		info.ResetAt = now.Add(window)
	}

	// Check if we're over the limit
	if info.Count >= limit {
		return false
	}

	// Increment the counter
	info.Count++
	return true
}

// GenerateHMACKey generates a 32-byte secure HMAC key.
func GenerateHMACKey() (string, error) {
	key := make([]byte, 32)

	// Generate cryptographically secure random bytes.
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}

	// Base64 encode the key for safe storage and transmission.
	encodedKey := base64.StdEncoding.EncodeToString(key)

	return encodedKey, nil
}
