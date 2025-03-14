package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/altcha-org/altcha-lib-go"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// handleRoot serves the root page with server info
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Calculate total stats
	var totalChallenges, solvedChallenges, failedChallenges int64
	for _, stats := range s.config.Stats {
		totalChallenges += stats.TotalChallenges
		solvedChallenges += stats.SolvedChallenges
		failedChallenges += stats.FailedChallenges
	}

	// Calculate success rate
	var successRate float64
	if totalChallenges > 0 {
		successRate = float64(solvedChallenges) / float64(totalChallenges) * 100
	}

	// HTML template
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>Verity Server Info</title>
    <style>
        body { font-family: sans-serif; padding: 20px; }
        h1 { color: #333; }
        .info { border: 1px solid #ddd; padding: 10px; margin-top: 20px; width: 300px;}
        .info p { margin: 5px 0; }
    </style>
</head>
<body>
    <h1>Verity Server Info</h1>
    <div class="info">
        <p>This is <a href="https://github.com/Flameborn/verity">Verity</a>, a tiny server for <a href="https://altcha.org/">Altcha</a> Made by Erion (AKA Flameborn).</p>
    </div>
    <div class="info">
        <p><strong>Total Challenges:</strong> {{.TotalChallenges}}</p>
        <p><strong>Solved Challenges:</strong> {{.SolvedChallenges}}</p>
        <p><strong>Failed Challenges:</strong> {{.FailedChallenges}}</p>
        <p><strong>Success Rate:</strong> {{.SuccessRate}}</p>
    </div>
</body>
</html>
`

	// Data for the template
	data := struct {
		TotalChallenges  int64
		SolvedChallenges int64
		FailedChallenges int64
		SuccessRate      string
	}{
		TotalChallenges:  totalChallenges,
		SolvedChallenges: solvedChallenges,
		FailedChallenges: failedChallenges,
		SuccessRate:      fmt.Sprintf("%.2f%%", successRate),
	}

	// Parse and execute the template
	tmpl, err := template.New("serverInfo").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleGetChallenge generates a new challenge
func (s *Server) handleGetChallenge(w http.ResponseWriter, r *http.Request) {
	// Get API key from context
	apiKey, ok := r.Context().Value(APIKeyContextKey).(string)
	if !ok {
		writeErrorResponse(w, "Missing API key in context", http.StatusInternalServerError)
		return
	}

	// Get client IP address
	ip := GetRealIP(r)

	// Parse expire time from config
	duration, err := time.ParseDuration(s.config.ExpireTime)
	if err != nil {
		duration = 5 * time.Minute // Default to 5 minutes
	}

	expires := time.Now().Add(duration)
	complexity := s.getAdjustedComplexity(ip)

	// Create challenge
	challengeOptions := altcha.ChallengeOptions{
		Algorithm: s.config.Algorithm,
		MaxNumber: complexity,
		HMACKey:   s.config.HMACKey,
		Expires:   &expires,
	}

	challenge, err := altcha.CreateChallenge(challengeOptions)
	if err != nil {
		writeErrorResponse(w, fmt.Sprintf("Failed to create challenge: %v", err), http.StatusInternalServerError)
		return
	}

	// Update stats
	s.mutex.Lock()
	stats := s.config.Stats[apiKey]
	stats.TotalChallenges++
	// Track IP throttling
	if stats.IPThrottleCount == nil {
		stats.IPThrottleCount = make(map[string]int64)
	}
	stats.IPThrottleCount[ip]++
	s.config.Stats[apiKey] = stats
	s.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(challenge)
}

// handleVerifyChallenge verifies a challenge solution
func (s *Server) handleVerifyChallenge(w http.ResponseWriter, r *http.Request) {
	apiKey, ok := r.Context().Value(APIKeyContextKey).(string)
	if !ok {
		writeErrorResponse(w, "Missing API key in context", http.StatusInternalServerError)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeErrorResponse(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	encodedPayload := strings.TrimSpace(string(bodyBytes))

	// Decode base64 to check for replay attacks.
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedPayload)
	if err != nil {
		writeErrorResponse(w, "Invalid base64 encoding", http.StatusBadRequest)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(decodedBytes, &payload); err != nil {
		fmt.Printf("\nJSON unmarshal error: %v\n", err)
		writeErrorResponse(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	// Extract challenge ID and expiration
	challengeID, ok := payload["challenge"].(string)
	if !ok {
		writeErrorResponse(w, "Invalid challenge format", http.StatusBadRequest)
		return
	}
	splitSalt := strings.Split(payload["salt"].(string), "?")
	if len(splitSalt) <= 1 {
		// Missing salt parameters, at least expiration is required.
		writeErrorResponse(w, "Invalid challenge format", http.StatusBadRequest)
		return
	}
	params, _ := url.ParseQuery(splitSalt[1])

	challengeExpire, err := strconv.ParseInt(params.Get("expires"), 10, 64)
	if err != nil || challengeExpire < 1 {
		writeErrorResponse(w, "Invalid challenge format", http.StatusBadRequest)
		return
	}

	// Check for duplicate challenge
	if cm.Exists(challengeID) {
		writeErrorResponse(w, "Challenge already solved", http.StatusConflict)
		return
	}

	// Verify payload
	verified, err := altcha.VerifySolution(encodedPayload, s.config.HMACKey, true)
	if err != nil {
		writeErrorResponse(w, fmt.Sprintf("Verification error: %v", err), http.StatusInternalServerError)
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")

	if verified {
		cm.AddChallenge(challengeID, challengeExpire)
		stats := s.config.Stats[apiKey]
		stats.SolvedChallenges++
		s.config.Stats[apiKey] = stats
		json.NewEncoder(w).Encode(Response{
			Code:    http.StatusOK,
			Message: "OK",
		})
	} else {
		stats := s.config.Stats[apiKey]
		stats.FailedChallenges++
		s.config.Stats[apiKey] = stats
		json.NewEncoder(w).Encode(Response{
			Code:    http.StatusBadRequest,
			Message: "Invalid payload",
		})
	}
	return
}
