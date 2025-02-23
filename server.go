package main

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"net/http"
	"sync"
	"time"
)

// StatsEntry holds statistics for an API key
type StatsEntry struct {
	TotalChallenges  int64            `json:"totalChallenges"`
	SolvedChallenges int64            `json:"solvedChallenges"`
	FailedChallenges int64            `json:"failedChallenges"`
	IPThrottleCount  map[string]int64 `json:"ipThrottleCount"`
}

// Server is the main server instance
type Server struct {
	config         ServerConfig
	mutex          sync.RWMutex
	ipRequestCount map[string]int64
	ipLastRequest  map[string]time.Time
}

// Response is the standard API response format
type Response struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// NewServer creates a new server instance
func NewServer(config ServerConfig) *Server {
	return &Server{
		config:         config,
		mutex:          sync.RWMutex{},
		ipRequestCount: make(map[string]int64),
		ipLastRequest:  make(map[string]time.Time),
	}
}

// setupRouter configures the HTTP router
func (s *Server) setupRouter() *chi.Mux {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // We'll check origins in our handler
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Routes
	r.Get("/", s.handleRoot)
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/challenge", s.handleGetChallenge)
		r.Post("/challenge/verify", s.handleVerifyChallenge)
	})

	return r
}

// writeErrorResponse writes an error response to the client
func writeErrorResponse(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{Code: 400, Message: message})
}

// getAdjustedComplexity returns the complexity adjusted for server load
func (s *Server) getAdjustedComplexity(ip string) int64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if the IP has made requests recently
	count, exists := s.ipRequestCount[ip]
	lastTime, timeExists := s.ipLastRequest[ip]

	// Reset counter if the last request was more than 5 minutes ago
	if timeExists && time.Since(lastTime) > 5*time.Minute {
		count = 0
	}

	// Update request count and time
	s.ipRequestCount[ip] = count + 1
	s.ipLastRequest[ip] = time.Now()

	// Base complexity
	complexity := s.config.Complexity

	// Adjust complexity based on request frequency
	if exists && count > 10 {
		// Increase complexity by 10% for each 10 requests
		factor := 1.0 + float64(count/10)*0.1
		return int64(float64(complexity) * factor)
	}

	return complexity
}
