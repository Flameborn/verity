package main

import (
	"context"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var cm *ChallengeManager

func main() {
	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		log.Printf("Error while loading configuration: %v", err)
		return
	}
	log.Println("Loaded config.")

	// Create server
	server := NewServer(*config)
	rateLimiter := NewRateLimiter()

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // We'll validate in our middleware
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(rateLimiter.RateLimitMiddleware)
	r.Use(middleware.Logger)

	// Public routes
	r.Get("/", server.handleRoot)

	// API routes with key validation
	r.Route("/api/v1", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(server.APIKeyMiddleware)
			r.Get("/challenge", server.handleGetChallenge)
			r.Post("/challenge/verify", server.handleVerifyChallenge)
		})
	})

	// Setup server
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.Addr, config.Port),
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()
	log.Printf("Server started on port %d", config.Port)

	//Schedule challenge manager to prevent replay attacks
	cm = NewChallengeManager(server.config.ExpireTime)
	log.Printf("Scheduled challenge manager to run every %s.", server.config.ExpireTime)

	// Handle graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Save stats on shutdown
	if err := SaveConfig("./verity.yaml", &server.config); err != nil {
		log.Printf("Error saving configuration: %v", err)
	}

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}
