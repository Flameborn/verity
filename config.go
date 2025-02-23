package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/altcha-org/altcha-lib-go"
	"github.com/spf13/viper"
)

const (
	DefaultAddr       = "127.0.0.1"
	DefaultPort       = 8080
	DefaultComplexity = 50000
	DefaultExpireTime = "5m"
	EnvPrefix         = "VERITY"
)

// ServerConfig holds the application configuration
type ServerConfig struct {
	Addr       string                `mapstructure:"addr" json:"addr"`
	Port       int                   `mapstructure:"port" json:"port"`
	HMACKey    string                `mapstructure:"hmacKey" json:"hmacKey"`
	Algorithm  altcha.Algorithm      `mapstructure:"algorithm" json:"algorithm"`
	Complexity int64                 `mapstructure:"complexity" json:"complexity"`
	ExpireTime string                `mapstructure:"expireTime" json:"expireTime"`
	APIKeys    map[string][]string   `mapstructure:"apiKeys" json:"apiKeys"`
	Stats      map[string]StatsEntry `mapstructure:"stats" json:"stats"`
}

// LoadConfig loads the configuration from files, environment variables, and flags
func LoadConfig() (*ServerConfig, error) {
	config := &ServerConfig{
		APIKeys: make(map[string][]string),
		Stats:   make(map[string]StatsEntry),
	}

	// Initialize stats for each API key
	for key := range config.APIKeys {
		if _, exists := config.Stats[key]; !exists {
			config.Stats[key] = StatsEntry{
				IPThrottleCount: make(map[string]int64),
			}
		}
	}

	// Create config file if it doesn't exist
	if err := ensureConfig("./verity.yaml"); err != nil {
		return nil, fmt.Errorf("error ensuring config: %w", err)
	}

	// Setup command line flags
	configPath := flag.String("config", "./verity.yaml", "path to config file")
	addr := flag.String("addr", "", "server address")
	port := flag.Int("port", 0, "server port")
	algorithm := flag.String("algorithm", "", "hash algorithm (SHA256 or SHA512)")
	complexity := flag.Int64("complexity", 0, "challenge complexity")
	expireTime := flag.String("expire-time", "", "challenge expire time")

	// Add command for generating API keys
	addCmd := flag.NewFlagSet("add", flag.ExitOnError)

	// Custom usage
	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		fmt.Println("Commands:")
		fmt.Println("  add <domain1> [domain2...]  Generate new API key for specified domains")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
	}

	// Parse flags
	if len(os.Args) > 1 && os.Args[1] == "add" {
		addCmd.Parse(os.Args[2:])
		if addCmd.NArg() < 1 {
			fmt.Println("Error: at least one domain is required")
			addCmd.Usage()
			os.Exit(1)
		}
		return handleAddCommand(addCmd.Args(), configPath)
	}

	flag.Parse()

	// Initialize viper
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigFile(*configPath)
	v.SetEnvPrefix(EnvPrefix)
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set defaults
	v.SetDefault("addr", DefaultAddr)
	v.SetDefault("port", DefaultPort)
	v.SetDefault("complexity", DefaultComplexity)
	v.SetDefault("expireTime", DefaultExpireTime)
	v.SetDefault("algorithm", "SHA-256")

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	// Override with environment variables and flags
	if *addr != "" {
		v.Set("addr", *addr)
	}
	if *port != 0 {
		v.Set("port", *port)
	}
	if *algorithm != "" {
		v.Set("algorithm", *algorithm)
	}
	if *complexity != 0 {
		v.Set("complexity", *complexity)
	}
	if *expireTime != "" {
		v.Set("expireTime", *expireTime)
	}

	// Unmarshal config
	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate config
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

// ensureConfig creates a default config file if it doesn't exist
func ensureConfig(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create directory if it doesn't exist
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("error creating config directory: %w", err)
		}

		// Create default config
		config := &ServerConfig{
			Addr:       DefaultAddr,
			Port:       DefaultPort,
			HMACKey:    "",
			Algorithm:  "SHA-256",
			Complexity: DefaultComplexity,
			ExpireTime: DefaultExpireTime,
			APIKeys:    make(map[string][]string),
			Stats:      make(map[string]StatsEntry),
		}

		config.HMACKey, err = GenerateHMACKey()
		if err != nil {
			return fmt.Errorf("error generating HMACKey: %w", err)
		}

		// Save default config
		if err := SaveConfig(path, config); err != nil {
			return fmt.Errorf("error saving default config: %w", err)
		}
	}
	return nil
}

// SaveConfig saves the configuration to file
func SaveConfig(path string, config *ServerConfig) error {
	v := viper.New()
	v.SetConfigFile(path)

	// Set all config values
	v.Set("addr", config.Addr)
	v.Set("port", config.Port)
	v.Set("hmacKey", config.HMACKey)
	v.Set("algorithm", config.Algorithm)
	v.Set("complexity", config.Complexity)
	v.Set("expireTime", config.ExpireTime)
	v.Set("apiKeys", config.APIKeys)
	v.Set("stats", config.Stats)

	return v.WriteConfig()
}

// validateConfig validates the configuration values
func validateConfig(config *ServerConfig) error {
	if config.Algorithm != "SHA-256" && config.Algorithm != "SHA-512" {
		return fmt.Errorf("invalid algorithm: must be SHA-256 or SHA-512")
	}

	if _, err := time.ParseDuration(config.ExpireTime); err != nil {
		return fmt.Errorf("invalid expireTime: %w", err)
	}

	if config.Complexity <= 0 {
		return fmt.Errorf("complexity must be greater than 0")
	}

	return nil
}

// handleAddCommand handles the 'add' command for generating API keys
func handleAddCommand(domains []string, configPath *string) (*ServerConfig, error) {
	// Load existing config
	config := &ServerConfig{}
	v := viper.New()
	v.SetConfigFile(*configPath)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Generate new API key
	apiKey, err := GenerateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("Error while adding an API key: %w", err)
	}

	// Initialise APIKey map if nil
	if config.APIKeys == nil {
		config.APIKeys = make(map[string][]string)
	}
	// Add to config
	config.APIKeys[apiKey] = domains

	// Save updated config
	if err := SaveConfig(*configPath, config); err != nil {
		return nil, fmt.Errorf("error saving config: %w", err)
	}

	// Print the generated API key
	fmt.Printf("Generated API key:\n%s\nAllowed domains: %s\nPlease restart Verity for the changes to take effect.", apiKey, strings.Join(domains, ", "))

	os.Exit(0)
	return config, nil
}
