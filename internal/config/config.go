package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"ufw/internal/rule"
)

type Config struct {
	Rules []*rule.Rule `json:"rules"`
	path  string
	mu    sync.Mutex
}

// GetDataDir determines the appropriate directory for storing UFW configuration on Windows.
func GetDataDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		dir := filepath.Join(pd, "ufw")
		if err := os.MkdirAll(dir, 0755); err == nil {
			return dir
		}
	}
	if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
		dir := filepath.Join(userProfile, ".ufw")
		if err := os.MkdirAll(dir, 0755); err == nil {
			return dir
		}
	}
	// Fallback to current directory
	return "."
}

// GetConfigPath returns the full path to the user_rules.json file.
func GetConfigPath() string {
	return filepath.Join(GetDataDir(), "user_rules.json")
}

// Load loads the configuration from disk, or returns an empty Config if it doesn't exist.
func Load() (*Config, error) {
	cfgPath := GetConfigPath()
	cfg := &Config{
		Rules: make([]*rule.Rule, 0),
		path:  cfgPath,
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.path = cfgPath
	return cfg, nil
}

// Save writes the current configuration to disk atomically.
func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := c.path + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}

	return os.Rename(tmpFile, c.path)
}

// FindDuplicate checks if an identical rule already exists.
func (c *Config) FindDuplicate(r *rule.Rule) *rule.Rule {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, existing := range c.Rules {
		if existing.Action == r.Action &&
			existing.Direction == r.Direction &&
			strings.EqualFold(existing.Protocol, r.Protocol) &&
			strings.EqualFold(existing.Port, r.Port) &&
			strings.EqualFold(existing.FromDisplay(), r.FromDisplay()) &&
			strings.EqualFold(existing.ToDisplay(), r.ToDisplay()) {
			return existing
		}
	}
	return nil
}

// NextID calculates the next sequential rule ID.
func (c *Config) NextID() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	maxID := 0
	for _, existing := range c.Rules {
		if existing.ID > maxID {
			maxID = existing.ID
		}
	}
	return maxID + 1
}

// AddRule appends the rule (assigning ID if not set) and saves the configuration.
func (c *Config) AddRule(r *rule.Rule) error {
	c.mu.Lock()
	if r.ID == 0 {
		maxID := 0
		for _, existing := range c.Rules {
			if existing.ID > maxID {
				maxID = existing.ID
			}
		}
		r.ID = maxID + 1
	}
	c.Rules = append(c.Rules, r)
	c.mu.Unlock()

	return c.Save()
}
