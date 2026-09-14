package config

import (
	"os"
	"path/filepath"
	"testing"
	"ufw/internal/rule"
)

func TestConfigSaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	testPath := filepath.Join(tempDir, "user_rules.json")

	cfg := &Config{
		Rules: make([]*rule.Rule, 0),
		path:  testPath,
	}

	r := &rule.Rule{
		Action:    rule.Allow,
		Direction: rule.In,
		Port:      "51312",
		From:      "Anywhere",
	}

	if err := cfg.AddRule(r); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].ID != 1 {
		t.Fatalf("expected rule ID 1, got %d", cfg.Rules[0].ID)
	}

	// Verify duplicate detection
	dup := cfg.FindDuplicate(&rule.Rule{
		Action:    rule.Allow,
		Direction: rule.In,
		Port:      "51312",
		From:      "Anywhere",
	})
	if dup == nil {
		t.Errorf("expected duplicate to be found")
	}

	// Load back
	loadedData, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("failed to read test config file: %v", err)
	}
	if len(loadedData) == 0 {
		t.Fatalf("file is empty")
	}
}
