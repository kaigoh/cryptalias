package cryptalias

import (
	"path/filepath"
	"testing"
)

func TestConfigStoreUpdatePersistsToDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	store := NewConfigStore(path, testConfig(t))

	if err := store.Update(func(c *Config) error {
		c.BaseURL = "http://example.com:9999/"
		c.Logging.Level = "debug"
		return nil
	}); err != nil {
		t.Fatalf("update config: %v", err)
	}

	got := store.Get()
	if got.BaseURL != "http://example.com:9999" {
		t.Fatalf("expected trimmed base_url, got %q", got.BaseURL)
	}
	if got.Logging.Level != "debug" {
		t.Fatalf("expected logging level debug, got %q", got.Logging.Level)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load config from disk: %v", err)
	}
	if loaded.BaseURL != got.BaseURL {
		t.Fatalf("expected disk base_url %q, got %q", got.BaseURL, loaded.BaseURL)
	}
}

func TestConfigStoreSaveCurrentWritesExistingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	store := NewConfigStore(path, testConfig(t))

	cfg := store.Get()
	cfg.BaseURL = "http://saved.example/"
	if err := store.Set(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}

	if err := store.SaveCurrent(); err != nil {
		t.Fatalf("save current config: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load config from disk: %v", err)
	}
	if loaded.BaseURL != "http://saved.example" {
		t.Fatalf("expected saved base_url, got %q", loaded.BaseURL)
	}
}

