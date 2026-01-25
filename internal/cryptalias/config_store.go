package cryptalias

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

type ConfigStore struct {
	mu   sync.RWMutex
	cfg  *Config
	path string
}

// NewConfigStore creates a threadsafe config holder that also knows its path,
// enabling Save/Update to persist without callers passing paths around.
func NewConfigStore(path string, cfg *Config) *ConfigStore {
	return &ConfigStore{
		path: path,
		cfg:  cfg.Clone(),
	}
}

// Get returns a defensive clone so callers cannot mutate shared state.
func (s *ConfigStore) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Clone()
}

// Set validates and applies a config in memory only (no disk write).
func (s *ConfigStore) Set(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	cfg.Normalize(s.path)
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg = cfg.Clone()
	s.mu.Unlock()
	slog.Debug("config applied in memory", "path", s.path)
	return nil
}

// Save validates, writes to disk atomically, then applies in memory.
func (s *ConfigStore) Save(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	cfg.Normalize(s.path)
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := SaveConfig(s.path, cfg); err != nil {
		return err
	}
	s.cfg = cfg.Clone()
	slog.Info("config saved", "path", s.path)
	return nil
}

// SaveCurrent persists the already-applied config without requiring a path.
func (s *ConfigStore) SaveCurrent() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if err := s.cfg.Validate(); err != nil {
		return err
	}
	if err := SaveConfig(s.path, s.cfg); err != nil {
		return err
	}
	slog.Info("config saved", "path", s.path)
	return nil
}

// Update is the preferred mutation entry point: it clones, mutates, validates,
// saves atomically, and only then swaps the in-memory pointer.
func (s *ConfigStore) Update(fn func(*Config) error) error {
	if fn == nil {
		return fmt.Errorf("update function is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Work on a clone so callers cannot mutate shared state mid-update.
	next := s.cfg.Clone()
	if err := fn(next); err != nil {
		return err
	}
	next.Normalize(s.path)
	if err := next.Validate(); err != nil {
		return err
	}
	if err := SaveConfig(s.path, next); err != nil {
		return err
	}
	s.cfg = next
	slog.Info("config updated", "path", s.path)
	return nil
}

// saveConfigAtomic writes to a temp file in the same directory and renames it,
// so readers never observe partial writes and fsnotify sees a clean replace.
func saveConfigAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	// Write to a temp file in the same directory so rename is atomic.
	tmp, err := os.CreateTemp(dir, ".cryptalias.config-*.yml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Atomic replace prevents readers from observing partial writes.
	return os.Rename(tmpName, path)
}
