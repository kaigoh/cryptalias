package cryptalias

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type ConfigStore struct {
	mu   sync.RWMutex
	cfg  *Config
	path string
}

func NewConfigStore(path string, cfg *Config) *ConfigStore {
	return &ConfigStore{
		path: path,
		cfg:  cfg.Clone(),
	}
}

func (s *ConfigStore) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Clone()
}

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
	return nil
}

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
	return nil
}

func (s *ConfigStore) SaveCurrent() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if err := s.cfg.Validate(); err != nil {
		return err
	}
	return SaveConfig(s.path, s.cfg)
}

func (s *ConfigStore) Update(fn func(*Config) error) error {
	if fn == nil {
		return fmt.Errorf("update function is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
	return nil
}

func saveConfigAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
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

	return os.Rename(tmpName, path)
}
