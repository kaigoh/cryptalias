package cryptalias

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AddressStore struct {
	mu   sync.RWMutex
	path string
	data map[string]addressEntry
}

type addressStoreFile struct {
	Entries map[string]addressEntry `json:"entries"`
}

type addressEntry struct {
	Address   string `json:"address"`
	ClientKey string `json:"client_key"`
	ExpiresAt int64  `json:"expires_at"`
}

func newAddressStore(configPath string) (*AddressStore, error) {
	path := statePathFor(configPath)
	store := &AddressStore{
		path: path,
		data: map[string]addressEntry{},
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func statePathFor(configPath string) string {
	return configPath + ".state.json"
}

func aliasKey(ticker, domain, alias, tag, accountKey, clientKey string) string {
	// Keep the key stable and readable; tag may be empty.
	return ticker + "|" + domain + "|" + alias + "|" + tag + "|" + accountKey + "|" + clientKey
}

func (s *AddressStore) Get(key string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.data[key]
	if !ok {
		return "", false
	}
	if entry.ExpiresAt > 0 && now.Unix() >= entry.ExpiresAt {
		// Lazy expiry: drop stale entries when encountered.
		delete(s.data, key)
		return "", false
	}
	return entry.Address, true
}

func (s *AddressStore) Put(key, address, clientKey string, now time.Time, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiresAt := now.Add(ttl).Unix()
	s.data[key] = addressEntry{
		Address:   address,
		ClientKey: clientKey,
		ExpiresAt: expiresAt,
	}
	return s.saveLocked()
}

func (s *AddressStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var file addressStoreFile
	if err := json.Unmarshal(b, &file); err != nil {
		// Backward compatibility: older state files stored string values.
		var legacy struct {
			Entries map[string]string `json:"entries"`
		}
		if errLegacy := json.Unmarshal(b, &legacy); errLegacy != nil {
			return err
		}
		converted := make(map[string]addressEntry, len(legacy.Entries))
		for k, v := range legacy.Entries {
			converted[k] = addressEntry{Address: v}
		}
		s.data = converted
		return nil
	}
	if file.Entries == nil {
		file.Entries = map[string]addressEntry{}
	}
	s.data = file.Entries
	return nil
}

func (s *AddressStore) saveLocked() error {
	file := addressStoreFile{Entries: s.data}
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, b, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cryptalias.state-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
