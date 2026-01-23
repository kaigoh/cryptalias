package cryptalias

import (
	"log"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

func WatchConfigFile(path string, store *ConfigStore) (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return nil, err
	}
	_ = watcher.Add(path)

	cleanPath := filepath.Clean(path)
	baseName := filepath.Base(cleanPath)

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				affected := filepath.Clean(event.Name) == cleanPath || filepath.Base(event.Name) == baseName
				if !affected {
					continue
				}

				if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
					_ = watcher.Remove(path)
					_ = watcher.Add(path)
				}

				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
					cfg, err := LoadConfig(path)
					if err != nil {
						log.Printf("config reload failed: %v", err)
						continue
					}
					cfg.Normalize(path)
					if err := cfg.Validate(); err != nil {
						log.Printf("config reload rejected: %v", err)
						continue
					}
					if err := store.Set(cfg); err != nil {
						log.Printf("config apply failed: %v", err)
						continue
					}
					log.Printf("config reloaded from disk")
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("config watcher error: %v", err)
			}
		}
	}()

	return watcher, nil
}
