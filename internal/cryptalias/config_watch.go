package cryptalias

import (
	"log/slog"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// WatchConfigFile applies on-disk config edits live using fsnotify.
// It watches both the directory and the file to survive atomic saves.
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
	// Watch both the directory and the file to survive atomic renames.
	_ = watcher.Add(path)

	cleanPath := filepath.Clean(path)
	baseName := filepath.Base(cleanPath)

	go func() {
		slog.Debug("config watcher loop started", "path", cleanPath)
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				slog.Debug("config watcher event", "op", event.Op.String(), "name", event.Name)

				affected := filepath.Clean(event.Name) == cleanPath || filepath.Base(event.Name) == baseName
				if !affected {
					continue
				}

				if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
					// Atomic saves replace the file; re-add the watch on the new inode.
					_ = watcher.Remove(path)
					_ = watcher.Add(path)
				}

				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
					// Load -> validate -> apply keeps the running config consistent.
					cfg, err := LoadConfig(path)
					if err != nil {
						slog.Error("config reload failed", "path", path, "error", err)
						continue
					}
					cfg.Normalize(path)
					if err := cfg.Validate(); err != nil {
						slog.Warn("config reload rejected", "path", path, "error", err)
						continue
					}
					if err := store.Set(cfg); err != nil {
						slog.Error("config apply failed", "path", path, "error", err)
						continue
					}
					// Re-apply logging settings on successful reload.
					InitLogger(cfg.Logging)
					for _, d := range cfg.Domains {
						slog.Info("dns txt record", "domain", d.Domain, "name", "_cryptalias."+d.Domain, "value", d.DNSTXTValue())
					}
					slog.Info("config reloaded from disk", "path", path)
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.Error("config watcher error", "path", path, "error", err)
			}
		}
	}()

	return watcher, nil
}
