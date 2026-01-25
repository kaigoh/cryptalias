package cryptalias

import (
	"log/slog"
	"os"
	"strings"
	"time"
)

var logLevel slog.LevelVar

func parseLogLevel(level string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug, true
	case "", "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}

func InitLogger(cfg LoggingConfig) {
	lvl, ok := parseLogLevel(cfg.Level)
	if !ok {
		lvl = slog.LevelInfo
	}
	logLevel.Set(lvl)

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &logLevel,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				return slog.String(slog.TimeKey, a.Value.Time().Format(time.TimeOnly))
			case slog.LevelKey:
				// slog may pass the level as a string or a slog.Level depending on the handler path.
				switch v := a.Value.Any().(type) {
				case slog.Level:
					return slog.String(slog.LevelKey, strings.ToUpper(v.String()))
				case slog.Leveler:
					return slog.String(slog.LevelKey, strings.ToUpper(v.Level().String()))
				case string:
					return slog.String(slog.LevelKey, strings.ToUpper(v))
				default:
					return slog.String(slog.LevelKey, strings.ToUpper(a.Value.String()))
				}
			default:
				return a
			}
		},
	})

	slog.SetDefault(slog.New(handler))
	slog.Info("logger initialized", "level", strings.ToUpper(lvl.String()))
}
