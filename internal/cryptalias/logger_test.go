package cryptalias

import (
	"log/slog"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
		ok   bool
	}{
		{in: "debug", want: slog.LevelDebug, ok: true},
		{in: "INFO", want: slog.LevelInfo, ok: true},
		{in: "warn", want: slog.LevelWarn, ok: true},
		{in: "warning", want: slog.LevelWarn, ok: true},
		{in: "error", want: slog.LevelError, ok: true},
		{in: "nope", want: slog.LevelInfo, ok: false},
	}

	for _, tc := range cases {
		got, ok := parseLogLevel(tc.in)
		if ok != tc.ok {
			t.Fatalf("parseLogLevel(%q) ok=%v want %v", tc.in, ok, tc.ok)
		}
		if got != tc.want {
			t.Fatalf("parseLogLevel(%q) level=%v want %v", tc.in, got, tc.want)
		}
	}
}

