// Package regressionutil contains only bounded, read-only synthetic
// teardown checks. No ARI constructor, provider connection or call control.
package regressionutil

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// WaitForZero repeats only GETs after the exact-owned session has closed.
// Ambiguous responses, malformed JSON and transport errors fail closed.
func WaitForZero(ctx context.Context, get func(context.Context, string) (int, []byte, error)) bool {
	for {
		allEmpty := true
		for _, path := range []string{"/ari/channels", "/ari/bridges"} {
			code, body, err := get(ctx, path)
			if err != nil || code != http.StatusOK || len(body) > 1024 {
				return false
			}
			var entries []json.RawMessage
			if json.Unmarshal(body, &entries) != nil || entries == nil {
				return false
			}
			if len(entries) != 0 {
				allEmpty = false
			}
		}
		if allEmpty {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}
