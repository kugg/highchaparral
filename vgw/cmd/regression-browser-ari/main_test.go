package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestReadOnlySettlementWaitsForBothARILists(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var calls []string
	if !waitForZero(ctx, func(_ context.Context, path string) (int, []byte, error) {
		calls = append(calls, path)
		if len(calls) == 1 {
			return http.StatusOK, []byte(`[{"id":"synthetic"}]`), nil
		}
		return http.StatusOK, []byte(`[]`), nil
	}) || len(calls) != 4 || calls[0] != "/ari/channels" || calls[1] != "/ari/bridges" ||
		calls[2] != "/ari/channels" || calls[3] != "/ari/bridges" {
		t.Fatal("synthetic cleanup did not wait for both resource lists")
	}
}

func TestSettlementFailsClosedOnUnknownOrUntrustedResponse(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   []byte
		err    error
	}{
		{http.StatusUnauthorized, []byte(`[]`), nil},
		{http.StatusOK, []byte(`not-json`), nil},
		{http.StatusOK, bytes.Repeat([]byte("a"), 1025), nil},
		{0, nil, errors.New("untrusted response")},
	} {
		count := 0
		if waitForZero(context.Background(), func(context.Context, string) (int, []byte, error) {
			count++
			return tc.status, tc.body, tc.err
		}) || count != 1 {
			t.Fatal("unknown ARI list accepted or retried")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitForZero(ctx, func(context.Context, string) (int, []byte, error) {
		return http.StatusOK, []byte(`[{"id":"pending"}]`), nil
	}) {
		t.Fatal("cancelled settlement was accepted")
	}
	t.Setenv("HOME_MOCK_ARI_USER", "unowned")
	t.Setenv("HOME_MOCK_ARI_PASSWORD", "test")
	t.Setenv("HOME_MOCK_NONCE", "bad")
	var output bytes.Buffer
	if run(&output) != "MOCK_CONFIG_REFUSED" || output.Len() != 0 {
		t.Fatal("invalid synthetic identity reached ARI")
	}
}
