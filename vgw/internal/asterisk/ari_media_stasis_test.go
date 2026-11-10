package asterisk

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestOwnedMediaBridgeRetriesOnlyTransientUnprocessable(t *testing.T) {
	calls := 0
	err := waitForOwnedMediaStasis(context.Background(), time.Second,
		func(context.Context) (int, error) {
			calls++
			if calls == 1 {
				return http.StatusUnprocessableEntity, nil
			}
			return http.StatusNoContent, nil
		})
	if err != nil || calls != 2 {
		t.Fatal("owned media Stasis transition was not bounded")
	}
}

func TestOwnedMediaBridgeDoesNotRetryUnknownOrForeignResponse(t *testing.T) {
	for _, tc := range []struct {
		status int
		err    error
	}{
		{http.StatusNotFound, nil},
		{http.StatusConflict, nil},
		{http.StatusUnprocessableEntity, errors.New("transport unknown")},
	} {
		calls := 0
		err := waitForOwnedMediaStasis(context.Background(), time.Second,
			func(context.Context) (int, error) {
				calls++
				return tc.status, tc.err
			})
		if err == nil || calls != 1 {
			t.Fatal("foreign or ambiguous media add was retried")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	if waitForOwnedMediaStasis(ctx, 100*time.Millisecond, func(context.Context) (int, error) {
		calls++
		return http.StatusUnprocessableEntity, nil
	}) == nil || calls > 1 {
		t.Fatal("cancelled media add was not bounded")
	}
}
