// One synthetic browser regression launcher using the existing inventoried
// ari-browser-probe caller. No new ARI client constructor or provider socket.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sync/atomic"
	"time"

	"example.com/ata/voip-gateway/internal/regressionutil"
)

var syntheticNonce = regexp.MustCompile(`^[a-f0-9]{32}$`)
var syntheticPassword = regexp.MustCompile(`^[A-Za-z0-9_-]{32,64}$`)

// Existing assertions exercise the SAME bounded check used by the
// inventoried ari-browser-probe regression mode, without a second caller.
func waitForZero(ctx context.Context, get func(context.Context, string) (int, []byte, error)) bool {
	return regressionutil.WaitForZero(ctx, get)
}

// Child stderr is never logged. The first byte aborts the exact child;
// even a library error cannot be silently ignored on an otherwise green run.
type stderrGate struct {
	child *exec.Cmd
	seen  atomic.Bool
}

func (gate *stderrGate) Write(data []byte) (int, error) {
	if len(data) != 0 {
		gate.seen.Store(true)
		if gate.child.Process != nil {
			_ = gate.child.Process.Kill()
		}
	}
	return len(data), nil
}

func run(out io.Writer) string {
	if os.Getenv("HOME_MOCK_ARI_USER") != "home-control" ||
		!syntheticPassword.MatchString(os.Getenv("HOME_MOCK_ARI_PASSWORD")) ||
		!syntheticNonce.MatchString(os.Getenv("HOME_MOCK_NONCE")) {
		return "MOCK_CONFIG_REFUSED"
	}
	ctx, stop := context.WithTimeout(context.Background(), 65*time.Second)
	defer stop()
	child := exec.CommandContext(ctx, "/usr/local/bin/ari-browser-probe", "--synthetic-regression")
	gate := &stderrGate{child: child}
	child.Stdin, child.Stderr = nil, gate
	pipe, err := child.StdoutPipe()
	if err != nil || child.Start() != nil {
		return "MOCK_PROBE_REFUSED"
	}
	last := "MOCK_PROBE_REFUSED"
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 128), 256) // fixed category lines only
	for scanner.Scan() {
		line := scanner.Text()
		switch line {
		case "MOCK_WATCHER_READY", "MOCK_BROWSER_ADMITTED", "MOCK_ATTACH_OK", "MOCK_PROVIDER_200_ANSWERED":
			_, _ = fmt.Fprintln(out, line)
		case "MOCK_PROVIDER_SETTLED_LOCAL_ONLY", "MOCK_CLEANUP_UNKNOWN", "MOCK_CONFIG_REFUSED",
			"MOCK_NO_BROWSER_CHANNEL", "MOCK_SUBSCRIPTION_GONE", "MOCK_BROWSER_ADMISSION_REFUSED",
			"MOCK_MEDIA_SOCKET_REFUSED", "MOCK_ATTACH_REFUSED", "MOCK_RELAY_REFUSED",
			"MOCK_ANSWER_REFUSED", "MOCK_AUDIO_BUFFER_REFUSED", "MOCK_DIALOG_UNCERTAIN",
			"MOCK_RESOURCE_CLEANUP_REFUSED":
			last = line
		default:
			_ = child.Process.Kill()
			_ = child.Wait()
			return "MOCK_PROBE_REFUSED" // never echo or forgive raw child/ARI/SIP text
		}
	}
	if scanner.Err() != nil {
		_ = child.Process.Kill() // includes overlong lines; do not wait for child timeout
		_ = child.Wait()
		return "MOCK_PROBE_REFUSED"
	}
	if child.Wait() != nil || ctx.Err() != nil || gate.seen.Load() {
		return "MOCK_PROBE_REFUSED"
	}
	return last
}

func main() { fmt.Println(run(os.Stdout)) }
