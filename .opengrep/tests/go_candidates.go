package candidates

import (
	"context"
	"crypto/tls"
	"os/exec"
)

func candidate(command string) {
	// ruleid: highchaparral.go.dynamic-shell-command
	exec.Command("sh", "-c", command)
	// ruleid: highchaparral.go.dynamic-shell-command
	exec.CommandContext(context.Background(), "bash", "-c", command)
	// ruleid: highchaparral.go.insecure-tls-verification
	_ = tls.Config{InsecureSkipVerify: true}
	// ok: highchaparral.go.dynamic-shell-command
	exec.Command("printf", "%s", command)
	// ok: highchaparral.go.insecure-tls-verification
	_ = tls.Config{MinVersion: tls.VersionTLS13}
}
