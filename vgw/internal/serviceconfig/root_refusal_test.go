package serviceconfig

import (
	"flag"
	"io"
	"testing"
)

func nonZeroOptions() RuntimeOptions {
	return RuntimeOptions{
		UID: 700, GID: 700,
		ConfigPath: "/etc/voip-gateway/config",
		RuntimeDir: "/run/voip-gateway",
		StateDir:   "/var/lib/voip-gateway/byok-v1",
		SocketName: "byok.sock",
		OfficePort: 5061,
	}
}

func TestValidRejectsRootUID(t *testing.T) {
	r := nonZeroOptions()
	r.UID = 0
	if r.Valid() {
		t.Fatal("Valid() accepted UID 0; non-root lower bound missing")
	}
}

func TestValidRejectsRootGID(t *testing.T) {
	r := nonZeroOptions()
	r.GID = 0
	if r.Valid() {
		t.Fatal("Valid() accepted GID 0; non-root lower bound missing")
	}
}

func TestValidRejectsRootUIDAndGID(t *testing.T) {
	r := nonZeroOptions()
	r.UID, r.GID = 0, 0
	if r.Valid() {
		t.Fatal("Valid() accepted UID/GID 0; non-root lower bound missing")
	}
}

func TestValidAcceptsNonZeroIdentity(t *testing.T) {
	if !nonZeroOptions().Valid() {
		t.Fatal("Valid() refused a legitimate non-zero service identity")
	}
}

func TestRunUIDZeroRefusedByLaunchFlags(t *testing.T) {
	fs := flag.NewFlagSet("repair", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fl := BindRuntimeFlags(fs, DefaultRuntimeOptions())
	if err := fs.Parse([]string{"--run-uid=0"}); err != nil {
		t.Fatalf("flag parse failed: %v", err)
	}
	if _, err := fl.Options(); err == nil {
		t.Fatal("--run-uid=0 accepted; launch flags must refuse a root service identity")
	}
}

func TestRunGIDZeroRefusedByLaunchFlags(t *testing.T) {
	fs := flag.NewFlagSet("repair", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fl := BindRuntimeFlags(fs, DefaultRuntimeOptions())
	if err := fs.Parse([]string{"--run-gid=0"}); err != nil {
		t.Fatalf("flag parse failed: %v", err)
	}
	if _, err := fl.Options(); err == nil {
		t.Fatal("--run-gid=0 accepted; launch flags must refuse a root service identity")
	}
}
