package main

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/byok"
	"example.com/ata/voip-gateway/internal/provider"
	"example.com/ata/voip-gateway/internal/serviceconfig"
	"example.com/ata/voip-gateway/internal/softphone"
)

const (
	byokRuntime = "/run/voip-gateway"
	byokSocket  = byokRuntime + "/byok.sock"
	byokState   = "/var/lib/voip-gateway/byok-v1"
)

func dirOwned(path string) bool {
	entry, err := os.Lstat(path)
	if err != nil || !entry.IsDir() || entry.Mode().Perm() != 0700 {
		return false
	}
	stat, ok := entry.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid() && int(stat.Gid) == os.Getegid()
}

// runBYOK neither reads a static upstream SIP password nor starts the old
// REGISTER service. Service files/runtime dirs must be pre-owned by a
// separately reviewed deploy stage; the process refuses stale sockets.
func runBYOK(out io.Writer) error {
	if os.Geteuid() != 34567 || os.Getegid() != 34567 ||
		!dirOwned(byokRuntime) || !dirOwned(byokState) {
		return errors.New("nonroot BYOK ownership boundary unavailable")
	}
	config, err := serviceconfig.ReadBYOK()
	if err != nil {
		return errors.New("private BYOK configuration unavailable")
	}
	ariPeer, err := serviceconfig.ReadARIPeerCertificate()
	if err != nil {
		return errors.New("authenticated ARI peer provisioning unavailable")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return errors.New("BYOK system CA roots unavailable")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	bind, err := onlySourceAddress(ctx, config.Host, config.Port)
	if err != nil {
		return errors.New("reviewed IPv4 registrar source unavailable")
	}
	journal, err := byok.OpenJournal(byokState)
	if err != nil {
		return errors.New("private BYOK call history unresolved")
	}
	defer journal.Close()
	milestones, err := byok.OpenMilestones(byokState)
	if err != nil {
		return errors.New("one-use BYOK call progress unavailable")
	}
	defer milestones.Close()
	ari, err := asterisk.New(asterisk.Config{BaseURL: "https://127.0.0.1:8089", PeerCertificate: ariPeer,
		Username: config.ARIUser, Password: config.ARIPassword,
		Timeout: 3 * time.Second, Target: asterisk.BrowserIngress})
	if err != nil {
		return errors.New("local browser ARI unavailable")
	}
	defer ari.Close()
	events, gone, err := ari.SubscribeBrowser(ctx)
	if err != nil {
		return errors.New("browser ARI Stasis subscription unavailable")
	}
	store, err := byok.New(config.Origins[:]...)
	if err != nil {
		return errors.New("exact BYOK HTTPS origins unavailable")
	}
	if _, err := os.Lstat(byokSocket); err == nil || !os.IsNotExist(err) {
		return errors.New("stale/foreign BYOK socket requires review")
	}
	oldMask := syscall.Umask(077)
	listener, err := net.Listen("unix", byokSocket)
	syscall.Umask(oldMask)
	if err != nil {
		return errors.New("BYOK Unix listener unavailable")
	}
	ownedSocket, err := os.Lstat(byokSocket)
	if err != nil {
		_ = listener.Close()
		return errors.New("BYOK Unix socket ownership unavailable")
	}
	info, hasStat := ownedSocket.Sys().(*syscall.Stat_t)
	if !hasStat || ownedSocket.Mode()&os.ModeSocket == 0 ||
		info.Uid != uint32(os.Geteuid()) || info.Gid != uint32(os.Getegid()) || info.Nlink != 1 ||
		os.Chmod(byokSocket, 0600) != nil {
		_ = listener.Close()
		return errors.New("BYOK Unix socket ownership invalid")
	}
	if after, err := os.Lstat(byokSocket); err != nil || !os.SameFile(ownedSocket, after) || after.Mode().Perm() != 0600 {
		_ = listener.Close()
		return errors.New("BYOK Unix socket permissions invalid")
	}
	defer func() {
		_ = listener.Close()
		if actual, e := os.Lstat(byokSocket); e == nil && os.SameFile(actual, ownedSocket) {
			_ = os.Remove(byokSocket) // only the exact inode this process created
			if dir, e := os.Open(filepath.Dir(byokSocket)); e == nil {
				_ = dir.Sync()
				_ = dir.Close()
			}
		}
	}()
	api := &http.Server{Handler: store, ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
		IdleTimeout: time.Second, MaxHeaderBytes: 2048,
		ErrorLog: log.New(io.Discard, "", 0)}
	serveDone := make(chan error, 1)
	go func() { serveDone <- api.Serve(listener) }()
	defer func() {
		stop, finish := context.WithTimeout(context.Background(), 3*time.Second)
		_ = api.Shutdown(stop)
		finish()
	}()
	bridge := &softphone.Bridge{ARI: ari, Milestones: milestones, ProviderProfile: provider.Profile{
		Host: config.Host, TLSName: config.TLSName, Port: int(config.Port),
		BindIPv4: bind, Roots: roots}}
	controller := &softphone.Coordinator{Store: store, Reader: ari, Call: bridge.Call,
		Journal: journal, Milestones: milestones}
	_, _ = io.WriteString(out, "VGW_BYOK_READY\n") // fixed marker, no config/credentials
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-serveDone:
			return errors.New("private BYOK API stopped")
		case <-gone:
			return errors.New("browser ARI subscription stopped")
		case start, ok := <-events:
			if !ok {
				return errors.New("browser Stasis event stream closed")
			}
			if controller.Handle(ctx, start, gone) != nil {
				return errors.New("browser call ambiguous; no automatic replay")
			}
		}
	}
}
