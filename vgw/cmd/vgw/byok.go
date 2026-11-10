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

// runBYOK neither reads a static upstream SIP password nor starts the old
// REGISTER service. Service files/runtime dirs must be pre-owned by a
// separately reviewed deploy stage; the process refuses stale sockets.
func runBYOK(out io.Writer, options serviceconfig.RuntimeOptions) (runErr error) {
	if !options.Valid() || os.Geteuid() == 0 || options.GID == 0 ||
		uint32(os.Geteuid()) != options.UID || uint32(os.Getegid()) != options.GID ||
		!serviceconfig.OwnedRuntimeDir(options.RuntimeDir, options.UID, options.GID) ||
		!serviceconfig.OwnedRuntimeDir(options.StateDir, options.UID, options.GID) {
		return errors.New("nonroot BYOK ownership boundary unavailable")
	}
	config, err := serviceconfig.ReadBYOKWithOptions(options)
	if err != nil {
		return errors.New("private BYOK configuration unavailable")
	}
	logFile, err := serviceconfig.OpenErrorLog(config.ErrorLogPath, options.UID, options.GID)
	if err != nil {
		return errors.New("owner-only BYOK log unavailable")
	}
	if logFile != nil {
		defer func() {
			category := "VGW_BYOK_STOPPED"
			if runErr != nil {
				category = "VGW_BYOK_REFUSED"
			}
			if serviceconfig.WriteLogCategory(logFile, category) != nil && runErr == nil {
				runErr = errors.New("bounded BYOK error log unavailable")
			}
			_ = logFile.Close()
		}()
	}
	closePID, err := serviceconfig.OpenPIDFile(options)
	if err != nil {
		return errors.New("owned BYOK PID file unavailable")
	}
	defer func() {
		if closePID() != nil && runErr == nil {
			runErr = errors.New("owned BYOK PID file cleanup incomplete")
		}
	}()
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
	bind, err = selectedBindIPv4(bind, config.BindIPv4)
	if err != nil {
		return errors.New("reviewed SIP bind address unavailable")
	}
	journal, err := byok.OpenJournal(options.StateDir)
	if err != nil {
		return errors.New("private BYOK call history unresolved")
	}
	defer journal.Close()
	milestones, err := byok.OpenMilestones(options.StateDir)
	if err != nil {
		return errors.New("one-use BYOK call progress unavailable")
	}
	defer milestones.Close()
	peer, err := serviceconfig.ReadARIPeerCertificateWithOptions(options)
	if err != nil {
		return errors.New("authenticated ARI peer provisioning unavailable")
	}
	ari, err := asterisk.New(asterisk.Config{BaseURL: config.ARIBaseURL, PeerCertificate: peer,
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
	socketPath := options.SocketPath()
	if _, err := os.Lstat(socketPath); err == nil || !os.IsNotExist(err) {
		return errors.New("stale/foreign BYOK socket requires review")
	}
	oldMask := syscall.Umask(077)
	listener, err := net.Listen("unix", socketPath)
	syscall.Umask(oldMask)
	if err != nil {
		return errors.New("BYOK Unix listener unavailable")
	}
	ownedSocket, err := os.Lstat(socketPath)
	if err != nil {
		_ = listener.Close()
		return errors.New("BYOK Unix socket ownership unavailable")
	}
	info, hasStat := ownedSocket.Sys().(*syscall.Stat_t)
	if !hasStat || ownedSocket.Mode()&os.ModeSocket == 0 ||
		info.Uid != uint32(os.Geteuid()) || info.Gid != uint32(os.Getegid()) || info.Nlink != 1 ||
		os.Chmod(socketPath, 0600) != nil {
		_ = listener.Close()
		return errors.New("BYOK Unix socket ownership invalid")
	}
	if after, err := os.Lstat(socketPath); err != nil || !os.SameFile(ownedSocket, after) || after.Mode().Perm() != 0600 {
		_ = listener.Close()
		return errors.New("BYOK Unix socket permissions invalid")
	}
	defer func() {
		_ = listener.Close()
		if actual, e := os.Lstat(socketPath); e == nil && os.SameFile(actual, ownedSocket) {
			_ = os.Remove(socketPath) // only the exact inode this process created
			if dir, e := os.Open(filepath.Dir(socketPath)); e == nil {
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
		BindIPv4: bind, BindPort: int(config.BindPort), Roots: roots}}
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
