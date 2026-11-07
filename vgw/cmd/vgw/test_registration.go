package main

// One-use *development* registration with the owner-only hg.eventphone.de
// test account. This command never places an INVITE, never copies the test
// password into an image or argv, and is not an office EPVPN identity.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"example.com/ata/voip-gateway/internal/registration"
	"example.com/ata/voip-gateway/internal/serviceconfig"
)

const (
	testRegistrar = "hg.eventphone.de"
	testFile      = "../../../../ata/webrtc/gateway/eventphone_creds"
	testStage     = "../../../state/vgw-test-register-once-v1"
)

type devCredentials struct{ user, password string }

func (devCredentials) String() string   { return "test provider credential [redacted]" }
func (devCredentials) GoString() string { return "devCredentials{redacted}" }

func readDevCredentials(path string) (devCredentials, error) {
	var empty devCredentials
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 ||
		before.Size() < 30 || before.Size() > 1024 {
		return empty, errors.New("private development credential unavailable")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return empty, errors.New("private development credential unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) || info.Mode().Perm() != 0600 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) ||
		info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return empty, errors.New("private development credential ownership changed")
	}
	raw := make([]byte, before.Size())
	if n, err := io.ReadFull(f, raw); err != nil || n != len(raw) {
		return empty, errors.New("private development credential unreadable")
	}
	return parseDevCredentials(raw)
}

func parseDevCredentials(raw []byte) (devCredentials, error) {
	var empty devCredentials
	if len(raw) < 30 || len(raw) > 1024 || strings.ContainsAny(string(raw), "\r\x00") {
		return empty, errors.New("invalid development credential shape")
	}
	rows := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(rows) != 3 {
		return empty, errors.New("invalid development credential shape")
	}
	fields := make(map[string]string, 3)
	for _, row := range rows {
		key, val, ok := strings.Cut(row, ": ")
		if !ok || len(val) == 0 || len(val) > 256 {
			return empty, errors.New("invalid development credential shape")
		}
		for i := 0; i < len(val); i++ {
			if val[i] < 0x21 || val[i] > 0x7e {
				return empty, errors.New("invalid development credential shape")
			}
		}
		if key == "SIP-Registrar" || key == "Server/Registrar" {
			key = "host"
		} else if key == "SIP-Identity" || key == "AuthUser" {
			key = "user"
		} else if key == "SIP-Password" || key == "Password" {
			key = "pass"
		} else {
			return empty, errors.New("invalid development credential shape")
		}
		if fields[key] != "" {
			return empty, errors.New("ambiguous development credential fields")
		}
		fields[key] = val
	}
	if fields["host"] != testRegistrar || !regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`).MatchString(fields["user"]) ||
		fields["pass"] == "" {
		return empty, errors.New("development credential host or identity refused")
	}
	return devCredentials{user: fields["user"], password: fields["pass"]}, nil
}

func ownerDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("development stage ownership unavailable")
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return errors.New("development stage unavailable")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return errors.New("development stage not durable")
	}
	return nil
}

func privateJSON(dir, name string, value any) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("development result already exists or unavailable")
	}
	defer f.Close()
	if json.NewEncoder(f).Encode(value) != nil || f.Sync() != nil || syncDir(dir) != nil {
		return errors.New("development result not durable")
	}
	return nil
}

func reserveTestRegister(dir string) error {
	parent := filepath.Dir(dir)
	if ownerDir(parent) != nil {
		return errors.New("private development stage parent unavailable")
	}
	if os.Mkdir(dir, 0700) != nil {
		return errors.New("development registration already reserved; no replay")
	}
	if err := privateJSON(dir, "attempt.json", struct {
		State string `json:"state"`
		Time  string `json:"created_at"`
	}{"attempt_reserved_before_provider_network", time.Now().UTC().Format(time.RFC3339)}); err != nil {
		return err
	}
	return syncDir(parent)
}

func checkTestRegisterCredentials(out io.Writer) error {
	if _, err := readDevCredentials(testFile); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "VGW_TEST_CREDENTIAL_SHAPE_ACCEPTED_NO_NETWORK")
	return nil
}

func reportTestRegisterStatus(out io.Writer) error {
	if _, err := os.Lstat(testStage); os.IsNotExist(err) {
		_, _ = fmt.Fprintln(out, "VGW_TEST_REGISTER_NO_STAGE")
		return nil
	} else if err != nil || ownerDir(testStage) != nil {
		return errors.New("development registration stage unavailable")
	}
	path := filepath.Join(testStage, "result.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		_, _ = fmt.Fprintln(out, "VGW_TEST_REGISTER_ATTEMPT_RESERVED")
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		info.Size() > 512 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("development registration result unavailable")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("development registration result unavailable")
	}
	defer f.Close()
	var result struct {
		Category string `json:"category"`
	}
	if json.NewDecoder(io.LimitReader(f, 513)).Decode(&result) != nil {
		return errors.New("development registration result invalid")
	}
	switch result.Category {
	case "registered-and-unregistered", "registered-unregister-unconfirmed", "register-unconfirmed", "local-source-unavailable":
		_, _ = fmt.Fprintln(out, "VGW_TEST_REGISTER_"+strings.ToUpper(strings.ReplaceAll(result.Category, "-", "_")))
		return nil
	default:
		return errors.New("development registration result invalid")
	}
}

func runTestRegisterOnce(out io.Writer) error {
	credentials, err := readDevCredentials(testFile)
	if err != nil {
		return err
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return errors.New("development CA roots unavailable")
	}
	service := serviceconfig.Config{UpstreamHost: testRegistrar, UpstreamPort: 5061,
		UpstreamTLSName: testRegistrar, UpstreamUsername: credentials.user,
		UpstreamPassword: credentials.password, CAOnly: true}
	tlsPolicy, err := serviceconfig.TLSClient(service, roots)
	if err != nil {
		return errors.New("development TLS policy unavailable")
	}
	if err := reserveTestRegister(testStage); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	category := "register-unconfirmed"
	registered, unregistered := false, false
	local, err := onlySourceAddress(ctx, testRegistrar, 5061)
	if err != nil {
		category = "local-source-unavailable"
	} else {
		result, _ := registration.RegisterOnce(ctx, registration.Config{
			Host: testRegistrar, BindHost: local, Port: 5061,
			ServerName: testRegistrar, Roots: roots, TLS: tlsPolicy,
			Username: credentials.user, Password: credentials.password,
			Expiry: 90 * time.Second, Refresh: 45 * time.Second,
			RetryMin: 2 * time.Second, RetryMax: 10 * time.Second, Timeout: 5 * time.Second,
		})
		registered, unregistered = result.Registered, result.Unregistered
		if registered && unregistered {
			category = "registered-and-unregistered"
		} else if registered {
			category = "registered-unregister-unconfirmed"
		}
	}
	if err := privateJSON(testStage, "result.json", struct {
		Category     string `json:"category"`
		Registered   bool   `json:"registered"`
		Unregistered bool   `json:"unregistered"`
	}{category, registered, unregistered}); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "VGW_TEST_REGISTER_"+strings.ToUpper(strings.ReplaceAll(category, "-", "_")))
	if category != "registered-and-unregistered" {
		return errors.New("development REGISTER requires manual result review; no replay")
	}
	return nil
}
