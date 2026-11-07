// Package callapproval provides an owner-only, one-use numeric target
// reservation for the FIRST attended SPA112/provider call test. It
// does not dial or send a SIP packet. After any ambiguous delivery the
// stage persists and automatic redial is deliberately impossible.
package callapproval

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{7,63}$`)
	numberPattern = regexp.MustCompile(`^[0-9]{2,15}$`)
	hexPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// OpenWrt /var may be backed by /tmp. The release must create this
// vgw-owned directory on the persistent /etc overlay before any call.
const ServiceAttempts = "/etc/voip-gateway/attempts"

type Stage struct {
	Schema     int    `json:"schema"`
	State      string `json:"state"`
	AttemptID  string `json:"attempt_id"`
	TargetHMAC string `json:"target_hmac_sha256"`
	CreatedUTC string `json:"created_utc"`
}

func denied() error { return errors.New("vgw one-use approved call stage invalid") }

func digest(key []byte, number string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(number))
	return hex.EncodeToString(mac.Sum(nil))
}

// Reserve writes only HMAC(privateKey, numeric target), never the number
// or provider credential. Directory must be a dedicated vgw-owned 0700
// path created by a reviewed package/release operation. Any failure after
// creating the file leaves a consumed attempt ID for manual reconciliation.
func Reserve(directory, attemptID, approvedNumber string, privateKey []byte) (string, error) {
	if !idPattern.MatchString(attemptID) || !numberPattern.MatchString(approvedNumber) ||
		len(privateKey) < 16 || len(privateKey) > 256 {
		return "", denied()
	}
	parent, err := os.Lstat(directory)
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return "", denied()
	}
	if meta, ok := parent.Sys().(*syscall.Stat_t); !ok || meta.Uid != uint32(os.Getuid()) {
		return "", denied()
	}
	path := filepath.Join(directory, "attempt-"+attemptID+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", denied()
	}
	defer file.Close()
	data := Stage{Schema: 1, State: "reserved-before-network", AttemptID: attemptID,
		TargetHMAC: digest(privateKey, approvedNumber),
		CreatedUTC: time.Now().UTC().Format(time.RFC3339)}
	if err := json.NewEncoder(file).Encode(data); err != nil {
		return "", denied()
	}
	if err := file.Sync(); err != nil {
		return "", denied()
	}
	opened, err := os.Open(directory)
	if err != nil {
		return "", denied()
	}
	defer opened.Close()
	if err := opened.Sync(); err != nil {
		return "", denied()
	}
	return path, nil
}

// matchTarget is deliberately private: inspecting an approved stage is
// not permission to dial. Commit must succeed before any INVITE.
func matchTarget(stage Stage, dialed string, privateKey []byte) bool {
	if stage.Schema != 1 || stage.State != "reserved-before-network" ||
		!idPattern.MatchString(stage.AttemptID) || !numberPattern.MatchString(dialed) ||
		len(privateKey) < 16 || len(privateKey) > 256 || !hexPattern.MatchString(stage.TargetHMAC) {
		return false
	}
	actual := digest(privateKey, dialed)
	return hmac.Equal([]byte(actual), []byte(stage.TargetHMAC))
}

// Read never logs a target, SIP header or credential and refuses links,
// unowned files, broad modes or a changed source dir. No phone is dialed.
func Read(path string) (Stage, error) {
	var empty Stage
	name := filepath.Base(path)
	if !strings.HasPrefix(name, "attempt-") || !strings.HasSuffix(name, ".json") ||
		len(name) <= len("attempt-")+len(".json") ||
		!idPattern.MatchString(strings.TrimSuffix(strings.TrimPrefix(name, "attempt-"), ".json")) {
		return empty, denied()
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return empty, denied()
	}
	meta, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || meta.Uid != uint32(os.Getuid()) {
		return empty, denied()
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 50 || before.Size() > 1024 {
		return empty, denied()
	}
	old, ok := before.Sys().(*syscall.Stat_t)
	if !ok || old.Uid != uint32(os.Getuid()) || old.Nlink != 1 {
		return empty, denied()
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return empty, denied()
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(before, current) || !current.Mode().IsRegular() ||
		current.Mode().Perm() != 0600 {
		return empty, denied()
	}
	actual, ok := current.Sys().(*syscall.Stat_t)
	if !ok || actual.Uid != uint32(os.Getuid()) || actual.Nlink != 1 {
		return empty, denied()
	}
	contents, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil || len(contents) != int(current.Size()) {
		return empty, denied()
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return empty, denied()
	}
	seen := make(map[string]bool, 5)
	var stage Stage
	for decoder.More() {
		field, err := decoder.Token()
		if err != nil {
			return empty, denied()
		}
		key, ok := field.(string)
		if !ok || seen[key] {
			return empty, denied()
		}
		seen[key] = true
		switch key {
		case "schema":
			err = decoder.Decode(&stage.Schema)
		case "state":
			err = decoder.Decode(&stage.State)
		case "attempt_id":
			err = decoder.Decode(&stage.AttemptID)
		case "target_hmac_sha256":
			err = decoder.Decode(&stage.TargetHMAC)
		case "created_utc":
			err = decoder.Decode(&stage.CreatedUTC)
		default:
			return empty, denied()
		}
		if err != nil {
			return empty, denied()
		}
	}
	end, err := decoder.Token()
	created, timeErr := time.Parse(time.RFC3339, stage.CreatedUTC)
	if err != nil || end != json.Delim('}') || len(seen) != 5 || stage.Schema != 1 ||
		!idPattern.MatchString(stage.AttemptID) ||
		"attempt-"+stage.AttemptID+".json" != name || !hexPattern.MatchString(stage.TargetHMAC) ||
		stage.State != "reserved-before-network" || timeErr != nil ||
		created.UTC().Format(time.RFC3339) != stage.CreatedUTC {
		return empty, denied()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return empty, denied()
	}
	return stage, nil
}

// Commit burns the approved attempt BEFORE any INVITE. A crash or failed
// sync leaves the marker in place, so an ambiguous delivery cannot be
// silently retried. The future call controller must check this error and
// must never place a call directly from Read.
func Commit(path, dialed string, privateKey []byte) error {
	stage, err := Read(path)
	if err != nil || !matchTarget(stage, dialed, privateKey) {
		return denied()
	}
	created, err := time.Parse(time.RFC3339, stage.CreatedUTC)
	if err != nil || created.After(time.Now().Add(time.Minute)) || time.Since(created) > 15*time.Minute {
		return denied()
	}
	marker := path + ".spent"
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return denied()
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return denied()
	}
	if err := file.Close(); err != nil {
		return denied()
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return denied()
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return denied()
	}
	return nil
}
