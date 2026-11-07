package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

func stageDir(testID string) (string, error) {
	switch testID {
	case "first":
		return "secrets/attended-provider", nil
	case "maze":
		return "secrets/attended-provider-maze", nil
	case "announcement":
		return "secrets/attended-provider-announcement-v1", nil
	default:
		return "", errors.New("unreviewed one-use provider test identity")
	}
}

// prepareAutomatedTarget is a local, private one-use approval for the
// operator-reviewed public automated extension. No number is in source
// or logs. This is not a call and never sends a SIP packet.
func prepareAutomatedTarget(dirName, target string) error {
	if !regexp.MustCompile(`^[0-9]{2,5}$`).MatchString(target) {
		return errors.New("unreviewed automated target")
	}
	if err := os.Mkdir("secrets", 0700); err != nil && !os.IsExist(err) {
		return errors.New("private automated approval parent unavailable")
	}
	parent, err := os.Lstat("secrets")
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 ||
		parent.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("private automated approval parent changed")
	}
	if err := os.Mkdir(dirName, 0700); err != nil {
		return errors.New("one-use automated target stage already exists")
	}
	file, err := os.OpenFile(filepath.Join(dirName, "approved_target"),
		os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("private automated target record unavailable")
	}
	defer file.Close()
	if n, err := file.WriteString(target + "\n"); err != nil || n != len(target)+1 || file.Sync() != nil {
		return errors.New("private automated target record incomplete")
	}
	dir, err := os.Open(dirName)
	if err != nil {
		return errors.New("private automated target directory unavailable")
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return errors.New("private automated target durability unavailable")
	}
	parentDir, err := os.Open("secrets")
	if err != nil {
		return errors.New("private automated approval parent unavailable")
	}
	defer parentDir.Close()
	if err := parentDir.Sync(); err != nil {
		return errors.New("private automated approval parent durability unavailable")
	}
	return nil
}

func requireAutomatedTarget(dirName, target string) error {
	if !regexp.MustCompile(`^[0-9]{2,5}$`).MatchString(target) {
		return errors.New("unreviewed automated target")
	}
	dir, err := os.Lstat(dirName)
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 ||
		dir.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("private automated target stage changed")
	}
	f, err := os.OpenFile(filepath.Join(dirName, "approved_target"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("private automated target unavailable")
	}
	defer f.Close()
	meta, err := f.Stat()
	if err != nil || !meta.Mode().IsRegular() || meta.Mode().Perm() != 0600 ||
		meta.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) ||
		meta.Sys().(*syscall.Stat_t).Nlink != 1 || meta.Size() != int64(len(target)+1) {
		return errors.New("private automated target changed")
	}
	raw := make([]byte, meta.Size())
	if _, err := io.ReadFull(f, raw); err != nil || string(raw) != target+"\n" {
		return errors.New("private automated target mismatch")
	}
	return nil
}

// reserveAttempt is deliberately irreversible by this binary. A stage on
// disk, even without a result, means delivery may have been ambiguous.
// Repeating the command cannot place another call without a separate
// manual review outside this one-use test harness.
func reserveAttempt(dirName string) error {
	if err := os.Mkdir("secrets", 0700); err != nil && !os.IsExist(err) {
		return errors.New("one-use private test parent unavailable")
	}
	parent, err := os.Lstat("secrets")
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
		return errors.New("one-use private test parent not owner-only")
	}
	if err := os.Mkdir(dirName, 0700); err != nil && !os.IsExist(err) {
		return errors.New("one-use provider stage unavailable")
	}
	dir, err := os.Lstat(dirName)
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 {
		return errors.New("one-use provider stage not owner-only")
	}
	file, err := os.OpenFile(filepath.Join(dirName, "attempt.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("provider attempt already reserved; never auto-redial")
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(map[string]any{
		"state": "attempt_reserved_before_network", "created_at": time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return errors.New("one-use provider attempt record incomplete")
	}
	if err := file.Sync(); err != nil {
		return errors.New("one-use provider attempt record not durable")
	}
	parentDir, err := os.Open(dirName)
	if err != nil {
		return errors.New("one-use provider stage sync unavailable")
	}
	defer parentDir.Close()
	if err := parentDir.Sync(); err != nil {
		return errors.New("one-use provider stage sync failed")
	}
	return nil
}

func recordResult(dirName, category string, result outcome) error {
	file, err := os.OpenFile(filepath.Join(dirName, "result.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("provider one-use result already recorded or unavailable")
	}
	defer file.Close()
	// No account identity, registrar header, IP, SDP, credential or media.
	if err := json.NewEncoder(file).Encode(struct {
		Category       string `json:"category"`
		Registered     bool   `json:"registered"`
		RegisterStatus int    `json:"register_status"`
		InviteStatus   int    `json:"invite_status"`
		Answered       bool   `json:"answered"`
		MediaReturned  bool   `json:"media_returned"`
		BYE            bool   `json:"bye"`
		Unregistered   bool   `json:"unregistered"`
	}{category, result.registered, result.registerStatus, result.inviteStatus,
		result.answered, result.received, result.bye, result.unregistered}); err != nil {
		return errors.New("provider one-use result record incomplete")
	}
	if err := file.Sync(); err != nil {
		return errors.New("provider one-use result not durable")
	}
	dir, err := os.Open(dirName)
	if err != nil {
		return errors.New("provider one-use result stage unavailable")
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return errors.New("provider one-use result stage sync failed")
	}
	return nil
}
