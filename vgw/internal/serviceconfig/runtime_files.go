package serviceconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

func OwnedRuntimeDir(path string, uid, gid uint32) bool {
	if !validAbs(path) || !TrustedAncestors(path, uid) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && owned(info, uid, gid, 0700, false)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return errors.New("owned directory unavailable")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return errors.New("owned directory not durable")
	}
	return nil
}

// OpenPIDFile never chooses a PID: the kernel does. It refuses a stale
// file and returns inode-checked cleanup for the one this process created.
func OpenPIDFile(r RuntimeOptions) (func() error, error) {
	if !r.Valid() || r.UID != uint32(os.Geteuid()) || r.GID != uint32(os.Getegid()) {
		return nil, errors.New("PID-file runtime identity refused")
	}
	if r.PIDFileName == "" {
		return func() error { return nil }, nil
	}
	if !OwnedRuntimeDir(r.RuntimeDir, r.UID, r.GID) {
		return nil, errors.New("PID-file runtime directory unavailable")
	}
	path := r.PIDPath()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("stale or foreign PID file refused")
	}
	_, writeErr := fmt.Fprintf(file, "%d\n", os.Getpid())
	if writeErr != nil || file.Sync() != nil || syncDirectory(r.RuntimeDir) != nil {
		_ = file.Close()
		return nil, errors.New("PID file could not be made durable; inspect before restart")
	}
	before, err := file.Stat()
	_ = file.Close()
	if err != nil || !owned(before, r.UID, r.GID, 0600, true) {
		return nil, errors.New("PID-file ownership changed")
	}
	return func() error {
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, current) || !owned(current, r.UID, r.GID, 0600, true) {
			return errors.New("PID-file concurrent modification refused")
		}
		if os.Remove(path) != nil || syncDirectory(r.RuntimeDir) != nil {
			return errors.New("PID-file cleanup incomplete")
		}
		return nil
	}, nil
}

// OpenErrorLog accepts a pre-owned 0600 file or creates one only in a
// process-owned private dir. An existing root-owned nonwritable /var/log
// parent is allowed when the operator has pre-provisioned the 0600 file.
func OpenErrorLog(path string, uid, gid uint32) (*os.File, error) {
	if path == "" {
		return nil, nil // default: daemon's fixed-category stderr output
	}
	if !validAbs(path) || uid != uint32(os.Geteuid()) || gid != uint32(os.Getegid()) {
		return nil, errors.New("error log path or identity refused")
	}
	parent := filepath.Dir(path)
	if !TrustedAncestors(parent, uid) {
		return nil, errors.New("error log parent untrusted")
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || (!owned(parentInfo, uid, gid, 0700, false) &&
		(!owned(parentInfo, 0, 0, 0755, false) || parentInfo.Mode().Perm()&0022 != 0)) {
		return nil, errors.New("error log directory untrusted")
	}
	before, err := os.Lstat(path)
	if err == nil && !owned(before, uid, gid, 0600, true) {
		return nil, errors.New("error log inode untrusted")
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.New("error log lookup refused")
	}
	if os.IsNotExist(err) && !owned(parentInfo, uid, gid, 0700, false) {
		return nil, errors.New("error log must be pre-provisioned")
	}
	flags := os.O_WRONLY | os.O_APPEND | syscall.O_NOFOLLOW
	if os.IsNotExist(err) {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, openErr := os.OpenFile(path, flags, 0600)
	if openErr != nil {
		return nil, errors.New("error log open refused")
	}
	opened, statErr := file.Stat()
	if statErr != nil || !owned(opened, uid, gid, 0600, true) ||
		(before != nil && !os.SameFile(before, opened)) {
		_ = file.Close()
		return nil, errors.New("error log inode changed")
	}
	if before == nil && syncDirectory(parent) != nil {
		_ = file.Close()
		return nil, errors.New("error log creation not durable")
	}
	return file, nil
}

var fixedLogCategory = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

func WriteLogCategory(file *os.File, category string) error {
	if file == nil {
		return nil
	}
	if !fixedLogCategory.MatchString(category) {
		return errors.New("untrusted error log category refused")
	}
	if _, err := fmt.Fprintf(file, "%s %s\n", time.Now().UTC().Format(time.RFC3339), category); err != nil || file.Sync() != nil {
		return errors.New("bounded error log write unavailable")
	}
	return nil
}
