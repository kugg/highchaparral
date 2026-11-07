package byok

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxJournal = 65536

var record = regexp.MustCompile(`^(begin|end) [a-f0-9]{64} [0-9]{10,13}$`)

type Journal struct {
	mu        sync.Mutex
	file      *os.File
	active    string
	uncertain bool
}

func (j *Journal) Close() error {
	if j == nil || j.file == nil {
		return errors.New("BYOK journal unavailable")
	}
	return j.file.Close()
}

// OpenJournal owns a persistent owner0700 directory and one owner0600 file.
// An incomplete begin from power loss/BYE ambiguity blocks ALL future
// provider calls until separately reviewed; it is never auto-truncated.
func OpenJournal(dir string) (*Journal, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return nil, reject()
	}
	path := filepath.Join(dir, "calls.journal")
	fd, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, reject()
	}
	good := false
	defer func() {
		if !good {
			_ = fd.Close()
		}
	}()
	opened, err := fd.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 ||
		opened.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) ||
		opened.Sys().(*syscall.Stat_t).Nlink != 1 || opened.Size() > maxJournal {
		return nil, reject()
	}
	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, reject()
	}
	raw, err := io.ReadAll(io.LimitReader(fd, maxJournal+1))
	if err != nil || len(raw) > maxJournal || len(raw) != int(opened.Size()) {
		return nil, reject()
	}
	if len(raw) != 0 && (!strings.HasSuffix(string(raw), "\n") || strings.Contains(string(raw), "\n\n")) {
		return nil, reject()
	}
	active := ""
	for _, row := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if row == "" {
			continue
		}
		if !record.MatchString(row) {
			return nil, reject()
		}
		fields := strings.Split(row, " ")
		if fields[0] == "begin" {
			if active != "" {
				return nil, reject()
			}
			active = fields[1]
		} else {
			if active != fields[1] {
				return nil, reject()
			}
			active = ""
		}
	}
	if active != "" {
		return nil, reject()
	}
	if _, err := fd.Seek(0, io.SeekEnd); err != nil {
		return nil, reject()
	}
	dirfd, err := os.Open(dir)
	if err != nil {
		return nil, reject()
	}
	if err := dirfd.Sync(); err != nil {
		_ = dirfd.Close()
		return nil, reject()
	}
	_ = dirfd.Close()
	good = true
	return &Journal{file: fd}, nil
}

func journalHash(nonce string) (string, error) {
	if !noncePattern.MatchString(nonce) {
		return "", reject()
	}
	digest := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(digest[:]), nil
}

func (j *Journal) append(action, hash string) error {
	if j.file == nil || j.uncertain {
		return reject()
	}
	meta, err := j.file.Stat()
	if err != nil || meta.Size() > maxJournal-100 || meta.Mode().Perm() != 0600 {
		j.uncertain = true
		return reject()
	}
	if _, err := io.WriteString(j.file, fmt.Sprintf("%s %s %d\n", action, hash, time.Now().UTC().Unix())); err != nil {
		j.uncertain = true
		return reject()
	}
	if err := j.file.Sync(); err != nil {
		j.uncertain = true
		return reject()
	}
	return nil
}

func (j *Journal) Begin(nonce string) error {
	if j == nil {
		return reject()
	}
	hash, err := journalHash(nonce)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.active != "" || j.uncertain {
		return reject()
	}
	if j.append("begin", hash) != nil {
		return reject()
	}
	j.active = hash
	return nil
}

func (j *Journal) End(nonce string) error {
	if j == nil {
		return reject()
	}
	hash, err := journalHash(nonce)
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.active != hash || j.uncertain {
		return reject()
	}
	if j.append("end", hash) != nil {
		return reject()
	}
	j.active = ""
	return nil
}
