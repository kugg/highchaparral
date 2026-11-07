package byok

// Durable, fixed-category one-use diagnostics for a separately authorized
// browser call. No identity, password, target, nonce, SIP header or media is
// accepted by this API, serialized or returned from it.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Milestone string

const (
	AdmissionReady    Milestone = "admission-ready"
	BridgeStart       Milestone = "bridge-start"
	BridgeAttached    Milestone = "bridge-attached"
	BridgeRefused     Milestone = "bridge-refused"
	ProviderStart     Milestone = "provider-start"
	RegisterStart     Milestone = "register-start"
	RegisterOK        Milestone = "register-ok"
	RegisterRefused   Milestone = "register-refused"
	InviteStart       Milestone = "invite-start"
	InviteAnswered    Milestone = "invite-answered"
	InviteRefused     Milestone = "invite-refused"
	InviteStatus403   Milestone = "invite-status-403"
	InviteStatus404   Milestone = "invite-status-404"
	InviteStatus480   Milestone = "invite-status-480"
	InviteStatus486   Milestone = "invite-status-486"
	InviteStatus488   Milestone = "invite-status-488"
	InviteStatus500   Milestone = "invite-status-500"
	InviteStatus503   Milestone = "invite-status-503"
	InviteOtherStatus Milestone = "invite-status-other"
	InviteTimeout     Milestone = "invite-timeout"
	InviteOtherError  Milestone = "invite-error-other"
	BrowserAnswered   Milestone = "browser-answered"
	BrowserRefused    Milestone = "browser-answer-refused"
	ByeStart          Milestone = "bye-start"
	ByeOK             Milestone = "bye-ok"
	ByeRefused        Milestone = "bye-refused"
	UnregisterStart   Milestone = "unregister-start"
	UnregisterOK      Milestone = "unregister-ok"
	UnregisterRefused Milestone = "unregister-refused"
	BridgeClosed      Milestone = "bridge-closed"
	BridgeCloseFailed Milestone = "bridge-close-refused"
	CallSettled       Milestone = "call-settled"
	CallAmbiguous     Milestone = "call-ambiguous"
)

var permittedMilestones = map[Milestone]bool{
	AdmissionReady: true, BridgeStart: true, BridgeAttached: true, BridgeRefused: true,
	ProviderStart: true, RegisterStart: true, RegisterOK: true, RegisterRefused: true,
	InviteStart: true, InviteAnswered: true, InviteRefused: true,
	InviteStatus403: true, InviteStatus404: true, InviteStatus480: true,
	InviteStatus486: true, InviteStatus488: true, InviteStatus500: true,
	InviteStatus503: true, InviteOtherStatus: true, InviteTimeout: true,
	InviteOtherError: true,
	BrowserAnswered:  true, BrowserRefused: true, ByeStart: true, ByeOK: true,
	ByeRefused: true, UnregisterStart: true, UnregisterOK: true, UnregisterRefused: true,
	BridgeClosed: true, BridgeCloseFailed: true, CallSettled: true, CallAmbiguous: true,
}

type Milestones struct {
	mu   sync.Mutex
	file *os.File
	bad  bool
}

// OpenMilestones never truncates or reuses a previous attempt. A power loss
// after creation preserves the file and makes an implicit restart fail closed.
func OpenMilestones(dir string) (*Milestones, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("owned milestone directory unavailable")
	}
	path := filepath.Join(dir, "call-milestones-v1")
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("one-use milestone record already exists")
	}
	opened, err := fd.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 ||
		opened.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) ||
		opened.Sys().(*syscall.Stat_t).Nlink != 1 || fd.Sync() != nil {
		_ = fd.Close()
		return nil, errors.New("private milestone record unavailable")
	}
	directory, err := os.Open(dir)
	if err != nil {
		_ = fd.Close()
		return nil, errors.New("milestone directory unavailable")
	}
	err = directory.Sync()
	_ = directory.Close()
	if err != nil {
		_ = fd.Close()
		return nil, errors.New("milestone durability unavailable")
	}
	return &Milestones{file: fd}, nil
}

func (m *Milestones) Close() error {
	if m == nil || m.file == nil {
		return errors.New("milestones unavailable")
	}
	return m.file.Close()
}

func (m *Milestones) Mark(step Milestone) error {
	if m == nil || m.file == nil || !permittedMilestones[step] {
		return errors.New("unreviewed call milestone")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bad {
		return errors.New("milestone delivery ambiguous")
	}
	info, err := m.file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 3900 ||
		info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) ||
		info.Sys().(*syscall.Stat_t).Nlink != 1 {
		m.bad = true
		return errors.New("milestone state unavailable")
	}
	row := time.Now().UTC().Format("2006-01-02T15:04:05Z") + " " + string(step) + "\n"
	if n, err := io.WriteString(m.file, row); err != nil || n != len(row) || m.file.Sync() != nil {
		m.bad = true
		return errors.New("milestone write ambiguous")
	}
	return nil
}
