package main

import (
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
)

const jailedConfig = "/etc/epgateway-twin/ari.env"

func parseARIConfig(raw []byte) (string, string, error) {
	if len(raw) < 32 || len(raw) > 1024 || strings.ContainsAny(string(raw), "\r\x00") {
		return "", "", errors.New("guest-only ARI configuration invalid")
	}
	var user, password string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 || strings.Contains(pair[1], "=") {
			return "", "", errors.New("guest-only ARI configuration invalid")
		}
		switch pair[0] {
		case "GATEWAY_LAB_ARI_USER":
			if user != "" {
				return "", "", errors.New("guest-only ARI configuration ambiguous")
			}
			user = pair[1]
		case "GATEWAY_LAB_ARI_PASSWORD":
			if password != "" {
				return "", "", errors.New("guest-only ARI configuration ambiguous")
			}
			password = pair[1]
		default:
			return "", "", errors.New("guest-only ARI configuration invalid")
		}
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(user) ||
		!regexp.MustCompile(`^[a-zA-Z0-9_-]{16,256}$`).MatchString(password) {
		return "", "", errors.New("guest-only ARI configuration invalid")
	}
	return user, password, nil
}

func readARIConfig() (string, string, error) {
	path := os.Getenv("GATEWAY_LAB_CONFIG_FILE")
	if path == "" {
		return os.Getenv("GATEWAY_LAB_ARI_USER"), os.Getenv("GATEWAY_LAB_ARI_PASSWORD"), nil
	}
	if path != jailedConfig || os.Getenv("GATEWAY_LAB_ARI_USER") != "" ||
		os.Getenv("GATEWAY_LAB_ARI_PASSWORD") != "" {
		return "", "", errors.New("conflicting guest-only ARI credential sources")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", "", errors.New("guest-only ARI configuration unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024 || info.Size() < 32 ||
		info.Mode().Perm() != 0640 || info.Sys().(*syscall.Stat_t).Gid != 450 {
		return "", "", errors.New("guest-only ARI configuration ownership invalid")
	}
	buf := make([]byte, info.Size())
	if n, err := io.ReadFull(f, buf); err != nil || int64(n) != info.Size() {
		return "", "", errors.New("guest-only ARI configuration unreadable")
	}
	return parseARIConfig(buf)
}
