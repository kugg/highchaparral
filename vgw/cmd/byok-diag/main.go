// byok-diag is a bounded, read-only jailed-prerequisite probe for a failed
// service start. It never registers, invites, prints config or sends media.
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/user"
	"syscall"
	"time"

	"example.com/ata/voip-gateway/internal/serviceconfig"
)

func owned(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 34567 && st.Gid == 34567
}

func main() {
	if len(os.Args) != 1 || os.Geteuid() != 34567 || os.Getegid() != 34567 {
		fmt.Println("DIAG_IDENTITY_REFUSED")
		return
	}
	config, err := serviceconfig.ReadBYOK()
	if err != nil {
		group, lookup := user.LookupGroup("vgw")
		if lookup != nil || group.Gid != "34567" {
			fmt.Println("DIAG_GROUP_REFUSED")
			return
		}
		dir, dirErr := os.Lstat("/etc/voip-gateway")
		if dirErr != nil || !dir.IsDir() || dir.Mode().Perm() != 0750 ||
			dir.Sys().(*syscall.Stat_t).Uid != 0 || dir.Sys().(*syscall.Stat_t).Gid != 34567 {
			fmt.Println("DIAG_CONFIG_DIR_REFUSED")
			return
		}
		file, fileErr := os.Lstat("/etc/voip-gateway/byok.config")
		if fileErr != nil || !file.Mode().IsRegular() || file.Mode().Perm() != 0640 ||
			file.Sys().(*syscall.Stat_t).Uid != 0 || file.Sys().(*syscall.Stat_t).Gid != 34567 {
			fmt.Println("DIAG_CONFIG_INODE_REFUSED")
			return
		}
		raw, readErr := os.ReadFile("/etc/voip-gateway/byok.config")
		if readErr != nil {
			fmt.Println("DIAG_CONFIG_READ_REFUSED")
			return
		}
		if _, parseErr := serviceconfig.ParseBYOK(raw); parseErr != nil {
			fmt.Println("DIAG_CONFIG_PARSE_REFUSED")
			return
		}
		fmt.Println("DIAG_CONFIG_REFUSED")
		return
	}
	fmt.Println("DIAG_CONFIG_PASS")
	if !owned("/run/voip-gateway") || !owned("/var/lib/voip-gateway/byok-v1") {
		fmt.Println("DIAG_DIRECTORIES_REFUSED")
		return
	}
	fmt.Println("DIAG_DIRECTORIES_PASS")
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil || len(pool.Subjects()) == 0 {
		fmt.Println("DIAG_CA_REFUSED")
		return
	}
	fmt.Println("DIAG_CA_PASS")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, config.Host)
	if err != nil || len(addresses) == 0 || len(addresses) > 16 {
		fmt.Println("DIAG_DNS_REFUSED")
		return
	}
	fmt.Println("DIAG_DNS_PASS")
	for _, addr := range addresses {
		if addr.IP.To4() == nil || addr.IP.IsUnspecified() || addr.IP.IsMulticast() || addr.IP.IsLinkLocalUnicast() {
			continue
		}
		conn, dialErr := net.DialUDP("udp", nil, &net.UDPAddr{IP: addr.IP, Port: int(config.Port)})
		if dialErr == nil {
			_ = conn.Close() // selects source address; emits NO packet
			fmt.Println("DIAG_SOURCE_PASS")
			return
		}
	}
	fmt.Println("DIAG_SOURCE_REFUSED")
}
