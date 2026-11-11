//go:build linux

// A fixed default only in the caller's verified, private container namespace.
// The runner verifies the Docker bridge is Internal=true, grants NET_ADMIN
// solely to this short-lived helper and removes it before SIP starts.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
)

const (
	interfaceName = "eth0"
	localCIDR     = "10.254.251.0/24"
	gateway       = "10.254.251.1"
)

func request(index int) ([]byte, error) {
	if index <= 0 {
		return nil, errors.New("private bridge interface missing")
	}
	gw := net.ParseIP(gateway).To4()
	if gw == nil {
		return nil, errors.New("fixed internal gateway invalid")
	}
	msg := make([]byte, 44) // nlmsghdr, rtmsg, RTA_GATEWAY, RTA_OIF
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:6], syscall.RTM_NEWROUTE)
	binary.LittleEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL)
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	msg[16], msg[20], msg[21], msg[22], msg[23] = syscall.AF_INET, 254, 4, 0, 1
	binary.LittleEndian.PutUint16(msg[28:30], 8)
	binary.LittleEndian.PutUint16(msg[30:32], syscall.RTA_GATEWAY)
	copy(msg[32:36], gw)
	binary.LittleEndian.PutUint16(msg[36:38], 8)
	binary.LittleEndian.PutUint16(msg[38:40], syscall.RTA_OIF)
	binary.LittleEndian.PutUint32(msg[40:44], uint32(index))
	return msg, nil
}

func run() error {
	if len(os.Args) != 1 {
		return errors.New("unexpected helper arguments")
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return errors.New("private bridge interface unavailable")
	}
	_, network, err := net.ParseCIDR(localCIDR)
	if err != nil {
		return errors.New("fixed private subnet invalid")
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return errors.New("private bridge address unavailable")
	}
	valid := false
	for _, address := range addresses {
		if host, ok := address.(*net.IPNet); ok && network.Contains(host.IP) &&
			host.IP.String() != gateway && host.Mask.String() == network.Mask.String() {
			valid = true
		}
	}
	if !valid {
		return errors.New("private bridge identity changed")
	}
	before, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return errors.New("private routing readback refused")
	}
	for _, line := range strings.Split(string(before), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[1] == "00000000" {
			return errors.New("private default already exists")
		}
	}
	packet, err := request(iface.Index)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return errors.New("private netlink unavailable")
	}
	defer syscall.Close(fd)
	if syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}) != nil ||
		syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
			&syscall.Timeval{Sec: 2}) != nil ||
		syscall.Sendto(fd, packet, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}) != nil {
		return errors.New("private default request refused")
	}
	ack := make([]byte, 128)
	n, _, err := syscall.Recvfrom(fd, ack, 0)
	if err != nil || n < 20 || binary.LittleEndian.Uint16(ack[4:6]) != syscall.NLMSG_ERROR ||
		binary.LittleEndian.Uint32(ack[8:12]) != 1 || binary.LittleEndian.Uint32(ack[16:20]) != 0 {
		return errors.New("private default acknowledgement refused")
	}
	after, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return errors.New("private default verification refused")
	}
	for _, line := range strings.Split(string(after), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 2 && fields[0] == interfaceName && fields[1] == "00000000" && fields[2] == "01FBFE0A" {
			return nil
		}
	}
	return errors.New("private default missing after ACK")
}

func main() {
	if run() != nil {
		fmt.Println("MOCK_INTERNAL_DEFAULT_REFUSED")
		os.Exit(2)
	}
	fmt.Println("MOCK_INTERNAL_DEFAULT_READY")
}
