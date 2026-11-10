//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

func TestFixedGuestOnlyDefault(t *testing.T) {
	if _, err := request(0); err == nil {
		t.Fatal("no private interface was accepted")
	}
	packet, err := request(7)
	if err != nil || len(packet) != 44 || binary.LittleEndian.Uint16(packet[4:6]) != syscall.RTM_NEWROUTE ||
		binary.LittleEndian.Uint32(packet[40:44]) != 7 ||
		binary.LittleEndian.Uint16(packet[30:32]) != syscall.RTA_GATEWAY ||
		binary.LittleEndian.Uint16(packet[38:40]) != syscall.RTA_OIF ||
		net.IP(packet[32:36]).String() != gateway || packet[20] != 254 {
		t.Fatal("owned internal gateway request changed")
	}
}
