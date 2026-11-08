package registration

import "testing"

func TestConfiguredSIPSourcePortIsBoundedBeforeAnyREGISTER(t *testing.T) {
	mock := startMock(t)
	settings := config(mock)
	for _, bad := range []int{-1, 65536} {
		settings.BindPort = bad
		if Check(settings) == nil {
			t.Fatal("invalid SIP source port accepted before registration")
		}
	}
	settings.BindPort = 0 // kernel-selected source port remains the default
	if Check(settings) != nil {
		t.Fatal("kernel-selected SIP source port refused")
	}
	settings.BindPort = 15061
	if Check(settings) != nil || mock.registrations.Load() != 0 {
		t.Fatal("bounded custom SIP source port refused or sent a packet")
	}
}
