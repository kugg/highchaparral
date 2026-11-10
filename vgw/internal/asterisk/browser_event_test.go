package asterisk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const validBrowserEvent = `{"type":"StasisStart","application":"eventphone-vgw-browser","args":["browser-demo"],"channel":{"id":"1693496751.43","name":"PJSIP/webrtc-lan-000000ab","dialplan":{"context":"from-webrtc","exten":"e-1234"}}}`

func TestBrowserAdmissionEmitsOnlyLocalChannelIdentity(t *testing.T) {
	result, err := ParseBrowserStart([]byte(validBrowserEvent))
	if err != nil || result.ChannelID != "1693496751.43" || result.Nonce != "" {
		t.Fatal("owned browser ARI event did not yield the local channel id")
	}
	if strings.Contains(result.ChannelID, "e-1234") {
		t.Fatal("browser-supplied dialed digits escaped the ARI boundary")
	}
}

func TestBrowserAdmissionRefusesForeignEndpointsAndInboundInjection(t *testing.T) {
	for _, scenario := range []struct{ before, after string }{
		{`"StasisStart"`, `"ChannelDestroyed"`},
		{`"eventphone-vgw-browser"`, `"eventphone-gateway-lab"`},
		{`"browser-demo"`, `"from-ata"`},
		{`"args":["browser-demo"]`, `"args":["browser-demo","injected\nX-Log: secret"]`},
		{`"from-webrtc"`, `"from-ata"`},
		{`"PJSIP/webrtc-lan-000000ab"`, `"PJSIP/180-000000ab"`},
		{`"1693496751.43"`, `"../channels/other"`},
		{`"1693496751.43"`, `"a..b"`},
		{`"exten":"e-1234"`, `"exten":"1\nAuthorization: injected"`},
	} {
		data := []byte(strings.Replace(validBrowserEvent, scenario.before, scenario.after, 1))
		if _, err := ParseBrowserStart(data); err == nil || strings.Contains(err.Error(), scenario.after) {
			t.Fatal("foreign or untrusted browser event was accepted/reflected")
		}
	}
	if _, err := ParseBrowserStart([]byte(strings.Repeat("A", 4097))); err == nil {
		t.Fatal("oversized ARI event accepted")
	}
}

func TestBrowserARIChannelReadbackDoesNotTrustEventAlone(t *testing.T) {
	const snapshot = `{"id":"1693496751.43","name":"PJSIP/webrtc-lan-000000ab","state":"Ring","dialplan":{"context":"from-webrtc","exten":"e-1234","app_name":"Stasis"}}`
	var response = snapshot
	var nonceValue = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	statusCode := http.StatusOK
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		user, password, ok := r.BasicAuth()
		if r.Method != http.MethodGet || (r.URL.Path != "/ari/channels/1693496751.43" &&
			r.URL.Path != "/ari/channels/1693496751.43/variable") ||
			!ok || user != "synthetic" || password != "only-for-tests" {
			t.Error("unreviewed ARI browser channel readback")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/ari/channels/1693496751.43/variable" {
			if r.URL.Query().Get("variable") != "PJSIP_HEADER(read,X-VGW-Nonce)" {
				t.Error("dynamic ARI header function allowed")
			}
			_, _ = w.Write([]byte(`{"value":"` + nonceValue + `"}`))
			return
		}
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, PeerCertificate: server.Certificate(), Username: "synthetic", Password: "only-for-tests",
		Timeout: time.Second, Target: BrowserIngress})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	start, err := ParseBrowserStart([]byte(validBrowserEvent))
	if err != nil || client.VerifyBrowserChannel(context.Background(), start) != nil || requests != 2 {
		t.Fatal("owned browser channel was not authenticated and read back")
	}
	dial, err := client.ReadBrowserDial(context.Background(), start)
	if err != nil || dial.Destination != "1234" || dial.ChannelID != start.ChannelID ||
		dial.Nonce != nonceValue || requests != 4 {
		t.Fatal("readback did not yield only bounded, routed Eventphone digits")
	}
	response = strings.Replace(snapshot, "from-webrtc", "from-ata", 1)
	if ErrorCategory(client.VerifyBrowserChannel(context.Background(), start)) != "browser-admission" {
		t.Fatal("changed ARI channel context accepted after event")
	}
	response = strings.Replace(snapshot, `"app_name":"Stasis"`, `"app_name":"Dial"`, 1)
	if ErrorCategory(client.VerifyBrowserChannel(context.Background(), start)) != "browser-admission" {
		t.Fatal("browser channel escaped owned Stasis application")
	}
	response = snapshot
	if ErrorCategory(client.VerifyBrowserChannel(context.Background(), BrowserStart{ChannelID: "../foreign"})) != "browser-admission" || requests != 6 {
		t.Fatal("path injection was sent to ARI")
	}
	if ErrorCategory(client.VerifyBrowserChannel(context.Background(), BrowserStart{ChannelID: "a..b"})) != "browser-admission" || requests != 6 {
		t.Fatal("parent path segment reached ARI")
	}
	lab, err := New(Config{BaseURL: server.URL, PeerCertificate: server.Certificate(), Username: "synthetic", Password: "only-for-tests",
		Timeout: time.Second, Target: LabEcho})
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	if ErrorCategory(lab.VerifyBrowserChannel(context.Background(), start)) != "browser-admission" || requests != 6 {
		t.Fatal("lab adapter accepted a browser channel")
	}
	nonceValue = "forged\r\nX-Log: injected"
	_, err = client.ReadBrowserDial(context.Background(), start)
	if ErrorCategory(err) != "browser-admission" {
		t.Fatal("hostile ARI header value became BYOK nonce")
	}
	nonceValue = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	statusCode = http.StatusNotFound
	if class, err := client.BrowserChannelClass(context.Background(), start); err != nil || class != "gone" {
		t.Fatal("confirmed missing browser channel was not classified as a hangup")
	}
	statusCode = http.StatusServiceUnavailable
	if class, err := client.BrowserChannelClass(context.Background(), start); err == nil || class != "" {
		t.Fatal("ARI outage was confused with a browser hangup")
	}
}
