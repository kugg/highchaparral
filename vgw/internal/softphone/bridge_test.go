package softphone

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/byok"
	"example.com/ata/voip-gateway/internal/calls"
	"example.com/ata/voip-gateway/internal/provider"
)

func TestBrowserBridgeCleansOnlyOwnedResourcesAndAnswersAfterProvider(t *testing.T) {
	const browserID = "1693496751.43"
	var mu sync.Mutex
	var bridgeID, mediaID string
	var answerCount, bridgeRemoved, mediaRemoved, browserRemoved int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		user, pass, auth := r.BasicAuth()
		if !auth || user != "synthetic" || pass != "only-for-tests" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case r.Method == http.MethodGet && path == "/ari/channels/"+browserID:
			_, _ = w.Write([]byte(`{"id":"1693496751.43","name":"PJSIP/webrtc-lan-000000ab","state":"Ring","dialplan":{"context":"from-webrtc","exten":"e-1234","app_name":"Stasis"}}`))
		case r.Method == http.MethodGet && path == "/ari/channels/"+browserID+"/variable":
			if r.URL.Query().Get("variable") != "PJSIP_HEADER(read,X-VGW-Nonce)" {
				t.Error("dynamic SIP header lookup accepted")
			}
			_, _ = w.Write([]byte(`{"value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(path, "/ari/bridges/b-") && !strings.Contains(path, "/addChannel"):
			bridgeID = strings.TrimPrefix(path, "/ari/bridges/")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": bridgeID})
		case r.Method == http.MethodPost && path == "/ari/channels/externalMedia":
			mediaID = r.URL.Query().Get("channelId")
			if r.URL.Query().Get("app") != "eventphone-vgw-browser" ||
				r.URL.Query().Get("format") != "alaw" ||
				!strings.HasPrefix(r.URL.Query().Get("external_host"), "127.0.0.1:") {
				t.Error("unreviewed browser ExternalMedia target")
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": mediaID})
		case r.Method == http.MethodGet && path == "/ari/channels/"+mediaID+"/variable":
			value := "127.0.0.1"
			if r.URL.Query().Get("variable") == "UNICASTRTP_LOCAL_PORT" {
				value = "39001"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"value": value})
		case r.Method == http.MethodPost && path == "/ari/bridges/"+bridgeID+"/addChannel":
			if ch := r.URL.Query().Get("channel"); ch != mediaID && ch != browserID {
				t.Error("bridge added foreign channel")
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && path == "/ari/bridges/"+bridgeID:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": bridgeID, "channels": []string{mediaID, browserID}})
		case r.Method == http.MethodPost && path == "/ari/channels/"+browserID+"/answer":
			answerCount++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && path == "/ari/channels/"+browserID:
			browserRemoved++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && path == "/ari/channels/"+mediaID:
			mediaRemoved++
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && path == "/ari/bridges/"+bridgeID:
			bridgeRemoved++
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ari, err := asterisk.New(asterisk.Config{BaseURL: server.URL, PeerCertificate: server.Certificate(),
		Username: "synthetic", Password: "only-for-tests", Target: asterisk.BrowserIngress,
		Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ari.Close()
	called := false
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private milestone stage unavailable")
	}
	milestones, err := byok.OpenMilestones(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer milestones.Close()
	bridge := &Bridge{ARI: ari, Milestones: milestones, Connector: func(ctx context.Context, p provider.Profile,
		creds byok.Credentials, id string, fromARI <-chan calls.AudioFrame,
		toARI chan<- calls.AudioFrame) (bool, error) {
		called = creds.Target == "1234" && len(id) == 32 && fromARI != nil && toARI != nil
		if p.OnAnswer == nil || p.OnAnswer(ctx) != nil {
			return false, errors.New("answer failed")
		}
		return true, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	settled, err := bridge.Call(ctx, byok.Credentials{Identity: "synthetic", Password: []byte("only-for-tests"), Target: "1234"},
		asterisk.BrowserDial{ChannelID: browserID, Destination: "1234", Nonce: nonce})
	if err != nil || !settled || !called {
		t.Fatal("synthetic browser→owned ARI→provider callback not bridged")
	}
	mu.Lock()
	defer mu.Unlock()
	if answerCount != 1 || mediaRemoved != 1 || bridgeRemoved != 1 || browserRemoved != 0 {
		t.Fatal("browser answer or owned bridge/media cleanup incorrect")
	}
	progress, err := os.ReadFile(filepath.Join(dir, "call-milestones-v1"))
	if err != nil || !strings.Contains(string(progress), "bridge-start\n") ||
		!strings.Contains(string(progress), "bridge-attached\n") ||
		!strings.Contains(string(progress), "provider-start\n") ||
		!strings.Contains(string(progress), "bridge-closed\n") ||
		strings.Contains(string(progress), "only-for-tests") || strings.Contains(string(progress), "1234") {
		t.Fatal("owned progress omitted ARI milestones or leaked caller/provider data")
	}
}
