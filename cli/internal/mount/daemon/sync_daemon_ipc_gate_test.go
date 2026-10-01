package daemon

import (
	"encoding/json"
	"net"
	"pigcloud/internal/mount"
	"testing"
)

func roundTripSync(t *testing.T, sd *SyncDaemon, req mount.DaemonRequest) mount.DaemonResponse {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go sd.handleConn(server)
	if err := json.NewEncoder(client).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var resp mount.DaemonResponse
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func roundTripVirtual(t *testing.T, d *Daemon, req mount.DaemonRequest) mount.DaemonResponse {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	go d.handleConn(server)
	if err := json.NewEncoder(client).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var resp mount.DaemonResponse
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func TestSyncDaemonRejectsMutatingIPCDuringShutdown(t *testing.T) {
	sd := &SyncDaemon{token: "tok"}
	sd.gate.close()

	for _, action := range []string{"pin", "unpin", "flush", "clean", "retry", "resolve"} {
		resp := roundTripSync(t, sd, mount.DaemonRequest{Token: "tok", Action: action, Path: "x", Choice: "local"})
		if resp.Error != "shutting down" {
			t.Errorf("%s during shutdown: got %+v, want shutting-down rejection", action, resp)
		}
	}

	resp := roundTripSync(t, sd, mount.DaemonRequest{Token: "tok", Action: "ping"})
	if !resp.OK {
		t.Errorf("ping during shutdown: got %+v, want OK", resp)
	}
}

func TestSyncDaemonAllowsMutatingIPCBeforeShutdown(t *testing.T) {
	sd := &SyncDaemon{token: "tok"}
	resp := roundTripSync(t, sd, mount.DaemonRequest{Token: "tok", Action: "pin"})
	if !resp.OK {
		t.Fatalf("pin before shutdown: got %+v, want OK", resp)
	}
	done := make(chan struct{})
	go func() {
		sd.gate.wg.Wait()
		close(done)
	}()
	<-done
}

func TestVirtualDaemonRejectsMutatingIPCDuringShutdown(t *testing.T) {
	d := &Daemon{token: "tok"}
	d.gate.close()

	for _, action := range []string{"pin", "unpin", "flush", "clean", "retry"} {
		resp := roundTripVirtual(t, d, mount.DaemonRequest{Token: "tok", Action: action, Path: "x"})
		if resp.Error != "shutting down" {
			t.Errorf("%s during shutdown: got %+v, want shutting-down rejection", action, resp)
		}
	}

	resp := roundTripVirtual(t, d, mount.DaemonRequest{Token: "tok", Action: "ping"})
	if !resp.OK {
		t.Errorf("ping during shutdown: got %+v, want OK", resp)
	}
}
