package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

func TestPeerPermission(t *testing.T) {
	exits, err := parseExits("192.0.2.11, 198.51.100.22,192.0.2.11")
	if err != nil || len(exits) != 2 {
		t.Fatalf("expected two distinct exits: %v (%v)", exits, err)
	}
	permit := peerPermission(exits)
	for ip, want := range map[string]bool{
		"192.0.2.11": true, "198.51.100.22": true,
		"192.0.2.12": false, "2001:db8::1": false, "invalid": false,
	} {
		if got := permit(nil, net.ParseIP(ip)); got != want {
			t.Errorf("permission for %s = %v, want %v", ip, got, want)
		}
	}
	empty, err := parseExits("")
	if err != nil || peerPermission(empty)(nil, net.ParseIP("192.0.2.11")) {
		t.Fatal("an empty allowlist must deny peers")
	}
}

func TestRejectInvalidExit(t *testing.T) {
	for _, csv := range []string{"192.0.2.11,", "example.org", "2001:db8::1", "::ffff:192.0.2.11"} {
		if _, err := parseExits(csv); err == nil {
			t.Errorf("accepted invalid EXIT_IPS %q", csv)
		}
	}
}

func TestRelayAuthenticatesAndEnforcesPermissionsOverBothTransports(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	_, port, err := net.SplitHostPort(address)
	probe.Close()
	if err != nil {
		t.Fatal(err)
	}

	env := map[string]string{
		"RELAY_IP": "127.0.0.1", "RELAY_PORT": port, "EXIT_IP": "192.0.2.11",
		"RELAY_USERNAME": "fixture-user", "RELAY_PASSWORD": "fixture-password",
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- run(ctx, func(key string) (string, bool) {
			value, exists := env[key]
			return value, exists
		})
	}()
	var stream net.Conn
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		stream, err = net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("TURN listener did not start: %v", err)
	}
	defer stream.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()

	for name, conn := range map[string]net.PacketConn{"udp": udp, "tcp": turn.NewSTUNConn(stream)} {
		t.Run(name, func(t *testing.T) {
			client, err := turn.NewClient(&turn.ClientConfig{
				TURNServerAddr: address, Conn: conn, RTO: 20 * time.Millisecond,
				Username: env["RELAY_USERNAME"], Password: env["RELAY_PASSWORD"],
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.Listen(); err != nil {
				t.Fatal(err)
			}
			allocation, err := client.Allocate()
			if err != nil {
				t.Fatal(err)
			}
			defer allocation.Close()
			allowed := &net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 53492}
			if err := client.CreatePermission(allowed); err != nil {
				t.Errorf("allowed exit refused: %v", err)
			}
			denied := &net.UDPAddr{IP: net.ParseIP("192.0.2.12"), Port: 53492}
			if err := client.CreatePermission(denied); err == nil {
				t.Error("unlisted peer permitted")
			}
		})
	}

	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TURN server did not stop on cancellation")
	}
}
