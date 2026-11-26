package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

func parseExits(csv string) (map[netip.Addr]struct{}, error) {
	exits := make(map[netip.Addr]struct{})
	if strings.TrimSpace(csv) == "" {
		return exits, nil
	}
	for _, field := range strings.Split(csv, ",") {
		ip, err := netip.ParseAddr(strings.TrimSpace(field))
		if err != nil || !ip.Is4() {
			return nil, errors.New("EXIT_IPS must contain only IPv4 addresses")
		}
		exits[ip] = struct{}{}
	}
	return exits, nil
}

func peerPermission(exits map[netip.Addr]struct{}) turn.PermissionHandler {
	return func(_ net.Addr, peer net.IP) bool {
		ip, ok := netip.AddrFromSlice(peer)
		if !ok {
			return false
		}
		_, allowed := exits[ip.Unmap()]
		return allowed
	}
}

func run(ctx context.Context, lookup func(string) (string, bool)) error {
	env := func(key string) string {
		value, _ := lookup(key)
		return value
	}
	ip, err := netip.ParseAddr(env("RELAY_IP"))
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return errors.New("RELAY_IP must be a unicast IPv4 address")
	}
	port := env("RELAY_PORT")
	if port == "" {
		port = "53491"
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return errors.New("RELAY_PORT must be in 1..65535")
	}
	realm := env("RELAY_REALM")
	if realm == "" {
		realm = "turnrelay"
	}
	username, password := env("RELAY_USERNAME"), env("RELAY_PASSWORD")
	if username == "" || password == "" {
		return errors.New("RELAY_USERNAME and RELAY_PASSWORD are required")
	}
	csv, configured := lookup("EXIT_IPS")
	if !configured {
		csv = env("EXIT_IP")
	}
	exits, err := parseExits(csv)
	if err != nil {
		return err
	}
	permission := peerPermission(exits)
	key := turn.GenerateAuthKey(username, realm, password)

	address := netip.AddrPortFrom(ip, uint16(number)).String()
	udp, err := net.ListenPacket("udp4", address)
	if err != nil {
		return errors.New("could not bind TURN UDP listener")
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", address)
	if err != nil {
		return errors.New("could not bind TURN TCP listener")
	}
	defer tcp.Close()

	server, err := turn.NewServer(turn.ServerConfig{
		Realm: realm,
		// Pion's request errors can include the supplied username.
		LoggerFactory: &logging.DefaultLoggerFactory{Writer: io.Discard, DefaultLogLevel: logging.LogLevelDisabled},
		AuthHandler: func(request *turn.RequestAttributes) (string, []byte, bool) {
			if request.Realm != realm || subtle.ConstantTimeCompare([]byte(request.Username), []byte(username)) != 1 {
				return "", nil, false
			}
			return username, key, true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: udp, PermissionHandler: permission,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.IP(ip.AsSlice()), Address: ip.String()},
		}},
		ListenerConfigs: []turn.ListenerConfig{{
			Listener: tcp, PermissionHandler: permission,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.IP(ip.AsSlice()), Address: ip.String()},
		}},
	})
	if err != nil {
		return errors.New("could not start TURN server")
	}
	<-ctx.Done()
	if err := server.Close(); err != nil {
		return errors.New("could not close TURN server")
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.LookupEnv); err != nil {
		log.Fatal(err)
	}
}
