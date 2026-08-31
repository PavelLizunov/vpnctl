package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	stats "github.com/v2fly/v2ray-core/v5/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const defaultAddress = "127.0.0.1:10085"

var errMalformedCounter = errors.New("malformed traffic counter")

type counterScope uint8

const (
	userScope counterScope = iota
	inboundScope
)

type userTotals struct {
	UploadTotal   uint64 `json:"upload_total"`
	DownloadTotal uint64 `json:"download_total"`
}

type output struct {
	ServerUploadTotal   uint64                `json:"server_upload_total"`
	ServerDownloadTotal uint64                `json:"server_download_total"`
	UptimeSeconds       uint64                `json:"uptime_seconds"`
	Users               map[string]userTotals `json:"users"`
}

func counterIdentity(name string) (counterScope, string, bool, error) {
	const userPrefix = "user>>>"
	const inboundPrefix = "inbound>>>"
	const uploadSuffix = ">>>traffic>>>uplink"
	const downloadSuffix = ">>>traffic>>>downlink"
	var scope counterScope
	var body string
	switch {
	case strings.HasPrefix(name, userPrefix):
		scope = userScope
		body = strings.TrimPrefix(name, userPrefix)
	case strings.HasPrefix(name, inboundPrefix):
		scope = inboundScope
		body = strings.TrimPrefix(name, inboundPrefix)
	default:
		return 0, "", false, errMalformedCounter
	}
	var id string
	var upload bool
	switch {
	case strings.HasSuffix(body, uploadSuffix):
		id = strings.TrimSuffix(body, uploadSuffix)
		upload = true
	case strings.HasSuffix(body, downloadSuffix):
		id = strings.TrimSuffix(body, downloadSuffix)
	default:
		return 0, "", false, errMalformedCounter
	}
	if id == "" {
		return 0, "", false, errMalformedCounter
	}
	return scope, id, upload, nil
}

func add(total *uint64, value uint64) error {
	if value > math.MaxUint64-*total {
		return errors.New("traffic counter total overflow")
	}
	*total += value
	return nil
}

func aggregate(counters []*stats.Stat) (output, error) {
	result := output{Users: make(map[string]userTotals)}
	seen := make(map[string]uint8)
	for _, counter := range counters {
		if counter == nil || counter.Value < 0 {
			return output{}, errMalformedCounter
		}
		scope, id, upload, err := counterIdentity(counter.Name)
		if err != nil {
			return output{}, err
		}
		key := fmt.Sprintf("%d:%s", scope, id)
		bit := uint8(1)
		if !upload {
			bit = 2
		}
		if seen[key]&bit != 0 {
			return output{}, errors.New("duplicate traffic counter direction")
		}
		seen[key] |= bit
		value := uint64(counter.Value)
		if scope == inboundScope {
			if upload {
				err = add(&result.ServerUploadTotal, value)
			} else {
				err = add(&result.ServerDownloadTotal, value)
			}
			if err != nil {
				return output{}, err
			}
			continue
		}
		totals := result.Users[id]
		if upload {
			totals.UploadTotal = value
		} else {
			totals.DownloadTotal = value
		}
		result.Users[id] = totals
	}
	return result, nil
}

func query(ctx context.Context, address string) (output, error) {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return output{}, fmt.Errorf("create stats client: %w", err)
	}
	defer conn.Close()
	client := stats.NewStatsServiceClient(conn)
	before, err := client.GetSysStats(ctx, &stats.SysStatsRequest{})
	if err != nil {
		return output{}, fmt.Errorf("query system stats: %w", err)
	}
	response, err := client.QueryStats(ctx, &stats.QueryStatsRequest{
		Patterns: []string{"user>>>", "inbound>>>"},
		Reset_:   false,
	})
	if err != nil {
		return output{}, fmt.Errorf("query traffic stats: %w", err)
	}
	after, err := client.GetSysStats(ctx, &stats.SysStatsRequest{})
	if err != nil {
		return output{}, fmt.Errorf("recheck system stats: %w", err)
	}
	if after.Uptime < before.Uptime {
		return output{}, errors.New("sing-box restarted during stats query")
	}
	result, err := aggregate(response.Stat)
	if err != nil {
		return output{}, err
	}
	result.UptimeSeconds = uint64(after.Uptime)
	return result, nil
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("singbox-stats-helper", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	address := flags.String("address", defaultAddress, "loopback V2Ray Stats API address")
	timeout := flags.Duration("timeout", 5*time.Second, "query timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		return errors.New("invalid arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := query(ctx, *address)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "singbox-stats-helper:", err)
		os.Exit(1)
	}
}
