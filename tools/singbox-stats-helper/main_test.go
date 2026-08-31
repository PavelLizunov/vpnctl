package main

import (
	"testing"

	stats "github.com/v2fly/v2ray-core/v5/app/stats/command"
)

func TestAggregateTrafficCounters(t *testing.T) {
	got, err := aggregate([]*stats.Stat{
		{Name: "inbound>>>vless-in>>>traffic>>>uplink", Value: 500},
		{Name: "inbound>>>vless-in>>>traffic>>>downlink", Value: 600},
		{Name: "inbound>>>tuic-in>>>traffic>>>uplink", Value: 50},
		{Name: "user>>>alice>>>traffic>>>uplink", Value: 123},
		{Name: "user>>>alice>>>traffic>>>downlink", Value: 456},
		{Name: "user>>>team>>>west>>>traffic>>>uplink", Value: 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerUploadTotal != 550 || got.ServerDownloadTotal != 600 {
		t.Fatalf("server totals = %#v", got)
	}
	if got.Users["alice"] != (userTotals{UploadTotal: 123, DownloadTotal: 456}) {
		t.Fatalf("alice totals = %#v", got.Users["alice"])
	}
	if got.Users["team>>>west"] != (userTotals{UploadTotal: 7}) {
		t.Fatalf("separator-containing user totals = %#v", got.Users["team>>>west"])
	}
}

func TestAggregateRejectsMalformedName(t *testing.T) {
	_, err := aggregate([]*stats.Stat{{Name: "outbound>>>main>>>traffic>>>uplink", Value: 1}})
	if err == nil {
		t.Fatal("expected malformed name error")
	}
}

func TestAggregateRejectsNegativeCounter(t *testing.T) {
	_, err := aggregate([]*stats.Stat{{Name: "user>>>alice>>>traffic>>>uplink", Value: -1}})
	if err == nil {
		t.Fatal("expected negative counter error")
	}
}

func TestAggregateRejectsDuplicateDirection(t *testing.T) {
	_, err := aggregate([]*stats.Stat{
		{Name: "inbound>>>main>>>traffic>>>uplink", Value: 1},
		{Name: "inbound>>>main>>>traffic>>>uplink", Value: 2},
	})
	if err == nil {
		t.Fatal("expected duplicate direction error")
	}
}

func TestRunRejectsNonpositiveTimeout(t *testing.T) {
	if err := run([]string{"--timeout", "0s"}, nil); err == nil {
		t.Fatal("expected invalid timeout error")
	}
}
