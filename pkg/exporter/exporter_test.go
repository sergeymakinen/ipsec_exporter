package exporter

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/google/shlex"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMain(m *testing.M) {
	now = func() time.Time { return time.Unix(0, 0).UTC() }
	tz = time.UTC
	os.Exit(m.Run())
}

func TestExporter_Collect(t *testing.T) {
	exporter, err := New(&Config{
		Type:    CollectorIpsec,
		Address: nil,
		Timeout: 0,
		Logger:  log.NewNopLogger(),
	})
	if err != nil {
		t.Fatalf("New() = _, %v; want nil", err)
	}
	exporter.scrape = func(e *Exporter) (m metrics, ok bool) {
		sec := int64(123)
		return metrics{
			Stats: stats{
				Uptime: uptime{
					Since: now().Round(time.Second).Add(-3 * time.Minute).Format("Jan _2 15:04:05 2006"),
				},
				Workers: &workers{
					Total: 10,
					Idle:  5,
					Active: queues{
						Critical: 1,
						High:     2,
						Medium:   3,
						Low:      4,
					},
				},
				Queues: &queues{
					Critical: 1,
					High:     2,
					Medium:   3,
					Low:      4,
				},
				Scheduled: newUint64(12),
				IKESAs: ikeSAs{
					Total:    10,
					HalfOpen: 5,
				},
			},
			Pools: []pool{
				{
					Name:    "named",
					Address: "127.0.0.0/24",
					Size:    254,
					Online:  10,
					Offline: 5,
				},
				{
					Address: "0.0.0.0/0",
					Size:    16,
					Online:  1,
					Offline: 0,
				},
			},
			IKESAs: []*ikeSA{
				{
					Name:          "named-1",
					UID:           1,
					Version:       1,
					State:         "ESTABLISHED",
					LocalHost:     "10.0.2.1",
					LocalID:       "local",
					RemoteHost:    "10.0.3.1",
					RemoteID:      "remote",
					RemoteXAuthID: "xauth",
					Established:   &sec,
					LocalVIPs:     []string{"192.168.0.1"},
					RemoteVIPs:    []string{"192.168.0.2"},
					ChildSAs: map[string]*childSA{
						"named-3": {
							Name:       "named",
							UID:        3,
							ReqID:      newUint32(4),
							State:      "INSTALLED",
							Mode:       "TUNNEL",
							Protocol:   "AH",
							InBytes:    123,
							InPackets:  newUint64(456),
							OutBytes:   789,
							OutPackets: newUint64(901),
							LocalTS:    []string{"192.168.0.0/24", "192.168.1.0/24"},
							RemoteTS:   []string{"192.168.2.0/24", "192.168.3.0/24"},
						},
						"named-4": {
							Name:       "named",
							UID:        4,
							ReqID:      newUint32(5),
							State:      "INSTALLED",
							Mode:       "TUNNEL",
							Protocol:   "AH",
							InBytes:    124,
							InPackets:  newUint64(457),
							OutBytes:   790,
							OutPackets: newUint64(902),
							Installed:  &sec,
							LocalTS:    []string{"192.168.0.0/24", "192.168.1.0/24"},
							RemoteTS:   []string{"192.168.2.0/24", "192.168.3.0/24"},
						},
					},
				},
				{
					Name:       "named-2",
					UID:        2,
					Version:    2,
					State:      "ESTABLISHED",
					LocalHost:  "10.0.2.2",
					LocalID:    "foo",
					RemoteHost: "10.0.3.2",
					RemoteID:   "bar",
					ChildSAs: map[string]*childSA{
						"named-5": {
							Name:       "named",
							UID:        5,
							ReqID:      newUint32(6),
							State:      "INSTALLED",
							Mode:       "TUNNEL",
							Protocol:   "AH",
							InBytes:    125,
							InPackets:  newUint64(458),
							OutBytes:   791,
							OutPackets: newUint64(903),
							LocalTS:    []string{"192.168.0.0/24", "192.168.1.0/24"},
							RemoteTS:   []string{"192.168.2.0/24", "192.168.3.0/24"},
						},
					},
				},
			},
		}, true
	}
	f, err := os.Open("testdata/metrics.txt")
	if err != nil {
		t.Fatalf("os.Open() = _, %v; want nil", err)
	}
	defer f.Close()
	if err := testutil.CollectAndCompare(exporter, f); err != nil {
		t.Errorf("testutil.CollectAndCompare() = %v; want nil", err)
	}
}

func TestExporter_Collect_Unknown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestExporter_Collect_Unknown during short test")
	}
	cmd, _ := shlex.Split("docker-compose -f ../testdata/docker/libreswan/docker-compose.yml exec -T moon /bin/ls")
	exporter, err := New(&Config{
		Type:    CollectorIpsec,
		Address: nil,
		Timeout: time.Second,
		Logger:  log.NewNopLogger(),
	})
	if err != nil {
		t.Fatalf("New() = _, %v; want nil", err)
	}
	expected := `
# HELP ipsec_up Was the last scrape successful.
# TYPE ipsec_up gauge
ipsec_up 0
`
	if err := testutil.CollectAndCompare(exporter, strings.NewReader(expected)); err != nil {
		t.Errorf("testutil.CollectAndCompare() = %v; want nil", err)
	}
}

func newUint32(n uint32) *uint32 { return &n }
func newUint64(n uint64) *uint64 { return &n }
