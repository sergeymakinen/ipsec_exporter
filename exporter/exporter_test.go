package exporter

import (
	"bytes"
	"io/ioutil"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/google/shlex"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestExporter(t *testing.T) {
	exporter, err := New(CollectorVICI, nil, time.Second, nil, log.NewNopLogger())
	if err != nil {
		t.Fatalf("New() = _, %v; want nil", err)
	}
	exporter.scrape = func(e *Exporter) (m metrics, ok bool) {
		sec := int64(123)
		return metrics{
			Stats: stats{
				Uptime: uptime{
					Since: time.Now().Round(time.Second).Add(-3 * time.Minute).Format("Jan _2 15:04:05 2006"),
				},
				Workers: workers{
					Total: 10,
					Idle:  5,
					Active: queues{
						Critical: 1,
						High:     2,
						Medium:   3,
						Low:      4,
					},
				},
				Queues: queues{
					Critical: 1,
					High:     2,
					Medium:   3,
					Low:      4,
				},
				Scheduled: 12,
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
							State:      "INSTALLED",
							Mode:       "TUNNEL",
							Protocol:   "AH",
							InBytes:    123,
							InPackets:  456,
							OutBytes:   789,
							OutPackets: 901,
							LocalTS:    []string{"192.168.0.0/24", "192.168.1.0/24"},
							RemoteTS:   []string{"192.168.2.0/24", "192.168.3.0/24"},
						},
						"named-4": {
							Name:       "named",
							UID:        4,
							State:      "INSTALLED",
							Mode:       "TUNNEL",
							Protocol:   "AH",
							InBytes:    124,
							InPackets:  457,
							OutBytes:   790,
							OutPackets: 902,
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
							State:      "INSTALLED",
							Mode:       "TUNNEL",
							Protocol:   "AH",
							InBytes:    125,
							InPackets:  458,
							OutBytes:   791,
							OutPackets: 903,
							LocalTS:    []string{"192.168.0.0/24", "192.168.1.0/24"},
							RemoteTS:   []string{"192.168.2.0/24", "192.168.3.0/24"},
						},
					},
				},
			},
		}, true
	}
	f, err := os.Open("testdata/metrics-1.txt")
	if err != nil {
		t.Fatalf("os.Open() = _, %v; want nil", err)
	}
	defer f.Close()
	if err := testutil.CollectAndCompare(exporter, f); err != nil {
		t.Errorf("testutil.CollectAndCompare() = %v; want nil", err)
	}
}

func TestExporter_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestExporter_Integration during short test")
	}
	tests := []struct {
		Name          string
		CollectorType int
	}{
		{
			Name:          "VICI",
			CollectorType: CollectorVICI,
		},
		{
			Name:          "ipsec",
			CollectorType: CollectorIpsec,
		},
	}
	address, _ := url.Parse("tcp://127.0.0.1:4502")
	cmd, _ := shlex.Split("docker-compose -f ../testdata/docker/docker-compose.yml exec -T moon /bin/sh -c 'ipsec statusall || true'")
	b, err := ioutil.ReadFile("testdata/metrics-2.txt")
	if err != nil {
		panic("failed to read testdata/metrics-2.txt: " + err.Error())
	}
	metricNames := []string{
		"ipsec_child_sa_bytes_in",
		"ipsec_child_sa_bytes_out",
		"ipsec_child_sa_packets_in",
		"ipsec_child_sa_packets_out",
		"ipsec_child_sa_state",
		"ipsec_half_open_ike_sas",
		"ipsec_ike_sa_state",
		"ipsec_ike_sas",
		"ipsec_queues",
		"ipsec_up",
	}
	for _, td := range tests {
		t.Run(td.Name, func(t *testing.T) {
			exporter, err := New(td.CollectorType, address, time.Second, cmd, log.NewNopLogger())
			if err != nil {
				t.Fatalf("New() = _, %v; want nil", err)
			}
			if err := testutil.CollectAndCompare(exporter, bytes.NewReader(b), metricNames...); err != nil {
				t.Errorf("testutil.CollectAndCompare() = %v; want nil", err)
			}
		})
	}
}
