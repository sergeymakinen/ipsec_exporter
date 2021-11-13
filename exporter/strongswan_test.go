package exporter

import (
	"bytes"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/google/shlex"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"
)

func TestExporter_scrapeStrongswan(t *testing.T) {
	files, err := filepath.Glob("testdata/strongswan/*-command.txt")
	if err != nil {
		t.Fatalf("failed to list test files: %v", err)
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			in, err := ioutil.ReadFile(file)
			if err != nil {
				t.Fatalf("failed to read %s: %v", file, err)
			}
			exporter, err := New(CollectorIpsec, nil, 0, nil, log.NewNopLogger())
			if err != nil {
				t.Fatalf("New() = _, %v; want nil", err)
			}
			exporter.scrape = func(e *Exporter) (m metrics, ok bool) {
				return e.scrapeStrongswan(in)
			}
			outFile := strings.Replace(file, "-command.txt", "-metrics.txt", 1)
			if _, err := os.Stat(outFile); err == nil {
				out, err := ioutil.ReadFile(outFile)
				if err != nil {
					t.Fatalf("failed to read %s: %v", outFile, err)
				}
				if err = testutil.CollectAndCompare(exporter, bytes.NewReader(out)); err != nil {
					t.Errorf("testutil.CollectAndCompare() = %v; want nil", err)
				}
			} else {
				if err = ioutil.WriteFile(outFile, collect(t, exporter), 0666); err != nil {
					t.Fatalf("failed to write %s: %v", outFile, err)
				}
				t.Logf("wrote %s golden master", outFile)
			}
		})
	}
}

func TestExporter_Collect_Strongswan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestExporter_Collect_Strongswan during short test")
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
	cmd, _ := shlex.Split("docker-compose -f ../testdata/docker/strongswan/docker-compose.yml exec -T moon /bin/sh -c 'ipsec statusall || true'")
	b, err := ioutil.ReadFile("testdata/strongswan/metrics-integration.txt")
	if err != nil {
		t.Fatalf("failed to read testdata/strongswan/metrics-integration.txt: %v", err)
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
		"ipsec_up",
	}
	for _, td := range tests {
		t.Run(td.Name, func(t *testing.T) {
			exporter, err := New(td.CollectorType, address, time.Second, cmd, log.NewNopLogger())
			if err != nil {
				t.Fatalf("New() = _, %v; want nil", err)
			}
			if err = testutil.CollectAndCompare(exporter, bytes.NewReader(b), metricNames...); err != nil {
				t.Errorf("testutil.CollectAndCompare() = %v; want nil", err)
			}
		})
	}
}

func collect(t *testing.T, c prometheus.Collector) []byte {
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("failed to register exporter: %v", err)
	}
	got, err := reg.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.FmtText)
	for _, mf := range got {
		if err := enc.Encode(mf); err != nil {
			t.Fatalf("failed to encode metric: %v", err)
		}
	}
	return buf.Bytes()
}
