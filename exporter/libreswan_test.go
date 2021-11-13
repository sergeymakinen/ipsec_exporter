package exporter

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/google/shlex"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestExporter_scrapeLibreswan(t *testing.T) {
	files, err := filepath.Glob("testdata/libreswan/*-command.txt")
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
				return e.scrapeLibreswan(in)
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

func TestExporter_Collect_Libreswan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestExporter_Collect_Libreswan during short test")
	}
	cmd, _ := shlex.Split("docker-compose -f ../testdata/docker/libreswan/docker-compose.yml exec -T moon /bin/sh -c 'ipsec status || true'")
	b, err := ioutil.ReadFile("testdata/libreswan/metrics-integration.txt")
	if err != nil {
		t.Fatalf("failed to read testdata/libreswan/metrics-integration.txt: %v", err)
	}
	metricNames := []string{
		"ipsec_child_sa_bytes_in",
		"ipsec_child_sa_bytes_out",
		"ipsec_child_sa_state",
		"ipsec_half_open_ike_sas",
		"ipsec_ike_sa_state",
		"ipsec_ike_sas",
		"ipsec_up",
	}
	exporter, err := New(CollectorIpsec, nil, time.Second, cmd, log.NewNopLogger())
	if err != nil {
		t.Fatalf("New() = _, %v; want nil", err)
	}
	if err := testutil.CollectAndCompare(exporter, bytes.NewReader(b), metricNames...); err != nil {
		t.Errorf("testutil.CollectAndCompare() = %v; want nil", err)
	}
}
