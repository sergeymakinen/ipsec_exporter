package ipsecmetrics

import (
	"fmt"
	"os/exec"
	"sync"

	"github.com/spheromak/ipsec_exporter/internal/ourlog"
	"github.com/spheromak/ipsec_exporter/pkg/metric"
)

const ipsecCmdPrefix = "ipsec"

type Collector struct {
	mu   sync.Mutex
	args []string
}

func New(args []string) (*Collector, error) {
	c := &Collector{}
	c.args = args
	return c, nil
}

func (c *Collector) Scrape() (metric.Metrics, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := metric.Metrics{}
	cmd := exec.Command(ipsecCmdPrefix, c.args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			if code != 1 {
				ourlog.Debug("msg", "Failed to execute command", "cmd", cmd, "output", output, "err", err, "status", code)
				return m, fmt.Errorf("Failed to execute command %s, exited with code %d", cmd, code)
			}
		}
		ourlog.Debug("msg", "Ipsec command had non zero exit code, but it may be non-fatal", "cmd", cmd, "err", err)
	}

	switch {
	case reSSMarker.Match(output):
		ourlog.Debug("msg", "Output type is detected as strongswan", "cmd", cmd)
		return scrapeStrongswan(output), nil
	case reLSMarker.Match(output):
		ourlog.Debug("msg", "Output type is detected as libreswan", "cmd", cmd)
		return scrapeLibreswan(output), nil
	}

	ourlog.Debug("msg", "Failed to recognize output", "cmd", cmd, "output", output)
	return m, fmt.Errorf("Failed to recognize output type for cmd %s", cmd)
}
