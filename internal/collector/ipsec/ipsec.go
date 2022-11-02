package ipsec

import (
	"fmt"
	"os/exec"

	"github.com/go-kit/log/level"
)

func (e *collector) Scrape() (m metrics, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cmd := exec.Command(e.ipsecCmd[0], e.ipsecCmd[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if lerr := level.Error(e.logger).Log("msg", "Failed to execute command", "cmd", cmd, "output", output, "err", err); lerr != 0 {
			fmt.Println(lerr)
		}

		return
	}
	switch {
	case reSSMarker.Match(output):
		level.Debug(e.logger).Log("msg", "Output type is detected as strongswan", "cmd", cmd)
		return e.scrapeStrongswan(output)
	case reLSMarker.Match(output):
		level.Debug(e.logger).Log("msg", "Output type is detected as libreswan", "cmd", cmd)
		return e.scrapeLibreswan(output)
	}
	level.Error(e.logger).Log("msg", "Failed to recognize output type", "cmd", cmd, "output", output)
	return
}
