package vicimetrics

import (
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/sergeymakinen/ipsec_exporter/pkg/exporter"
	"github.com/sergeymakinen/ipsec_exporter/pkg/metric"
	"github.com/strongswan/govici/vici"
)

type Collector struct {
	address *url.URL
	timeout time.Duration
	vici    *vici.Session

	metrics *metric.Metrics
}

func New(url *url.URL, timeout time.Duration) (*Collector, error) {
	c := &Collector{
		address: url,
		timeout: timeout,
	}

	// try to connect when we instantiate, we will disco right after
	// TODO(jesse): we may want to just connect/keepalive here eventually ?
	if err := c.connect(); err != nil {
		return c, err
	}
	defer c.vici.Close()

	return c, nil
}

func (c *Collector) connect() error {
	network, addr := c.address.Scheme, c.address.Host
	if network == "unix" {
		addr = c.address.Path
	}

	sess, err := vici.NewSession(vici.WithAddr(network, addr), vici.WithDialContext((&net.Dialer{Timeout: c.timeout}).DialContext))
	if err != nil {
		return fmt.Errorf("Failed to connect to charon: %w", err)
	}
	c.vici = sess

	return nil
}

// run a command check status and  unmarshall into passed structure.
func (c *Collector) runcmd(cmd string, v interface{}) error {
	msg, err := c.vici.CommandRequest(cmd, nil)
	if err != nil {
		return fmt.Errorf("Failed to send '%s' command: %w", cmd, err)
	}

	if msg.Err() != nil {
		return fmt.Errorf("Failed to process '%s' command response: %w", cmd, err)
	}

	if err = vici.UnmarshalMessage(msg, v); err != nil {
		return fmt.Errorf("Failed to unmarshal '%s' command response: %w", cmd, err)
	}

	return nil
}

func (c *Collector) Scrape(e *exporter.Exporter) (metric.Metrics, error) {
	e.Lock()
	defer e.Unlock()

	if err := c.connect(); err != nil {
		return *c.metrics, err
	}
	defer c.vici.Close()

	if err := c.runcmd("stats", c.metrics.Stats); err != nil {
		return *c.metrics, err
	}

	if err := c.runcmd("stats", c.metrics.Stats); err != nil {
		return *c.metrics, err
	}

	pools := make(map[string]metric.Pool)
	if err := c.runcmd("get-pools", pools); err != nil {
		return *c.metrics, err
	}
	for name, pool := range pools {
		pool.Name = name
		c.metrics.Pools = append(c.metrics.Pools, pool)
	}

	stream, err := c.vici.StreamedCommandRequest("list-sas", "list-sa", nil)
	if err != nil {
		return *c.metrics, fmt.Errorf("Failed to send 'list-sas' command: %w", err)
	}

	for _, msg := range stream.Messages() {
		if msg.Err() != nil {
			return *c.metrics, fmt.Errorf("Failed to process 'lists-sas' command response: %w", err)
		}
		ikeSAs := make(map[string]metric.IkeSA)
		if err = vici.UnmarshalMessage(msg, ikeSAs); err != nil {
			return *c.metrics, fmt.Errorf("Failed to unmarshal 'list-sas' command response: %w", err)
		}

		for name, ikeSA := range ikeSAs {
			ikeSA.Name = name
			c.metrics.IKESAs = append(c.metrics.IKESAs, &ikeSA)
		}
	}

	return *c.metrics, nil
}
