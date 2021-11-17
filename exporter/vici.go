package exporter

import (
	"net"

	"github.com/go-kit/kit/log/level"
	"github.com/strongswan/govici/vici"
)

func (e *Exporter) scrapeVICI() (m metrics, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	network, addr := e.address.Scheme, e.address.Host
	if network == "unix" {
		addr = e.address.Path
	}
	sess, err := vici.NewSession(vici.WithAddr(network, addr), vici.WithDialContext((&net.Dialer{Timeout: e.timeout}).DialContext))
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to connect to charon", "err", err)
		return
	}
	defer sess.Close()

	msg, err := sess.CommandRequest("stats", nil)
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to send command", "cmd", "stats", "err", err)
		return
	}
	if msg.Err() != nil {
		level.Error(e.logger).Log("msg", "Failed to process command response", "cmd", "stats", "err", err)
		return
	}
	if err = vici.UnmarshalMessage(msg, &m.Stats); err != nil {
		level.Error(e.logger).Log("msg", "Failed to unmarshal command response", "cmd", "stats", "err", err)
		return
	}

	msg, err = sess.CommandRequest("get-pools", nil)
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to send command", "cmd", "get-pools", "err", err)
		return
	}
	if msg.Err() != nil {
		level.Error(e.logger).Log("msg", "Failed to process command response", "cmd", "get-pools", "err", err)
		return
	}
	pools := make(map[string]pool)
	if err = vici.UnmarshalMessage(msg, pools); err != nil {
		level.Error(e.logger).Log("msg", "Failed to unmarshal command response", "cmd", "get-pools", "err", err)
		return
	}
	for name, pool := range pools {
		pool.Name = name
		m.Pools = append(m.Pools, pool)
	}

	stream, err := sess.StreamedCommandRequest("list-sas", "list-sa", nil)
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to send command", "cmd", "list-sas", "err", err)
		return
	}
	for _, msg := range stream.Messages() {
		if msg.Err() != nil {
			level.Error(e.logger).Log("msg", "Failed to process command response", "cmd", "list-sas", "err", err)
			return
		}
		ikeSAs := make(map[string]ikeSA)
		if err = vici.UnmarshalMessage(msg, ikeSAs); err != nil {
			level.Error(e.logger).Log("msg", "Failed to unmarshal command response", "cmd", "list-sas", "err", err)
			return
		}
		for name, ikeSA := range ikeSAs {
			ikeSA.Name = name
			m.IKESAs = append(m.IKESAs, &ikeSA)
		}
	}
	ok = true
	return
}
