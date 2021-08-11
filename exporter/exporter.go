// Package exporter provides a collector for strongswan/libreswan IPsec stats.
package exporter

import (
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/strongswan/govici/vici"
)

// Collector types.
const (
	CollectorVICI = iota
	CollectorIpsec
)

const namespace = "ipsec"

const (
	prefixStatus = "Status of IKE charon daemon"
	prefixPools  = "Virtual IP pools (size/online/offline):"
	prefixSA     = "Security Associations"
)

var (
	reUptime           = regexp.MustCompile(`^  uptime: .+, since (.+)$`)
	reStats            = regexp.MustCompile(`^  worker threads: (\d+) of (\d+) idle, (\d+)/(\d+)/(\d+)/(\d+) working, job queue: (\d+)/(\d+)/(\d+)/(\d+), scheduled: (\d+)$`)
	rePool             = regexp.MustCompile(`^  (.+?): (\d+)/(\d+)/(\d+)$`)
	reSAHeader         = regexp.MustCompile(`^Security Associations \((\d+) up, (\d+) connecting\):$`)
	reSAPrefix         = regexp.MustCompile(`^\s*([^\[]+)\[(\d+)]: `)
	reSAStatus         = regexp.MustCompile(`^([^ ]+) .+ ago, ([^\[]+)\[([^]]+)]\.\.\.([^\[]+)\[([^]]+)]$`)
	reSAVersion        = regexp.MustCompile(`^(.+) SPIs:`)
	reSARemoteIdentity = regexp.MustCompile(`^Remote (.+) identity: (.+)$`)
	reChildSAPrefix    = regexp.MustCompile(`^\s*([^{]+){(\d+)}:  `)
	reChildSAStatus    = regexp.MustCompile(`^([^,]+), ([^,]+), reqid (\d+), (.+) SPIs:.+`)
	reChildSATraffic   = regexp.MustCompile(`(\d+) bytes_i(?: \((\d+) pkts?[^)]*\))?, (\d+) bytes_o(?: \((\d+) pkts?[^)]*\))?`)
	reChildSATS        = regexp.MustCompile(`^ (.+) === (.+)$`)
)

var (
	ikeSALbls = []string{
		"name",
		"uid",
		"version",
		"local_host",
		"local_id",
		"remote_host",
		"remote_id",
		"remote_identity",
		"vips",
	}
	childSALbls = []string{
		"ike_sa_name",
		"ike_sa_uid",
		"ike_sa_version",
		"ike_sa_local_host",
		"ike_sa_local_id",
		"ike_sa_remote_host",
		"ike_sa_remote_id",
		"ike_sa_remote_identity",
		"ike_sa_vips",
		"name",
		"uid",
		"mode",
		"protocol",
		"reqid",
		"local_ts",
		"remote_ts",
	}
)
var (
	ikeSAStates = map[string]float64{
		"CREATED":     0,
		"CONNECTING":  1,
		"ESTABLISHED": 2,
		"PASSIVE":     3,
		"REKEYING":    4,
		"REKEYED":     5,
		"DELETING":    6,
		"DESTROYING":  7,
	}
	childSAStates = map[string]float64{
		"CREATED":    0,
		"ROUTED":     1,
		"INSTALLING": 2,
		"INSTALLED":  3,
		"UPDATING":   4,
		"REKEYING":   5,
		"REKEYED":    6,
		"RETRYING":   7,
		"DELETING":   8,
		"DELETED":    9,
		"DESTROYING": 10,
	}
)

// Exporter collects IPsec stats via a VICI protocol or an ipsec binary
// and exports them using the prometheus metrics package.
type Exporter struct {
	scrape   func(e *Exporter) (m metrics, ok bool)
	address  *url.URL
	timeout  time.Duration
	ipsecCmd []string
	logger   log.Logger
	mu       sync.Mutex

	up                *prometheus.Desc
	uptime            *prometheus.Desc
	workers           *prometheus.Desc
	idleWorkers       *prometheus.Desc
	activeWorkers     *prometheus.Desc
	queues            *prometheus.Desc
	ikeSAs            *prometheus.Desc
	halfOpenIKESAs    *prometheus.Desc
	poolIPs           *prometheus.Desc
	onlinePoolIPs     *prometheus.Desc
	offlinePoolIPs    *prometheus.Desc
	ikeSAState        *prometheus.Desc
	establishedIKESA  *prometheus.Desc
	childSAState      *prometheus.Desc
	childSABytesIn    *prometheus.Desc
	childSAPacketsIn  *prometheus.Desc
	childSABytesOut   *prometheus.Desc
	childSAPacketsOut *prometheus.Desc
	childSAInstalled  *prometheus.Desc
}

// Describe describes all the metrics exported by the memcached exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.up
	ch <- e.uptime
	ch <- e.workers
	ch <- e.idleWorkers
	ch <- e.activeWorkers
	ch <- e.queues
	ch <- e.ikeSAs
	ch <- e.halfOpenIKESAs
	ch <- e.poolIPs
	ch <- e.onlinePoolIPs
	ch <- e.offlinePoolIPs
	ch <- e.ikeSAState
	ch <- e.establishedIKESA
	ch <- e.childSAState
	ch <- e.childSABytesIn
	ch <- e.childSAPacketsIn
	ch <- e.childSABytesOut
	ch <- e.childSAPacketsOut
	ch <- e.childSAInstalled
}

// Collect fetches the statistics from the configured memcached server, and
// delivers them as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	m, ok := e.scrape(e)
	if !ok {
		ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 0)
		return
	}

	e.collect(m, ch)
}

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

func (e *Exporter) scrapeIpsec() (m metrics, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cmd := exec.Command(e.ipsecCmd[0], e.ipsecCmd[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to execute command", "cmd", cmd, "output", output, "err", err)
		return
	}
	// Looking for prefixes then scanning lines below for matching regexps.
	// Using an additional newline just to avoid processing SAs not added yet
	lines := strings.Split(string(output)+"\n", "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, prefixStatus):
			j := i
			if i+1 < len(lines) {
				j++
			}
			for _, line := range lines[j:] {
				if !strings.HasPrefix(line, "  ") {
					break
				}
				matches := reUptime.FindStringSubmatch(line)
				if matches != nil {
					m.Stats.Uptime.Since = matches[1]
					continue
				}
				matches = reStats.FindStringSubmatch(line)
				if matches != nil {
					m.Stats.Workers.Idle, _ = strconv.ParseUint(matches[1], 10, 64)
					m.Stats.Workers.Total, _ = strconv.ParseUint(matches[2], 10, 64)
					m.Stats.Workers.Active.Critical, _ = strconv.ParseUint(matches[3], 10, 64)
					m.Stats.Workers.Active.High, _ = strconv.ParseUint(matches[4], 10, 64)
					m.Stats.Workers.Active.Medium, _ = strconv.ParseUint(matches[5], 10, 64)
					m.Stats.Workers.Active.Low, _ = strconv.ParseUint(matches[6], 10, 64)
					m.Stats.Queues.Critical, _ = strconv.ParseUint(matches[7], 10, 64)
					m.Stats.Queues.High, _ = strconv.ParseUint(matches[8], 10, 64)
					m.Stats.Queues.Medium, _ = strconv.ParseUint(matches[9], 10, 64)
					m.Stats.Queues.Low, _ = strconv.ParseUint(matches[10], 10, 64)
					m.Stats.Scheduled, _ = strconv.ParseUint(matches[11], 10, 64)
				}
			}
		case line == prefixPools:
			j := i
			if i+1 < len(lines) {
				j++
			}
			for _, line := range lines[j:] {
				matches := rePool.FindStringSubmatch(line)
				if matches == nil {
					break
				}
				pool := pool{Address: matches[1]}
				pool.Size, _ = strconv.ParseUint(matches[2], 10, 64)
				pool.Online, _ = strconv.ParseUint(matches[3], 10, 64)
				pool.Offline, _ = strconv.ParseUint(matches[4], 10, 64)
				m.Pools = append(m.Pools, pool)
			}
		case strings.HasPrefix(line, prefixSA):
			matches := reSAHeader.FindStringSubmatch(line)
			if matches != nil {
				m.Stats.IKESAs.Total, _ = strconv.ParseUint(matches[1], 10, 64)
				m.Stats.IKESAs.HalfOpen, _ = strconv.ParseUint(matches[2], 10, 64)
				j := i
				if i+1 < len(lines) {
					j++
				}
				var (
					prefix, childPrefix []string
					sa, prevSA          *ikeSA
					childSA2            *childSA
				)

			Loop:
				for _, line := range lines[j:] {
					if (prefix != nil && !strings.HasPrefix(line, prefix[0])) || (childPrefix != nil && !strings.HasPrefix(line, childPrefix[0])) {
						if sa != nil {
							prevSA = sa
						}
						prefix, childPrefix, sa, childSA2 = nil, nil, nil, nil
					}
					if prefix == nil && childPrefix == nil {
						matches = reSAPrefix.FindStringSubmatch(line)
						if matches != nil {
							prefix = matches
							sa = &ikeSA{
								Name:     matches[1],
								ChildSAs: make(map[string]*childSA),
							}
							n, _ := strconv.ParseUint(matches[2], 10, 32)
							sa.UID = uint32(n)
							m.IKESAs = append(m.IKESAs, sa)

						} else {
							matches = reChildSAPrefix.FindStringSubmatch(line)
							if matches != nil {
								childPrefix = matches
								childSA2 = &childSA{Name: matches[1]}
								n, _ := strconv.ParseUint(matches[2], 10, 32)
								childSA2.UID = uint32(n)
								if prevSA != nil {
									prevSA.ChildSAs[fmt.Sprintf("%s-%d", childSA2.Name, childSA2.UID)] = childSA2
								}
							}
						}
					}
					switch {
					case prefix != nil:
						line = strings.TrimPrefix(line, prefix[0])
						matches = reSAStatus.FindStringSubmatch(line)
						if matches != nil {
							sa.State = matches[1]
							sa.LocalHost = matches[2]
							sa.LocalID = matches[3]
							sa.RemoteHost = matches[4]
							sa.RemoteID = matches[5]
							continue
						}
						matches = reSAVersion.FindStringSubmatch(line)
						if matches != nil {
							switch matches[1] {
							case "IKEv1":
								sa.Version = 1
							case "IKEv2":
								sa.Version = 2
							}
							continue
						}
						matches = reSARemoteIdentity.FindStringSubmatch(line)
						if matches != nil {
							if matches[1] == "XAuth" {
								sa.RemoteXAuthID = matches[2]
							} else {
								sa.RemoteEAPID = matches[2]
							}
						}
					case childPrefix != nil:
						line = strings.TrimPrefix(line, childPrefix[0])
						matches = reChildSAStatus.FindStringSubmatch(line)
						if matches != nil {
							childSA2.State = matches[1]
							childSA2.Mode = matches[2]
							n, _ := strconv.ParseUint(matches[3], 10, 64)
							childSA2.ReqID = uint32(n)
							childSA2.Protocol = matches[4]
							continue
						}
						matches = reChildSATraffic.FindStringSubmatch(line)
						if matches != nil {
							childSA2.InBytes, _ = strconv.ParseUint(matches[1], 10, 64)
							childSA2.OutBytes, _ = strconv.ParseUint(matches[3], 10, 64)
							if matches[2] != "" && matches[4] != "" {
								childSA2.InPackets, _ = strconv.ParseUint(matches[2], 10, 64)
								childSA2.OutPackets, _ = strconv.ParseUint(matches[4], 10, 64)
							}
							continue
						}
						matches = reChildSATS.FindStringSubmatch(line)
						if matches != nil {
							childSA2.LocalTS = strings.Split(matches[1], " ")
							childSA2.RemoteTS = strings.Split(matches[2], " ")
						}
					default:
						break Loop
					}
				}
			}
		}
	}
	ok = true
	return
}

func (e *Exporter) collect(m metrics, ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 1)
	if m.Stats.Uptime.Since != "" {
		uptime, err := time.ParseInLocation("Jan _2 15:04:05 2006", m.Stats.Uptime.Since, time.Local)
		if err != nil {
			ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 0)
			level.Error(e.logger).Log("msg", "Failed to unmarshal uptime", "uptime", m.Stats.Uptime.Since, "err", err)
			return
		}
		ch <- prometheus.MustNewConstMetric(e.uptime, prometheus.GaugeValue, time.Now().Round(time.Second).Sub(uptime).Seconds())
	}
	ch <- prometheus.MustNewConstMetric(e.workers, prometheus.GaugeValue, float64(m.Stats.Workers.Total))
	ch <- prometheus.MustNewConstMetric(e.idleWorkers, prometheus.GaugeValue, float64(m.Stats.Workers.Idle))
	ch <- prometheus.MustNewConstMetric(e.activeWorkers, prometheus.GaugeValue, float64(m.Stats.Workers.Active.Total()))
	ch <- prometheus.MustNewConstMetric(e.queues, prometheus.GaugeValue, float64(m.Stats.Queues.Critical), "critical")
	ch <- prometheus.MustNewConstMetric(e.queues, prometheus.GaugeValue, float64(m.Stats.Queues.High), "high")
	ch <- prometheus.MustNewConstMetric(e.queues, prometheus.GaugeValue, float64(m.Stats.Queues.Medium), "medium")
	ch <- prometheus.MustNewConstMetric(e.queues, prometheus.GaugeValue, float64(m.Stats.Queues.Low), "low")
	ch <- prometheus.MustNewConstMetric(e.ikeSAs, prometheus.GaugeValue, float64(m.Stats.IKESAs.Total))
	ch <- prometheus.MustNewConstMetric(e.halfOpenIKESAs, prometheus.GaugeValue, float64(m.Stats.IKESAs.HalfOpen))
	for _, pool := range m.Pools {
		ch <- prometheus.MustNewConstMetric(e.poolIPs, prometheus.GaugeValue, float64(pool.Size), pool.Name, pool.Address)
		ch <- prometheus.MustNewConstMetric(e.onlinePoolIPs, prometheus.GaugeValue, float64(pool.Online), pool.Name, pool.Address)
		ch <- prometheus.MustNewConstMetric(e.offlinePoolIPs, prometheus.GaugeValue, float64(pool.Offline), pool.Name, pool.Address)
	}
	for _, ikeSA := range m.IKESAs {
		labelValues := []string{
			ikeSA.Name,
			strconv.FormatUint(uint64(ikeSA.UID), 10),
			strconv.FormatUint(uint64(ikeSA.Version), 10),
			ikeSA.LocalHost,
			ikeSA.LocalID,
			ikeSA.RemoteHost,
			ikeSA.RemoteID,
			ikeSA.RemoteXAuthID + ikeSA.RemoteEAPID,
			strings.Join(append(ikeSA.LocalVIPs, ikeSA.RemoteVIPs...), ", "),
		}
		ch <- prometheus.MustNewConstMetric(e.ikeSAState, prometheus.GaugeValue, ikeSAStates[ikeSA.State], labelValues...)
		if ikeSA.State == "ESTABLISHED" && ikeSA.Established != nil {
			ch <- prometheus.MustNewConstMetric(e.establishedIKESA, prometheus.GaugeValue, float64(*ikeSA.Established), labelValues...)
		}
		for _, childSA := range ikeSA.ChildSAs {
			childLabelValues := append(labelValues, []string{
				childSA.Name,
				strconv.FormatUint(uint64(childSA.UID), 10),
				childSA.Mode,
				childSA.Protocol,
				strconv.FormatUint(uint64(childSA.ReqID), 10),
				strings.Join(childSA.LocalTS, ", "),
				strings.Join(childSA.RemoteTS, ", "),
			}...)
			ch <- prometheus.MustNewConstMetric(e.childSAState, prometheus.GaugeValue, childSAStates[childSA.State], childLabelValues...)
			ch <- prometheus.MustNewConstMetric(e.childSABytesIn, prometheus.GaugeValue, float64(childSA.InBytes), childLabelValues...)
			ch <- prometheus.MustNewConstMetric(e.childSAPacketsIn, prometheus.GaugeValue, float64(childSA.InPackets), childLabelValues...)
			ch <- prometheus.MustNewConstMetric(e.childSABytesOut, prometheus.GaugeValue, float64(childSA.OutBytes), childLabelValues...)
			ch <- prometheus.MustNewConstMetric(e.childSAPacketsOut, prometheus.GaugeValue, float64(childSA.OutPackets), childLabelValues...)
			if childSA.Installed != nil {
				ch <- prometheus.MustNewConstMetric(e.childSAInstalled, prometheus.GaugeValue, float64(*childSA.Installed), childLabelValues...)
			}
		}
	}
}

// New returns an initialized exporter.
func New(collectorType int, address *url.URL, timeout time.Duration, ipsecCmd []string, logger log.Logger) (*Exporter, error) {
	e := &Exporter{
		address:  address,
		timeout:  timeout,
		ipsecCmd: ipsecCmd,
		logger:   logger,

		up: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "up"),
			"Was the last scrape successful.",
			nil,
			nil,
		),
		uptime: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "uptime_seconds"),
			"Number of seconds since the daemon started.",
			nil,
			nil,
		),
		workers: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "workers_total"),
			"Number of worker threads.",
			nil,
			nil,
		),
		idleWorkers: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "idle_workers"),
			"Number of idle worker threads.",
			nil,
			nil,
		),
		activeWorkers: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "active_workers"),
			"Number of threads processing jobs.",
			nil,
			nil,
		),
		queues: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "queues"),
			"Number of queued jobs.",
			[]string{"priority"},
			nil,
		),
		ikeSAs: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "ike_sas"),
			"Number of currently registered IKE SAs.",
			nil,
			nil,
		),
		halfOpenIKESAs: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "half_open_ike_sas"),
			"Number of IKE SAs in half-open state.",
			nil,
			nil,
		),
		poolIPs: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "pool_ips_total"),
			"Number of addresses in the pool.",
			[]string{"name", "address"},
			nil,
		),
		onlinePoolIPs: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "online_pool_ips"),
			"Number of leases online.",
			[]string{"name", "address"},
			nil,
		),
		offlinePoolIPs: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "offline_pool_ips"),
			"Number of leases offline.",
			[]string{"name", "address"},
			nil,
		),
		ikeSAState: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "ike_sa_state"),
			"IKE SA state.",
			ikeSALbls,
			nil,
		),
		establishedIKESA: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "ike_sa_established_seconds"),
			"Number of seconds since the IKE SA has been established.",
			ikeSALbls,
			nil,
		),
		childSAState: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "child_sa_state"),
			"Child SA state.",
			childSALbls,
			nil,
		),
		childSABytesIn: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "child_sa_bytes_in"),
			"Number of input bytes processed.",
			childSALbls,
			nil,
		),
		childSAPacketsIn: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "child_sa_packets_in"),
			"Number of input packets processed.",
			childSALbls,
			nil,
		),
		childSABytesOut: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "child_sa_bytes_out"),
			"Number of output bytes processed.",
			childSALbls,
			nil,
		),
		childSAPacketsOut: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "child_sa_packets_out"),
			"Number of output packets processed.",
			childSALbls,
			nil,
		),
		childSAInstalled: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "child_sa_installed_seconds"),
			"Number of seconds since the child SA has been installed.",
			childSALbls,
			nil,
		),
	}
	switch collectorType {
	case CollectorVICI:
		e.scrape = (*Exporter).scrapeVICI
	case CollectorIpsec:
		e.scrape = (*Exporter).scrapeIpsec
	default:
		return nil, fmt.Errorf("unknown collector type %d", collectorType)
	}
	return e, nil
}
