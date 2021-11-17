// Package exporter provides a collector for strongswan/libreswan IPsec stats.
package exporter

import (
	"fmt"
	"math"
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
)

// Collector types.
const (
	CollectorVICI = iota
	CollectorIpsec
)

const namespace = "ipsec"

var (
	reSSMarker = regexp.MustCompile(`(?m)` + ssSAHeaderRE.String())
	reLSMarker = regexp.MustCompile(`(?m)` + lsPrefix + `Connection list:$`)
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
	ikeSAStates   = make(map[string]float64)
	childSAStates = make(map[string]float64)
)

var (
	now = time.Now
	tz  = time.Local
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

// Describe describes all the metrics exported by the IPsec exporter. It
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

// Collect fetches the statistics from strongswan/libreswan, and
// delivers them as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	m, ok := e.scrape(e)
	if !ok {
		ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 0)
		return
	}

	e.collect(m, ch)
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

func (e *Exporter) collect(m metrics, ch chan<- prometheus.Metric) {
	if m.Stats.Uptime.Since != "" {
		uptime, err := time.ParseInLocation("Jan _2 15:04:05 2006", m.Stats.Uptime.Since, tz)
		if err != nil {
			ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 0)
			level.Error(e.logger).Log("msg", "Failed to parse uptime", "uptime", m.Stats.Uptime.Since, "err", err)
			return
		}
		ch <- prometheus.MustNewConstMetric(e.uptime, prometheus.GaugeValue, now().Round(time.Second).Sub(uptime).Seconds())
	}
	if m.Stats.Workers != nil {
		ch <- prometheus.MustNewConstMetric(e.workers, prometheus.GaugeValue, float64(m.Stats.Workers.Total))
		ch <- prometheus.MustNewConstMetric(e.idleWorkers, prometheus.GaugeValue, float64(m.Stats.Workers.Idle))
		ch <- prometheus.MustNewConstMetric(e.activeWorkers, prometheus.GaugeValue, float64(m.Stats.Workers.Active.Total()))
	}
	if m.Stats.Queues != nil {
		ch <- prometheus.MustNewConstMetric(e.queues, prometheus.GaugeValue, float64(m.Stats.Queues.Critical), "critical")
		ch <- prometheus.MustNewConstMetric(e.queues, prometheus.GaugeValue, float64(m.Stats.Queues.High), "high")
		ch <- prometheus.MustNewConstMetric(e.queues, prometheus.GaugeValue, float64(m.Stats.Queues.Medium), "medium")
		ch <- prometheus.MustNewConstMetric(e.queues, prometheus.GaugeValue, float64(m.Stats.Queues.Low), "low")
	}
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
		state := math.NaN()
		if f, ok := ikeSAStates[ikeSA.State]; ok {
			state = f
		}
		if !math.IsNaN(state) {
			ch <- prometheus.MustNewConstMetric(e.ikeSAState, prometheus.GaugeValue, state, labelValues...)
		}
		if ikeSA.State == "ESTABLISHED" && ikeSA.Established != nil {
			ch <- prometheus.MustNewConstMetric(e.establishedIKESA, prometheus.GaugeValue, float64(*ikeSA.Established), labelValues...)
		}
		for _, childSA := range ikeSA.ChildSAs {
			reqID := ""
			if childSA.ReqID != nil {
				reqID = strconv.FormatUint(uint64(*childSA.ReqID), 10)
			}
			childLabelValues := append(labelValues, []string{
				childSA.Name,
				strconv.FormatUint(uint64(childSA.UID), 10),
				childSA.Mode,
				childSA.Protocol,
				reqID,
				strings.Join(childSA.LocalTS, ", "),
				strings.Join(childSA.RemoteTS, ", "),
			}...)
			state := math.NaN()
			if f, ok := childSAStates[childSA.State]; ok {
				state = f
			}
			if !math.IsNaN(state) {
				ch <- prometheus.MustNewConstMetric(e.childSAState, prometheus.GaugeValue, state, childLabelValues...)
			}
			ch <- prometheus.MustNewConstMetric(e.childSABytesIn, prometheus.GaugeValue, float64(childSA.InBytes), childLabelValues...)
			if childSA.InPackets != nil {
				ch <- prometheus.MustNewConstMetric(e.childSAPacketsIn, prometheus.GaugeValue, float64(*childSA.InPackets), childLabelValues...)
			}
			ch <- prometheus.MustNewConstMetric(e.childSABytesOut, prometheus.GaugeValue, float64(childSA.OutBytes), childLabelValues...)
			if childSA.OutPackets != nil {
				ch <- prometheus.MustNewConstMetric(e.childSAPacketsOut, prometheus.GaugeValue, float64(*childSA.OutPackets), childLabelValues...)
			}
			if childSA.Installed != nil {
				ch <- prometheus.MustNewConstMetric(e.childSAInstalled, prometheus.GaugeValue, float64(*childSA.Installed), childLabelValues...)
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 1)
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
