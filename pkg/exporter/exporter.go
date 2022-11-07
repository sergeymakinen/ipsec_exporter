// Package exporter provides a collector for strongswan/libreswan IPsec stats.
package exporter

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spheromak/ipsec_exporter/internal/collector"
	"github.com/spheromak/ipsec_exporter/internal/ourlog"
	"github.com/spheromak/ipsec_exporter/pkg/metric"
)

const namespace = "ipsec"

var (
	ikeSAStates   = make(map[string]float64)
	childSAStates = make(map[string]float64)

	now = time.Now
	tz  = time.Local

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

	lsStates = map[string]float64{
		"STATE_MAIN_R0":        0,
		"STATE_MAIN_I1":        1,
		"STATE_MAIN_R1":        2,
		"STATE_MAIN_I2":        3,
		"STATE_MAIN_R2":        4,
		"STATE_MAIN_I3":        5,
		"STATE_MAIN_R3":        6,
		"STATE_MAIN_I4":        7,
		"STATE_AGGR_R0":        8,
		"STATE_AGGR_I1":        9,
		"STATE_AGGR_R1":        10,
		"STATE_AGGR_I2":        11,
		"STATE_AGGR_R2":        12,
		"STATE_QUICK_R0":       13,
		"STATE_QUICK_I1":       14,
		"STATE_QUICK_R1":       15,
		"STATE_QUICK_I2":       16,
		"STATE_QUICK_R2":       17,
		"STATE_INFO":           18,
		"STATE_INFO_PROTECTED": 19,
		"STATE_XAUTH_R0":       20,
		"STATE_XAUTH_R1":       21,
		"STATE_MODE_CFG_R0":    22,
		"STATE_MODE_CFG_R1":    23,
		"STATE_MODE_CFG_R2":    24,
		"STATE_MODE_CFG_I1":    25,
		"STATE_XAUTH_I0":       26,
		"STATE_XAUTH_I1":       27,

		"STATE_V2_PARENT_I0":            29,
		"STATE_V2_PARENT_I1":            30,
		"STATE_V2_PARENT_I2":            31,
		"STATE_V2_PARENT_R0":            32,
		"STATE_V2_PARENT_R1":            33,
		"STATE_V2_IKE_AUTH_CHILD_I0":    34,
		"STATE_V2_IKE_AUTH_CHILD_R0":    35,
		"STATE_V2_NEW_CHILD_I0":         36,
		"STATE_V2_NEW_CHILD_I1":         37,
		"STATE_V2_REKEY_IKE_I0":         38,
		"STATE_V2_REKEY_IKE_I1":         39,
		"STATE_V2_REKEY_CHILD_I0":       40,
		"STATE_V2_REKEY_CHILD_I1":       41,
		"STATE_V2_NEW_CHILD_R0":         42,
		"STATE_V2_REKEY_IKE_R0":         43,
		"STATE_V2_REKEY_CHILD_R0":       44,
		"STATE_V2_ESTABLISHED_IKE_SA":   45,
		"STATE_V2_ESTABLISHED_CHILD_SA": 46,
		"STATE_V2_IKE_SA_DELETE":        47,
		"STATE_V2_CHILD_SA_DELETE":      48,
	}
)

// Exporter collects IPsec stats via a VICI protocol or an ipsec binary
// and exports them using the prometheus metrics package.
type Exporter struct {
	collector collector.Scraper
	logCTX    context.Context

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
	var err error
	m, err := e.collector.Scrape()
	if err != nil {
		ourlog.Error("msg", "Failed to scrape", "err", err, "metric", m)
		ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 0)
		return
	}

	err = e.collect(m, ch)
	if err != nil {
		ourlog.Error("msg", "Failed to process", "err", err)
	}
}

func (e *Exporter) collect(m metric.Metrics, ch chan<- prometheus.Metric) error {
	if m.Stats.Uptime.Since != "" {
		uptime, err := time.ParseInLocation("Jan _2 15:04:05 2006", m.Stats.Uptime.Since, tz)
		if err != nil {
			ch <- prometheus.MustNewConstMetric(e.up, prometheus.GaugeValue, 0)
			return fmt.Errorf("Failed to parse uptime '%s': %w", m.Stats.Uptime, err)
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
	return nil
}

// New returns an initialized exporter.
func New(c collector.Scraper) (*Exporter, error) {
	for k, v := range lsStates {
		ikeSAStates[k] = v
		childSAStates[k] = v
	}

	e := &Exporter{
		collector: c,

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
		idleWorkers: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "idle_workers"), "Number of idle worker threads.",
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

	return e, nil
}
