package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/go-kit/kit/log/level"
	"github.com/google/shlex"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"github.com/sergeymakinen/ipsec_exporter/exporter"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Collector types.
type CollectorType int

const (
	CollectorVICI CollectorType = iota
	CollectorIpsec
)

type cmdValue []string

func (c *cmdValue) Set(s string) (err error) {
	*c, err = shlex.Split(s)
	return
}

func (c cmdValue) String() string { return strings.Join(c, " ") }

func newCmd(s kingpin.Settings) (target *[]string) {
	target = new([]string)
	s.SetValue((*cmdValue)(target))
	return
}

func main() {
	var (
		address       = kingpin.Flag("vici.address", "VICI socket address.").PlaceHolder(`"` + viciDefaultAddress + `"`).Default(viciDefaultAddress).URL()
		timeout       = kingpin.Flag("vici.timeout", "VICI socket connect timeout.").Default("1s").Duration()
		collector     = kingpin.Flag("collector", "Collector type to scrape metrics with. One of: [vici, ipsec]").Default("vici").Enum("vici", "ipsec")
		listenAddress = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9903").String()
		metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	)
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.HelpFlag.Short('h')
	kingpin.Version(version.Print("ipsec_exporter"))
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting ipsec_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())
	//ipsecCmd := []string{"ipsec", "statusall"}

	prometheus.MustRegister(version.NewCollector("ipsec_exporter"))

	col := vici.Collector
	if *collector == "vici" {
		col = ipsec.Collector
	}

	exporter, err := exporter.New()
	if err != nil {
		level.Error(logger).Log("msg", "Error creating the exporter", "err", err)
		os.Exit(1)
	}
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>IPsec Exporter</title></head>
             <body>
             <h1>IPsec Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
	srv := &http.Server{Addr: *listenAddress}
	webConfig := kingpinflag.AddFlags(kingpin.CommandLine, *listenAddress)
	if err := web.ListenAndServe(srv, webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error running HTTP server", "err", err)
		os.Exit(1)
	}
}
