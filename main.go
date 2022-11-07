package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/go-kit/log/level"
	"github.com/google/shlex"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
	col "github.com/spheromak/ipsec_exporter/internal/collector"
	ipsecmetrics "github.com/spheromak/ipsec_exporter/internal/collector/ipsec"
	vicimetrics "github.com/spheromak/ipsec_exporter/internal/collector/vici"
	"github.com/spheromak/ipsec_exporter/internal/ourlog"
	"github.com/spheromak/ipsec_exporter/pkg/exporter"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	viciFlag  = "vici"
	ipsecFlag = "ipsec"
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
		address     = kingpin.Flag("vici.address", "VICI socket address.").PlaceHolder(`"` + viciDefaultAddress + `"`).Default(viciDefaultAddress).URL()
		timeout     = kingpin.Flag("vici.timeout", "VICI socket connect timeout.").Default("1s").Duration()
		collector   = kingpin.Flag("collector", "Collector type to scrape metrics with. One of: [vici, ipsec]").Default(viciFlag).Enum(viciFlag, ipsecFlag)
		metricsPath = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		ipsecArgs   = kingpin.Flag("ipsec.args", "Arguments to pass to ipsec command").PlaceHolder(`"statusall"`).Default("statusall").Strings()
		webConfig   = kingpinflag.AddFlags(kingpin.CommandLine, ":9903")
	)

	flag.AddFlags(kingpin.CommandLine, ourlog.Config)
	kingpin.HelpFlag.Short('h')
	kingpin.Version(version.Print("ipsec_exporter"))
	kingpin.Parse()

	ourlog.Info("msg", "Starting ipsec_exporter", "version", version.Info())
	ourlog.Info("msg", "Build context", "context", version.BuildContext())
	//ipsecCmd := []string{"ipsec", "statusall"}
	prometheus.MustRegister(version.NewCollector("ipsec_exporter"))

	var err error
	var c col.Scraper

	if *collector == viciFlag {
		c, err = vicimetrics.New(*address, *timeout)
		if err != nil {
			ourlog.Error("msg", "Error creating vicimetrics", "err", err)
			os.Exit(1)
		}
	}

	if *collector == ipsecFlag {
		c, err = ipsecmetrics.New(*ipsecArgs)
		if err != nil {
			ourlog.Error("msg", "Error creating ipsecmetrics", "err", err)
			os.Exit(1)
		}
	}

	exporter, err := exporter.New(c)
	if err != nil {
		level.Error(ourlog.Default).Log("msg", "Error creating the exporter", "err", err)
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

	ourlog.Info("msg", "Starting server")
	err = web.ListenAndServe(
		&http.Server{},
		webConfig,
		ourlog.Default,
	)
	if err != nil {
		ourlog.Error("msg", "Error running HTTP server", "err", err)
		os.Exit(1)
	}

	ourlog.Info("msg", "Shutting down")
}
