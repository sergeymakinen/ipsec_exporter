package collector

import (
	"github.com/spheromak/ipsec_exporter/pkg/metric"
)

type Scraper interface {
	Scrape() (metric.Metrics, error)
}
