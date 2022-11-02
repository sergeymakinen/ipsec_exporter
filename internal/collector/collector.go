package collector

type Scraper interface {
	Scrape(*exporter) (metrics, bool)
}
