package exporter

import (
	"bytes"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

func collect(t *testing.T, c prometheus.Collector) []byte {
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(c); err != nil {
		t.Fatalf("failed to register exporter: %v", err)
	}
	got, err := reg.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.FmtText)
	for _, mf := range got {
		if err := enc.Encode(mf); err != nil {
			t.Fatalf("failed to encode metric: %v", err)
		}
	}
	return buf.Bytes()
}

var redactedLbls = []string{
	"uid",
	"ike_sa_uid",
	"reqid",
}

type redactedMetric struct {
	prometheus.Metric
}

func (m redactedMetric) Write(out *dto.Metric) error {
	if err := m.Metric.Write(out); err != nil {
		return err
	}
	for _, lbl := range out.Label {
		for _, name := range redactedLbls {
			if lbl.Name != nil && lbl.Value != nil && *lbl.Name == name && *lbl.Value != "" {
				*lbl.Value = "X"
				break
			}
		}
	}
	return nil
}

type redactor struct {
	prometheus.Collector
}

func (r redactor) Collect(ch chan<- prometheus.Metric) {
	buf := make(chan prometheus.Metric)
	go func() {
		r.Collector.Collect(buf)
		close(buf)
	}()
	for m := range buf {
		ch <- redactedMetric{m}
	}
}
