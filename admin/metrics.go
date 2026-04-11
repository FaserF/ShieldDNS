package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Registry for ShieldDNS metrics
	shieldDNSRegistry = prometheus.NewRegistry()

	// Metrics definitions
	queriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shielddns_queries_total",
			Help: "Total number of DNS queries processed.",
		},
		[]string{"status", "type"},
	)

	cacheHitsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "shielddns_cache_hits_total",
			Help: "Total number of DNS queries served from cache.",
		},
	)

	queryDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "shielddns_query_duration_seconds",
			Help:    "DNS query latency in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
	)

	activeClients = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "shielddns_active_clients_count",
			Help: "Number of unique clients seen recently.",
		},
	)

	dbSizeBytes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "shielddns_db_size_bytes",
			Help: "Current size of the SQLite query database in bytes.",
		},
	)

	abuseBlockedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "shielddns_abuse_blocked_total",
			Help: "Total number of clients automatically blocked by the abuse engine.",
		},
	)
)

func initMetrics() {
	shieldDNSRegistry.MustRegister(queriesTotal)
	shieldDNSRegistry.MustRegister(cacheHitsTotal)
	shieldDNSRegistry.MustRegister(queryDuration)
	shieldDNSRegistry.MustRegister(activeClients)
	shieldDNSRegistry.MustRegister(dbSizeBytes)
	shieldDNSRegistry.MustRegister(abuseBlockedTotal)
}

// RecordQuery updates Prometheus metrics based on a Query log
func RecordQuery(q Query) {
	queriesTotal.WithLabelValues(q.Status, q.Type).Inc()
	if q.IsCacheHit {
		cacheHitsTotal.Inc()
	}
	// Convert ms to seconds for Prometheus convention
	queryDuration.Observe(q.DurationMs / 1000.0)
}

// UpdateSystemMetrics updates gauge-based metrics based on live stats
func UpdateSystemMetrics(s *Stats) {
	activeClients.Set(float64(s.UniqueClients))
	// DBSizeMB to Bytes
	dbSizeBytes.Set(s.DBSizeMB * 1024 * 1024)
}

// RecordAbuseBlock increments the abuse blocked counter
func RecordAbuseBlock() {
	abuseBlockedTotal.Inc()
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Periodic update of gauges that are not updated per query
	// We use the cached stats if available to avoid DB locks
	statsLock.RLock()
	UpdateSystemMetrics(&stats)
	statsLock.RUnlock()

	promhttp.HandlerFor(shieldDNSRegistry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}
