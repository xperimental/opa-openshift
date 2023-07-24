package cache

import (
	"github.com/open-policy-agent/opa/server/types"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricNameCacheRequests = "opa_cache_requests_total"
	
	metricsMethodGet = "get"
	metricsMethodSet = "set"

	metricsGetResultHit   = "hit"
	metricsGetResultMiss  = "miss"
	metricsGetResultError = "error"

	metricsSetResultSuccess = "success"
	metricsSetResultError   = "error"
)

var metricsLabels = []string{"method", "result"}

type Metrics struct {
	cache         Cacher
	cacheRequests *prometheus.CounterVec
}

var (
	_ Cacher               = &Metrics{}
	_ prometheus.Collector = &Metrics{}
)

func NewMetrics(cache Cacher) *Metrics {
	return &Metrics{
		cache: cache,
		cacheRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricNameCacheRequests,
			Help: "Counts the number of requests to the authentication cache.",
		}, metricsLabels),
	}
}

func (c *Metrics) Describe(descs chan<- *prometheus.Desc) {
	c.cacheRequests.Describe(descs)
}

func (c *Metrics) Collect(metrics chan<- prometheus.Metric) {
	c.cacheRequests.Collect(metrics)
}

func (c *Metrics) Get(key string) (types.DataResponseV1, bool, error) {
	value, found, err := c.cache.Get(key)
	switch {
	case err != nil:
		c.cacheRequests.WithLabelValues(metricsMethodGet, metricsGetResultError).Inc()
	case !found:
		c.cacheRequests.WithLabelValues(metricsMethodGet, metricsGetResultMiss).Inc()
	default:
		c.cacheRequests.WithLabelValues(metricsMethodGet, metricsGetResultHit).Inc()
	}

	return value, found, err
}

func (c *Metrics) Set(key string, value types.DataResponseV1) error {
	if err := c.cache.Set(key, value); err != nil {
		c.cacheRequests.WithLabelValues(metricsMethodSet, metricsSetResultError).Inc()

		return err
	}

	c.cacheRequests.WithLabelValues(metricsMethodSet, metricsSetResultSuccess).Inc()
	return nil
}
