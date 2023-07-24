package cache

import (
	"errors"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/server/types"
)

type stubCache struct {
	getFunc func(key string) (types.DataResponseV1, bool, error)
	setFunc func(key string, value types.DataResponseV1) error
}

var _ Cacher = &stubCache{}

func (s *stubCache) Get(key string) (types.DataResponseV1, bool, error) {
	return s.getFunc(key)
}

func (s *stubCache) Set(key string, value types.DataResponseV1) error {
	return s.setFunc(key, value)
}

func TestMetrics(t *testing.T) {
	key := "test-key"
	value := types.DataResponseV1{}

	s := &stubCache{}
	m := NewMetrics(s)

	// Successful requests
	s.getFunc = func(_ string) (types.DataResponseV1, bool, error) {
		return types.DataResponseV1{}, true, nil
	}
	s.setFunc = func(_ string, _ types.DataResponseV1) error {
		return nil
	}
	m.Get(key)
	m.Set(key, value)

	// Error requests
	s.getFunc = func(_ string) (types.DataResponseV1, bool, error) {
		return types.DataResponseV1{}, false, errors.New("test error")
	}
	s.setFunc = func(_ string, _ types.DataResponseV1) error {
		return errors.New("test error")
	}
	m.Get(key)
	m.Set(key, value)

	// Cache miss
	s.getFunc = func(_ string) (types.DataResponseV1, bool, error) {
		return types.DataResponseV1{}, false, nil
	}
	m.Get(key)

	expectedMetrics := strings.NewReader(`
# HELP opa_cache_requests_total Counts the number of requests to the authentication cache.
# TYPE opa_cache_requests_total counter
opa_cache_requests_total{method="get",result="error"} 1
opa_cache_requests_total{method="get",result="hit"} 1
opa_cache_requests_total{method="get",result="miss"} 1
opa_cache_requests_total{method="set",result="error"} 1
opa_cache_requests_total{method="set",result="success"} 1
`)

	if err := testutil.CollectAndCompare(m, expectedMetrics, metricNameCacheRequests); err != nil {
		t.Errorf("collected metrics do not match: %s", err)
	}
}
