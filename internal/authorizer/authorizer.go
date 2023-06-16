package authorizer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/observatorium/opa-openshift/internal/cache"
	"github.com/observatorium/opa-openshift/internal/config"
	"github.com/observatorium/opa-openshift/internal/openshift"
	"github.com/open-policy-agent/opa/server/types"
	"github.com/prometheus/prometheus/pkg/labels"
)

const (
	GetVerb    = "get"
	CreateVerb = "create"
)

type Authorizer struct {
	client  openshift.Client
	logger  log.Logger
	cache   cache.Cacher
	matcher *config.Matcher
}

type AuthzResponseData struct {
	Matchers  []*labels.Matcher `json:"matchers,omitempty"`
	MatcherOp config.MatcherOp  `json:"matcherOp,omitempty"`
}

type StatusCoder interface {
	StatusCode() int
}

type StatusCodeError struct {
	error
	SC int
}

func (s *StatusCodeError) StatusCode() int {
	return s.SC
}

func New(c openshift.Client, l log.Logger, cc cache.Cacher, matcher *config.Matcher) *Authorizer {
	return &Authorizer{client: c, logger: l, cache: cc, matcher: matcher}
}

func (a *Authorizer) Authorize(
	token,
	user string, groups []string,
	verb, resource, resourceName, apiGroup string,
	namespaces []string, path string,
) (types.DataResponseV1, error) {
	cacheKey := strings.Join([]string{
		token,
		verb, resource, resourceName, apiGroup,
		strings.Join(namespaces, ","),
	}, ":")

	res, ok, err := a.cache.Get(cacheKey)
	if err != nil {
		return types.DataResponseV1{},
			&StatusCodeError{fmt.Errorf("failed to fetch authorization response from cache: %w", err), http.StatusInternalServerError}
	}

	if ok {
		return res, nil
	}

	res, err = a.authorizeInner(user, groups, verb, resource, resourceName, apiGroup, namespaces, path)
	if err != nil {
		return types.DataResponseV1{}, err
	}

	a.cache.Set(cacheKey, res)
	return res, nil
}

func (a *Authorizer) authorizeInner(user string, groups []string, verb, resource, resourceName, apiGroup string, namespaces []string, path string) (types.DataResponseV1, error) {
	// check if user has cluster-wide access
	clusterAllow, err := a.client.SubjectAccessReview(user, groups, verb, resource, resourceName, apiGroup, "")
	if err != nil {
		return types.DataResponseV1{}, &StatusCodeError{fmt.Errorf("cluster-wide SAR failed: %w", err), http.StatusUnauthorized}
	}

	if verb == CreateVerb {
		// No namespaced checks for log collection -> allow based on cluster-wide check
		return minimalDataResponseV1(clusterAllow), nil
	}

	if clusterAllow {
		// user has cluster-wide access -> per-namespace check is not meaningful (always successful)
		return a.authorizeClusterWide(namespaces)
	}

	isMeta := isMetaRequest(path)
	level.Debug(a.logger).Log("msg", "namespaced authorization",
		"path", path,
		"namespaces", fmt.Sprintf("%s", namespaces),
		"isMetaRequest", isMeta,
	)
	if isMeta && len(namespaces) == 0 {
		// Only a metadata request and no namespaces provided -> populate with API list
		nsList, err := a.client.ListNamespaces()
		if err != nil {
			return types.DataResponseV1{}, &StatusCodeError{fmt.Errorf("failed to access api server: %w", err), http.StatusUnauthorized}
		}
		level.Debug(a.logger).Log("msg", "list namespaces for meta request",
			"namespaces", fmt.Sprintf("%s", nsList),
		)

		if len(nsList) == 0 {
			// list of namespaces is empty -> deny
			return minimalDataResponseV1(false), nil
		}

		namespaces = nsList
	}

	allowed := []string{}
	for _, ns := range namespaces {
		nsAllowed, err := a.client.SubjectAccessReview(user, groups, verb, resource, resourceName, apiGroup, ns)
		if err != nil {
			return types.DataResponseV1{},
				&StatusCodeError{fmt.Errorf("failed to authorize subject for auth backend role: %w", err), http.StatusUnauthorized}
		}
		level.Debug(a.logger).Log(
			"msg", "executed SubjectAccessReview",
			"user", user, "groups", fmt.Sprintf("%s", groups),
			"res", resource, "name", resourceName, "api", apiGroup,
			"allowed", nsAllowed, "namespace", ns,
		)

		if nsAllowed {
			allowed = append(allowed, ns)
		}
	}

	if len(allowed) == 0 {
		// all SARs were unsuccessful -> deny
		return minimalDataResponseV1(false), nil
	}

	// allow access for the namespaces where the SAR was successful
	res, err := newDataResponseV1(allowed, a.matcher)
	if err != nil {
		return types.DataResponseV1{},
			&StatusCodeError{fmt.Errorf("failed to create auth response: %w", err), http.StatusInternalServerError}
	}

	return res, nil
}

func (a *Authorizer) authorizeClusterWide(namespaces []string) (types.DataResponseV1, error) {
	if a.matcher.IsEmpty() {
		// user has cluster-wide access and does not need matcher -> allow
		return minimalDataResponseV1(true), nil
	}

	// user has cluster-wide access but needs a matcher -> populate namespaces from API list
	nsList, err := a.client.ListNamespaces()
	if err != nil {
		return types.DataResponseV1{}, &StatusCodeError{fmt.Errorf("failed to access api server: %w", err), http.StatusUnauthorized}
	}
	level.Debug(a.logger).Log("msg", "executed ListNamespaces", "namespaces", fmt.Sprintf("%s", nsList))

	if len(nsList) == 0 {
		// list of namespaces is empty -> deny
		return minimalDataResponseV1(false), nil
	}

	if len(namespaces) == 0 {
		// request was cluster-scoped, return matcher with all accessible namespaces
		return newDataResponseV1(nsList, a.matcher)
	}

	nsMap := map[string]bool{}
	for _, ns := range nsList {
		nsMap[ns] = true
	}

	filtered := []string{}
	for _, ns := range namespaces {
		if nsMap[ns] {
			filtered = append(filtered, ns)
		}
	}

	// cluster-scoped SAR was successful, so namespaced SARs will be successful as well -> return matcher
	return newDataResponseV1(filtered, a.matcher)
}

func isMetaRequest(path string) bool {
	if path == "/loki/api/v1/labels" {
		return true
	}

	if strings.HasPrefix(path, "/loki/api/v1/label/") && strings.HasSuffix(path, "/values") {
		return true
	}

	return false
}

func minimalDataResponseV1(allowed bool) types.DataResponseV1 {
	var res interface{} = allowed
	//nolint:exhaustivestruct
	return types.DataResponseV1{Result: &res}
}

func newDataResponseV1(ns []string, matcher *config.Matcher) (types.DataResponseV1, error) {
	if matcher.IsEmpty() {
		return minimalDataResponseV1(true), nil
	}

	matchers := []*labels.Matcher{}
	for _, key := range matcher.Keys {
		lm, err := labels.NewMatcher(labels.MatchRegexp, key, strings.Join(ns, "|"))
		if err != nil {
			return types.DataResponseV1{}, fmt.Errorf("failed to create new matcher: %w", err)
		}
		matchers = append(matchers, lm)
	}

	data, err := json.Marshal(&AuthzResponseData{
		Matchers:  matchers,
		MatcherOp: matcher.MatcherOp,
	})
	if err != nil {
		return types.DataResponseV1{}, fmt.Errorf("failed to marshal matcher to json: %w", err)
	}

	var res interface{} = map[string]string{
		"allowed": "true",
		"data":    string(data),
	}

	//nolint:exhaustivestruct
	return types.DataResponseV1{Result: &res}, nil
}
