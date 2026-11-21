package traffic

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

// HostPolicy decides whether the recording proxy forwards a request to host on
// port. A refusal carries the reason sent back to the client.
type HostPolicy func(host string, port int) (allowed bool, reason string)

// SetHostPolicy installs the scope policy of the proxy; nil forwards every
// request, as before.
func (t *Traffic) SetHostPolicy(p HostPolicy) {
	if p == nil {
		t.hostPolicy.Store(nil)
		return
	}
	t.hostPolicy.Store(&p)
}

func (t *Traffic) allowHost(host string, port int) (bool, string) {
	p := t.hostPolicy.Load()
	if p == nil {
		return true, ""
	}
	return (*p)(host, port)
}

// schemePort is the port a URL without one dials.
func schemePort(scheme string) int {
	switch strings.ToLower(scheme) {
	case "http", "ws":
		return 80
	case "https", "wss":
		return 443
	}
	return 0
}

// splitTarget splits an authority into a lower-case host and a port, using
// def when the authority has none.
func splitTarget(authority string, def int) (string, int, bool) {
	host, portStr, err := net.SplitHostPort(authority)
	port := def
	if err != nil {
		host = authority
	} else if port, err = strconv.Atoi(portStr); err != nil {
		return "", 0, false
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	return host, port, host != "" && port > 0 && port <= 65535
}

// urlTarget returns the host and port an absolute request URL dials.
func urlTarget(u *url.URL) (string, int, bool) {
	if u == nil || u.Host == "" {
		return "", 0, false
	}
	return splitTarget(u.Host, schemePort(u.Scheme))
}

// entryTarget returns the target a request entering the proxy names: the
// authority of a CONNECT, or the URL of an absolute plain-HTTP request. A
// relative URL is a request to the proxy itself (the CA download) and names
// no target.
func entryTarget(req *http.Request) (string, int, bool) {
	if req.Method == http.MethodConnect {
		return splitTarget(req.Host, 443)
	}
	if !req.URL.IsAbs() {
		return "", 0, false
	}
	return urlTarget(req.URL)
}

const scopeRefusalNote = "Refused by ARTEX scope enforcement (the recording proxy, not the target): "

func scopeRefusalBody(host string, port int, reason string) string {
	return fmt.Sprintf("%s%s:%d is outside the authorized scope (%s). Nothing was sent to it. "+
		"Do not retry it another way: stay within the authorized hosts, or ask the operator.\n",
		scopeRefusalNote, host, port, reason)
}

// scopeEntry is the proxy's entry check (SetAuthProxy). It runs before a
// CONNECT is dialed or a plain-HTTP request is forwarded, so a refused target
// sees no connection at all. go-mitmproxy answers a false result with its own
// 407, which lands after the 403 written here and is ignored by the client.
func (t *Traffic) scopeEntry(res http.ResponseWriter, req *http.Request) (bool, error) {
	host, port, ok := entryTarget(req)
	if !ok {
		return true, nil
	}
	allowed, reason := t.allowHost(host, port)
	if allowed {
		return true, nil
	}
	log.Printf("[scope] refused %s %s:%d: %s", req.Method, host, port, reason)
	res.Header().Set("Content-Type", "text/plain; charset=utf-8")
	res.Header().Set("X-Artex-Scope", "refused")
	res.WriteHeader(http.StatusForbidden)
	_, _ = res.Write([]byte(scopeRefusalBody(host, port, reason)))
	return false, fmt.Errorf("scope enforcement refused %s:%d", host, port)
}

// scopeInner checks a request inside an intercepted tunnel, whose Host may
// name another host than the CONNECT did. A refusal answers it with a 403
// built here: go-mitmproxy then replies without going upstream, and the
// exchange is never recorded, since only the Response hook records.
func (t *Traffic) scopeInner(f *mproxy.Flow) bool {
	host, port, ok := urlTarget(f.Request.URL)
	if !ok {
		return true
	}
	allowed, reason := t.allowHost(host, port)
	if allowed {
		return true
	}
	log.Printf("[scope] refused %s %s:%d inside a tunnel: %s", f.Request.Method, host, port, reason)
	f.Response = &mproxy.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "X-Artex-Scope": {"refused"}},
		Body:       []byte(scopeRefusalBody(host, port, reason)),
	}
	return false
}
