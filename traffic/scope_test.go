package traffic

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
)

func TestSplitTarget(t *testing.T) {
	for _, c := range []struct {
		in   string
		def  int
		host string
		port int
		ok   bool
	}{
		{"Auth.Acme.example:443", 443, "auth.acme.example", 443, true},
		{"auth.acme.example", 443, "auth.acme.example", 443, true},
		{"auth.acme.example.:8443", 443, "auth.acme.example", 8443, true},
		{"[2001:db8::1]:443", 443, "2001:db8::1", 443, true},
		{"host:notaport", 443, "", 0, false},
		{"host:0", 443, "", 0, false},
		{":443", 443, "", 0, false},
	} {
		host, port, ok := splitTarget(c.in, c.def)
		if ok != c.ok || ok && (host != c.host || port != c.port) {
			t.Errorf("splitTarget(%q) = %q %d %v, want %q %d %v", c.in, host, port, ok, c.host, c.port, c.ok)
		}
	}
}

func TestEntryTargetSkipsProxyOwnRequests(t *testing.T) {
	req := httptest.NewRequest("GET", "/ssl", nil)
	if _, _, ok := entryTarget(req); ok {
		t.Fatal("a relative request to the proxy itself was read as a target")
	}
	abs := httptest.NewRequest("GET", "http://example.com/x", nil)
	if h, p, ok := entryTarget(abs); !ok || h != "example.com" || p != 80 {
		t.Fatalf("absolute request = %q %d %v", h, p, ok)
	}
}

// countingListener accepts and counts TCP connections without answering.
func countingListener(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), &n
}

func denyAll(string, int) (bool, string) { return false, "test policy" }

// A refused CONNECT is answered 403 before the proxy dials anything: the
// target sees no TCP connection, so no TLS handshake reaches it either.
func TestScopeRefusesConnectBeforeDial(t *testing.T) {
	tr, _, proxyURL := startProxy(t)
	tr.SetHostPolicy(denyAll)
	target, accepted := countingListener(t)

	c, err := net.Dial("tcp", strings.TrimPrefix(proxyURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), scopeRefusalNote) {
		t.Fatalf("CONNECT answered %d %q, want 403 with the refusal note", resp.StatusCode, body)
	}
	time.Sleep(200 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the refused target received %d connection(s)", n)
	}
}

func TestScopeRefusesPlainHTTP(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	tr, _, proxyURL := startProxy(t)
	tr.SetHostPolicy(denyAll)

	resp, err := proxyClient(t, tr, proxyURL).Get(srv.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Artex-Scope") != "refused" {
		t.Fatalf("plain HTTP answered %d, want the scope 403", resp.StatusCode)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the refused target served %d request(s)", n)
	}
}

// A request inside a tunnel is checked on its own URL, so a tunnel opened to
// an allowed host cannot carry one for a refused host: it gets the scope 403,
// which go-mitmproxy sends without going upstream.
func TestScopeRefusesInnerRequest(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	tr.SetHostPolicy(func(h string, p int) (bool, string) { return h == "allowed.example" && p == 443, "test policy" })
	s := tr.proxy.Addons[0].(*sink)
	flow := func(raw string) *mproxy.Flow {
		u, _ := url.Parse(raw)
		return &mproxy.Flow{
			Request:     &mproxy.Request{Method: "GET", URL: u, Header: http.Header{}},
			ConnContext: &mproxy.ConnContext{ClientConn: &mproxy.ClientConn{}},
		}
	}
	refused := flow("https://refused.example/x")
	s.Requestheaders(refused)
	if refused.Response == nil || refused.Response.StatusCode != http.StatusForbidden ||
		!strings.Contains(string(refused.Response.Body), scopeRefusalNote) {
		t.Fatalf("inner request to a refused host: response %+v, want the scope 403", refused.Response)
	}
	allowed := flow("https://allowed.example/x")
	s.Requestheaders(allowed)
	if allowed.Response != nil {
		t.Fatalf("inner request to an allowed host was answered by the proxy: %d", allowed.Response.StatusCode)
	}
	otherPort := flow("https://allowed.example:8443/x")
	s.Requestheaders(otherPort)
	if otherPort.Response == nil {
		t.Fatal("inner request to an allowed host on another port was forwarded")
	}
}

func TestScopeNilPolicyForwards(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	tr, _, proxyURL := startProxy(t)

	resp, err := proxyClient(t, tr, proxyURL).Get(srv.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || hits.Load() != 1 {
		t.Fatalf("without a policy: %d, %d hit(s); want 200 and 1", resp.StatusCode, hits.Load())
	}
}
