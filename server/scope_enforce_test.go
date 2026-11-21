package server

import (
	"errors"
	"testing"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

func scopedSnapshot() *scopeSnapshot {
	allow := func(id int64, pattern string) pgdb.AssetInterceptRule {
		return pgdb.AssetInterceptRule{ID: id, Enabled: true, Kind: "exact_domain", Pattern: pattern, Action: "allow"}
	}
	return &scopeSnapshot{
		built:   time.Now(),
		enabled: true,
		exempt:  map[string]bool{"pypi.org:443": true, "openrouter.ai:443": true},
		block:   []pgdb.AssetInterceptRule{{ID: 90, Enabled: true, Kind: "fuzzy_domain", Pattern: ".gov.example"}},
		tasks: []taskScopeRules{{id: 14, allow: []pgdb.AssetInterceptRule{
			allow(1, "auth.acme.example"), allow(2, "api.acme-cloud.example"), allow(3, "blocked.acme.example"),
		}, block: []pgdb.AssetInterceptRule{{ID: 4, Enabled: true, Kind: "exact_domain", Pattern: "blocked.acme.example"}}}},
		pins: []*pgdb.TargetPin{
			{Host: "github.com", Port: 443},
			{Host: "lab.internal", Port: 0},
		},
	}
}

func TestScopeSnapshotAllows(t *testing.T) {
	s := scopedSnapshot()
	for _, c := range []struct {
		host string
		port int
		want bool
	}{
		{"auth.acme.example", 443, true},
		{"auth.acme.example", 80, true},
		{"api.acme-cloud.example", 443, true},
		{"auth.acme.example", 22, false},     // allow rules name no port
		{"auth.acme.example", 8443, false},   // same
		{"x.auth.acme.example", 443, false},  // exact rule: no subdomains
		{"acme.example", 443, false},         // not listed
		{"blocked.acme.example", 443, false}, // the task's block rule beats its allow rule
		{"evil.example", 443, false},         // unlisted
		{"1.1.1.1", 443, false},              // an IP literal is not the name
		{"pypi.org", 443, true},              // exempt
		{"pypi.org", 80, false},              // exemptions are per port
		{"github.com", 443, true},            // human pin
		{"github.com", 22, false},            // pin is per port
		{"lab.internal", 5000, true},         // port-wide pin
		{"portal.gov.example", 443, false},   // global block
	} {
		if got, reason := s.allows(c.host, c.port); got != c.want {
			t.Errorf("allows(%s:%d) = %v (%s), want %v", c.host, c.port, got, reason, c.want)
		}
	}
}

func TestScopeSnapshotGlobalBlockBeatsPin(t *testing.T) {
	s := scopedSnapshot()
	s.pins = append(s.pins, &pgdb.TargetPin{Host: "portal.gov.example", Port: 443})
	if ok, _ := s.allows("portal.gov.example", 443); ok {
		t.Fatal("a pin overrode a global block rule")
	}
}

func TestScopeSnapshotDisabledAllowsAll(t *testing.T) {
	s := &scopeSnapshot{built: time.Now(), exempt: map[string]bool{}}
	if ok, _ := s.allows("anything.example", 22); !ok {
		t.Fatal("a disabled snapshot refused a request")
	}
}

func TestScopeSnapshotFailsClosed(t *testing.T) {
	s := scopedSnapshot()
	s.err = errors.New("db down")
	if ok, _ := s.allows("auth.acme.example", 443); ok {
		t.Fatal("an unreadable scope still allowed an in-scope host")
	}
	if ok, _ := s.allows("pypi.org", 443); !ok {
		t.Fatal("an unreadable scope refused an exemption")
	}
}

func TestScopeSnapshotTaskWithoutAllowRulesIsSkipped(t *testing.T) {
	// EvaluateAssetGate allows everything when a task has no allow rules; the
	// builder leaves such tasks out, and allows must not reintroduce them.
	s := &scopeSnapshot{built: time.Now(), enabled: true, exempt: map[string]bool{},
		tasks: nil}
	if ok, _ := s.allows("evil.example", 443); ok {
		t.Fatal("no task scope, yet a host was allowed")
	}
	if hasEnabledAllow([]pgdb.AssetInterceptRule{{Enabled: false, Kind: "exact_domain", Pattern: "x"}}) {
		t.Fatal("disabled allow rules count as a whitelist")
	}
}
