package server

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

// Scope enforcement in the recording proxy, and the scope policy that pins a
// task's exact in-scope hosts. Both are off by default.
//
// The target gate reads targets from the literal text of a command, so a host
// held in a variable, built by printf, or written to a script it never sees.
// The proxy sees every request a proxied client makes, whatever wrote it, so
// it is the layer that enforces scope for all of them. It knows no task: a
// request passes when any non-archived task's allow rules list its host on
// port 80 or 443, an active pin covers it, or it is exempt from the gate.
const (
	settingProxyScopeEnforcement = "proxy_scope_enforcement"
	settingTargetScopeAutoPin    = "target_scope_autopin"
)

const (
	// scopeSnapshotTTL bounds how long a change to rules, pins or the setting
	// takes to reach the proxy.
	scopeSnapshotTTL = 3 * time.Second
	// scopeRecheckAge: a refusal from a snapshot older than this is checked
	// once more against a fresh one, so a pin approved a moment ago is not
	// refused for a whole TTL.
	scopeRecheckAge = 250 * time.Millisecond
)

type taskScopeRules struct {
	id           int64
	block, allow []pgdb.AssetInterceptRule
}

type scopeSnapshot struct {
	built   time.Time
	enabled bool
	// err is why the scope could not be read; only exemptions pass then.
	err    error
	exempt map[string]bool // TargetKey(host, port)
	block  []pgdb.AssetInterceptRule
	tasks  []taskScopeRules
	pins   []*pgdb.TargetPin
}

func scopeCandidates(host string) (domains, ips []string) {
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, []string{host}
	}
	return []string{host}, nil
}

func scopeURL(host string, port int) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	switch port {
	case 443:
		return "https://" + host + "/"
	case 80:
		return "http://" + host + "/"
	}
	return fmt.Sprintf("https://%s:%d/", host, port)
}

// allows decides one request: exemptions, then global block rules, then the
// allow rules of each task (ports 80 and 443 only, since allow rules name no
// port), then active pins, which carry their own port.
func (s *scopeSnapshot) allows(host string, port int) (bool, string) {
	if !s.enabled {
		return true, ""
	}
	if s.exempt[pgdb.TargetKey(host, port)] {
		return true, ""
	}
	if s.err != nil {
		return false, "the authorized scope could not be read: " + s.err.Error()
	}
	domains, ips := scopeCandidates(host)
	urls := []string{scopeURL(host, port)}
	if r, _, hit := pgdb.MatchAssetInterceptRules(s.block, domains, ips, urls); hit {
		return false, r.Reason()
	}
	if port == 80 || port == 443 {
		for _, t := range s.tasks {
			if pgdb.EvaluateAssetGate(t.block, t.allow, domains, ips, urls).Allowed {
				return true, ""
			}
		}
	}
	for _, p := range s.pins {
		if strings.EqualFold(p.Host, host) && (p.Port == port || p.Port == 0) {
			return true, ""
		}
	}
	return false, "no task's allow rules list it on port 80 or 443, no approved pin covers it, and it is not exempt"
}

func hasEnabledAllow(rules []pgdb.AssetInterceptRule) bool {
	for _, r := range rules {
		if r.Enabled {
			return true
		}
	}
	return false
}

// buildScopeSnapshot reads the scope. While enforcement is on, any read that
// fails makes the snapshot refuse every target that is not exempt. The setting
// itself is read without a default, so a database error keeps the last known
// state instead of turning enforcement off.
func (m *Manager) buildScopeSnapshot(prev *scopeSnapshot) *scopeSnapshot {
	s := &scopeSnapshot{built: time.Now(), exempt: map[string]bool{}}
	for _, e := range m.interceptor.DerivedExemptions() {
		s.exempt[pgdb.TargetKey(e.Host, e.Port)] = true
	}
	fail := func(what string, err error) *scopeSnapshot {
		s.err = fmt.Errorf("%s: %w", what, err)
		log.Printf("[scope] %v; refusing every target that is not exempt until it can be read", s.err)
		return s
	}
	v, set, err := m.pg.GetSetting(settingProxyScopeEnforcement)
	if err != nil {
		s.enabled = prev != nil && prev.enabled
		return fail("enforcement setting", err)
	}
	if s.enabled = set && (v == "true" || v == "1"); !s.enabled {
		return s
	}
	stored, _, err := m.interceptor.Exemptions()
	if err != nil {
		return fail("exemptions", err)
	}
	for _, e := range stored {
		s.exempt[pgdb.TargetKey(e.Host, e.Port)] = true
	}
	if s.block, err = m.pg.ListAssetInterceptRules(); err != nil {
		return fail("global asset rules", err)
	}
	tasks, err := m.pg.ListTasks()
	if err != nil {
		return fail("tasks", err)
	}
	for _, t := range tasks {
		block, allow, err := m.assets.TaskInterceptRulesSplit(t.ID)
		if err != nil {
			return fail(fmt.Sprintf("rules of task %d", t.ID), err)
		}
		// A task without allow rules has no whitelist, and EvaluateAssetGate
		// would allow everything for it.
		if hasEnabledAllow(allow) {
			s.tasks = append(s.tasks, taskScopeRules{id: t.ID, block: block, allow: allow})
		}
	}
	if s.pins, err = m.pg.AllActiveTargetPins(); err != nil {
		return fail("target pins", err)
	}
	return s
}

func (m *Manager) currentScope(fresh bool) *scopeSnapshot {
	m.scopeMu.Lock()
	defer m.scopeMu.Unlock()
	if fresh || m.scopeSnap == nil || time.Since(m.scopeSnap.built) >= scopeSnapshotTTL {
		m.scopeSnap = m.buildScopeSnapshot(m.scopeSnap)
	}
	return m.scopeSnap
}

// proxyHostPolicy is the recording proxy's HostPolicy.
func (m *Manager) proxyHostPolicy(host string, port int) (bool, string) {
	snap := m.currentScope(false)
	ok, reason := snap.allows(host, port)
	if !ok && time.Since(snap.built) >= scopeRecheckAge {
		ok, reason = m.currentScope(true).allows(host, port)
	}
	return ok, reason
}

// ProxyScopeActive reports whether the recording proxy enforces scope on
// Bash egress now: the proxy runs, capture routes Bash through it, and the
// setting is on. With capture off Bash leaves through the global proxy or
// directly, and nothing enforces scope.
func (m *Manager) ProxyScopeActive() bool {
	return m.traffic != nil && m.TrafficEnabled() && m.pg.GetBool(settingProxyScopeEnforcement, false)
}

// ScopeAutoPinActive reports whether the scope policy may pin targets. It
// requires proxy enforcement: without it a pin from policy would rest on the
// target gate alone, which a host it cannot read escapes.
func (m *Manager) ScopeAutoPinActive() bool {
	return m.pg.GetBool(settingTargetScopeAutoPin, false) && m.ProxyScopeActive()
}
