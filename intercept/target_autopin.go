package intercept

import (
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// SetScopeAutoPin installs the check that reports whether the scope policy may
// pin targets without a human (nil = never). The server layer makes it true
// only while the recording proxy enforces scope, since a pin then never
// widens what the proxy lets through beyond the task's own allow rules.
func (i *Interceptor) SetScopeAutoPin(f func() bool) {
	i.mu.Lock()
	i.scopeAutoPin = f
	i.mu.Unlock()
}

// autoPinPorts are the only ports the scope policy pins. Allow rules name
// hosts, not ports, so any other port, and an undeclared one, stays a human
// decision.
var autoPinPorts = map[int]bool{80: true, 443: true}

// nonPublicPrefixes are ranges netip does not classify as private but that
// are not a public target either: shared address space, IETF protocol
// assignments, documentation, benchmarking, reserved, and the IPv6 transition
// and local-use NAT64 prefixes that can carry any IPv4 address.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

// nat64WellKnown is the NAT64 well-known prefix: the low 32 bits are an IPv4
// address, which is what is actually reached.
var nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")

// publicAddr reports whether ip is a public unicast address. An address
// under the NAT64 well-known prefix is judged by the IPv4 address it embeds.
func publicAddr(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	if nat64WellKnown.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if !a.IsGlobalUnicast() || voidsExemption(a.String()) {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// scopeAutoPinPolicy returns the policy text when t may be pinned without a
// human: a first request (no earlier pin) for a name on port 80 or 443 that
// an enabled exact_domain allow rule of the task names, no block rule hits,
// and every resolved address is public. Anything else is left to a human.
func scopeAutoPinPolicy(t TargetRequest, block, allow []db.AssetInterceptRule) (string, bool) {
	if t.Reason != "no_pin" || t.Pin != nil || t.ExemptVoid || t.Kind != TargetDomain || !autoPinPorts[t.Port] {
		return "", false
	}
	if len(t.ResolvedIPs) == 0 {
		return "", false
	}
	for _, ip := range t.ResolvedIPs {
		if !publicAddr(ip) {
			return "", false
		}
	}
	if _, _, hit := db.MatchAssetInterceptRules(block, []string{t.Host}, nil, nil); hit {
		return "", false
	}
	for _, r := range allow {
		if r.Enabled && r.Kind == "exact_domain" && strings.EqualFold(strings.TrimSpace(r.Pattern), t.Host) {
			return fmt.Sprintf("exact in-scope host %s (allow rule #%d), port %d, public addresses %s",
				t.Host, r.ID, t.Port, strings.Join(t.ResolvedIPs, ", ")), true
		}
	}
	return "", false
}

// tryScopeAutoPin settles the request row id this call just opened when the
// scope policy covers it, and reports whether it did. Every failure leaves the
// row pending for a human.
func (i *Interceptor) tryScopeAutoPin(ref db.TargetScopeRef, t TargetRequest, id int64) bool {
	i.mu.RLock()
	enabled := i.scopeAutoPin
	i.mu.RUnlock()
	if enabled == nil || ref.TaskID <= 0 || !enabled() {
		return false
	}
	block, allow, err := i.db.Assets().TaskInterceptRulesSplit(ref.TaskID)
	if err != nil {
		log.Printf("[target] scope auto-pin skipped for %s: task rules unreadable: %v", targetName(t), err)
		return false
	}
	global, err := i.db.ListAssetInterceptRules()
	if err != nil {
		log.Printf("[target] scope auto-pin skipped for %s: global rules unreadable: %v", targetName(t), err)
		return false
	}
	policy, ok := scopeAutoPinPolicy(t, append(global, block...), allow)
	if !ok {
		return false
	}
	if refused, err := i.db.TargetRefusedByHuman(ref, t.Host, t.Port); err != nil || refused {
		return false
	}
	if _, ok, err := i.db.AutoPinTargetRequest(id, policy); err != nil || !ok {
		if err != nil {
			log.Printf("[target] scope auto-pin of %s (#%d) failed: %v", targetName(t), id, err)
		}
		return false
	}
	i.pending.resolve(id, true)
	log.Printf("[target] task %d: %s pinned by scope policy (#%d)", ref.TaskID, targetName(t), id)
	return true
}
