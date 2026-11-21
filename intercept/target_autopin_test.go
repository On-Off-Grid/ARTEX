package intercept

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestPublicAddr(t *testing.T) {
	for ip, want := range map[string]bool{
		"1.1.1.1":                  true,
		"8.8.8.8":                  true,
		"2a00:1450:4001:80b::200e": true,
		"64:ff9b::101:101":         true,  // NAT64 of 1.1.1.1
		"64:ff9b::a9fe:a9fe":       false, // NAT64 of 169.254.169.254
		"64:ff9b::a00:1":           false, // NAT64 of 10.0.0.1
		"64:ff9b:1::5bd2:46ff":     false, // local-use NAT64
		"169.254.169.254":          false,
		"127.0.0.1":                false,
		"10.1.2.3":                 false,
		"172.16.0.1":               false,
		"192.168.1.1":              false,
		"100.64.0.1":               false,
		"100.100.100.200":          false,
		"0.0.0.0":                  false,
		"224.0.0.1":                false,
		"198.18.0.1":               false,
		"192.0.2.1":                false,
		"::1":                      false,
		"fe80::1":                  false,
		"fd00:ec2::254":            false,
		"2001:db8::1":              false,
		"2002:a00:1::1":            false, // 6to4 can carry any IPv4
		"::ffff:10.0.0.1":          false,
		"not-an-ip":                false,
	} {
		if got := publicAddr(ip); got != want {
			t.Errorf("publicAddr(%q) = %v, want %v", ip, got, want)
		}
	}
}

func TestScopeAutoPinPolicy(t *testing.T) {
	allow := []db.AssetInterceptRule{
		{ID: 1, Enabled: true, Kind: "exact_domain", Pattern: "auth.acme.example", Action: "allow"},
		{ID: 2, Enabled: false, Kind: "exact_domain", Pattern: "disabled.acme.example", Action: "allow"},
		{ID: 3, Enabled: true, Kind: "fuzzy_domain", Pattern: ".acme-cloud.example", Action: "allow"},
	}
	base := TargetRequest{Host: "auth.acme.example", Port: 443, Kind: TargetDomain, ResolvedIPs: []string{"1.1.1.1", "64:ff9b::101:101"}, Reason: "no_pin"}
	if policy, ok := scopeAutoPinPolicy(base, nil, allow); !ok || policy == "" {
		t.Fatalf("exact in-scope host on 443 with public addresses was not pinned")
	}
	port80 := base
	port80.Port = 80
	if _, ok := scopeAutoPinPolicy(port80, nil, allow); !ok {
		t.Error("port 80 was not pinned")
	}

	refused := map[string]func(*TargetRequest){
		"undeclared port (every port)": func(r *TargetRequest) { r.Port = 0 },
		"other port":                   func(r *TargetRequest) { r.Port = 22 },
		"new address of a pinned host": func(r *TargetRequest) { r.Reason = "new_ip" },
		"extends an existing pin":      func(r *TargetRequest) { r.Pin = &db.TargetPin{ID: 9} },
		"void exemption":               func(r *TargetRequest) { r.ExemptVoid = true },
		"ip literal":                   func(r *TargetRequest) { r.Kind, r.Host = TargetIP, "1.1.1.1" },
		"no address":                   func(r *TargetRequest) { r.ResolvedIPs = nil },
		"one private address":          func(r *TargetRequest) { r.ResolvedIPs = append(r.ResolvedIPs, "10.0.0.5") },
		"metadata via NAT64":           func(r *TargetRequest) { r.ResolvedIPs = []string{"64:ff9b::a9fe:a9fe"} },
		"subdomain of a listed host":   func(r *TargetRequest) { r.Host = "x.auth.acme.example" },
		"disabled allow rule":          func(r *TargetRequest) { r.Host = "disabled.acme.example" },
		"fuzzy allow rule only":        func(r *TargetRequest) { r.Host = "api.acme-cloud.example" },
		"unlisted host":                func(r *TargetRequest) { r.Host = "evil.example" },
	}
	for name, mutate := range refused {
		r := base
		r.ResolvedIPs = append([]string(nil), base.ResolvedIPs...)
		mutate(&r)
		if _, ok := scopeAutoPinPolicy(r, nil, allow); ok {
			t.Errorf("%s: pinned by policy, want a human decision", name)
		}
	}

	block := []db.AssetInterceptRule{{ID: 7, Enabled: true, Kind: "exact_domain", Pattern: "auth.acme.example"}}
	if _, ok := scopeAutoPinPolicy(base, block, allow); ok {
		t.Error("a host a block rule names was pinned by policy")
	}
	if _, ok := scopeAutoPinPolicy(base, nil, nil); ok {
		t.Error("pinned with no allow rules at all")
	}
}

func TestScopeAutoPinOffWithoutCheck(t *testing.T) {
	i := &Interceptor{}
	if i.tryScopeAutoPin(db.TargetScopeRef{TaskID: 14}, TargetRequest{}, 1) {
		t.Fatal("pinned with no policy check installed")
	}
	i.SetScopeAutoPin(func() bool { return false })
	if i.tryScopeAutoPin(db.TargetScopeRef{TaskID: 14}, TargetRequest{}, 1) {
		t.Fatal("pinned while the policy check reports off")
	}
	i.SetScopeAutoPin(func() bool { return true })
	if i.tryScopeAutoPin(db.TargetScopeRef{ConversationID: 3}, TargetRequest{}, 1) {
		t.Fatal("pinned a conversation target: the policy is task-scoped")
	}
}
