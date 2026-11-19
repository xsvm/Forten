package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/tailscale/wf"
	"gopkg.in/yaml.v3"
)

func TestBoundPolicyIsIsolated(t *testing.T) {
	path := `C:\Program Files (x86)\Demo, Inc\example.exe`
	proxy := func(name string) map[string]any {
		return map[string]any{"name": name, "type": "socks5", "server": "192.0.2.1", "port": 1080}
	}
	c := Config{
		Nodes:   []map[string]any{proxy("node (A), west"), proxy("node B")},
		Default: "node (A), west",
		Policies: []Policy{{Exe: path, Node: "node (A), west", Rules: []Rule{
			{Type: "DOMAIN-SUFFIX", Value: "example.org", Node: "node B"},
			{Type: "IP-CIDR", Value: "192.0.2.1/24", Node: "REJECT"},
		}}},
	}
	raw, err := c.render("", "", true)
	if err != nil {
		t.Fatal(err)
	}
	var output struct {
		Rules    []string            `yaml:"rules"`
		SubRules map[string][]string `yaml:"sub-rules"`
	}
	if err := yaml.Unmarshal(raw, &output); err != nil {
		t.Fatal(err)
	}
	want := []string{"DOMAIN-SUFFIX,example.org,FortenNode0002", "IP-CIDR,192.0.2.0/24,REJECT,no-resolve", "MATCH,FortenNode0001"}
	if got := output.SubRules["forten-app-0"]; !slices.Equal(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if output.Rules[len(output.Rules)-1] != "MATCH,REJECT" || strings.Contains(string(raw), "DIRECT") {
		t.Fatal("protected traffic must not fall back to a direct connection")
	}
	pattern := processPattern(path)
	if strings.ContainsAny(pattern, "(),") || !regexp.MustCompile(pattern).MatchString(path) {
		t.Fatalf("process pattern does not safely represent %s: %s", path, pattern)
	}
	c.Policies[0].Node = "DIRECT"
	if _, err := c.render("", "", true); err == nil {
		t.Fatal("DIRECT must be rejected as a protected policy target")
	}
}

func TestGuardUsesPersistentBlockAndInterfacePermit(t *testing.T) {
	for family, layer := range families {
		block := guardRule("app.exe", "app-id", family, 0)
		permit := guardRule("app.exe", "app-id", family, 42)
		if block.Action != wf.ActionBlock || !block.Persistent || len(block.Conditions) != 1 ||
			permit.Action != wf.ActionPermit || permit.Persistent || len(permit.Conditions) != 2 ||
			block.Layer != layer || permit.Layer != layer || block.Weight >= permit.Weight || block.ID == permit.ID {
			t.Fatalf("invalid WFP policy pair for %s", layer)
		}
		if iface := permit.Conditions[1]; iface.Field != wf.FieldIPNexthopInterface || iface.Op != wf.MatchTypeEqual || iface.Value != uint64(42) {
			t.Fatalf("permit must only match the measured TUN interface: %#v", iface)
		}
	}
}
