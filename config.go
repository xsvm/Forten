package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	adapter    = "Forten"
	tunnelIPv4 = "198.19.0.1"
	doh        = "https://1.1.1.1/dns-query"
	limit      = 16 << 20
)

type Config struct {
	Subscription string           `json:"subscription,omitempty"`
	Nodes        []map[string]any `json:"nodes"`
	Default      string           `json:"default_node"`
	Policies     []Policy         `json:"policies"`
}

type Policy struct {
	Exe   string `json:"exe"`
	Node  string `json:"node"`
	Rules []Rule `json:"rules"`
}

type Rule struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Node  string `json:"node"`
}

var client = &http.Client{
	Timeout: 25 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return httpsURL(req.URL)
	},
}

func httpsURL(u *url.URL) error {
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("subscription endpoints must use HTTPS without URL userinfo")
	}
	return nil
}

func bounded(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err == nil && len(data) > limit {
		err = errors.New("input exceeds 16 MiB")
	}
	return data, err
}

func download(source string) ([]byte, error) {
	u, err := url.Parse(source)
	if err != nil {
		return nil, errors.New("invalid subscription URL")
	}
	if err = httpsURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid subscription request")
	}
	req.Header.Set("User-Agent", "clash.meta")
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("subscription request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription HTTP status %d", res.StatusCode)
	}
	return bounded(res.Body)
}

func importNodes(source string, remote bool) ([]map[string]any, error) {
	var data []byte
	var err error
	if remote {
		data, err = download(source)
	} else {
		f, openErr := os.Open(source)
		if openErr != nil {
			return nil, openErr
		}
		defer f.Close()
		data, err = bounded(f)
	}
	if err != nil {
		return nil, err
	}
	var profile struct {
		Proxies   []map[string]any `yaml:"proxies"`
		Providers map[string]struct {
			Type string
			URL  string
		} `yaml:"proxy-providers"`
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(&profile); err != nil {
		return nil, errors.New("invalid Clash YAML")
	}
	if len(profile.Providers) > 8 {
		return nil, errors.New("at most 8 HTTP proxy providers are supported")
	}
	for _, provider := range profile.Providers {
		if provider.Type != "http" {
			return nil, errors.New("only HTTPS-backed HTTP proxy providers are supported")
		}
		raw, err := download(provider.URL)
		if err != nil {
			return nil, err
		}
		var payload struct{ Proxies []map[string]any }
		if yaml.Unmarshal(raw, &payload) != nil || len(payload.Proxies) == 0 {
			return nil, errors.New("provider must return Clash YAML with proxies")
		}
		profile.Proxies = append(profile.Proxies, payload.Proxies...)
	}
	if len(profile.Proxies) == 0 || len(profile.Proxies) > 4096 {
		return nil, errors.New("expected between 1 and 4096 Clash nodes")
	}
	seen := map[string]bool{}
	nodes := make([]map[string]any, 0, len(profile.Proxies))
	for _, proxy := range profile.Proxies {
		name, _ := proxy["name"].(string)
		if !usableProxy(proxy) {
			continue
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate node name %q", name)
		}
		seen[name] = true
		nodes = append(nodes, proxy)
	}
	if len(nodes) == 0 {
		return nil, errors.New("no supported standalone proxy nodes were found")
	}
	return nodes, nil
}

var supported = map[string]bool{
	"ss": true, "ssr": true, "vmess": true, "vless": true, "trojan": true,
	"hysteria": true, "hysteria2": true, "tuic": true, "socks5": true,
	"http": true, "anytls": true,
}

func usableProxy(p map[string]any) bool {
	kind, _ := p["type"].(string)
	name, _ := p["name"].(string)
	server, _ := p["server"].(string)
	if !supported[kind] || strings.TrimSpace(name) == "" || strings.EqualFold(name, "REJECT") ||
		strings.EqualFold(name, "DIRECT") || strings.TrimSpace(server) == "" {
		return false
	}
	for _, key := range []string{"dialer-proxy", "interface-name", "routing-mark", "certificate", "private-key", "ca", "ca-str"} {
		if v := p[key]; v != nil && v != "" {
			return false
		}
	}
	return true
}

func exePath(path string) (string, error) {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") ||
		strings.HasPrefix(path, `\\`) || strings.ContainsAny(path, "\r\n") {
		return "", errors.New("use an absolute local .exe path")
	}
	return filepath.Clean(path), nil
}

var domainPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*$`)

func normalizedRule(rule Rule) (Rule, error) {
	rule.Type = strings.ToUpper(strings.TrimSpace(rule.Type))
	rule.Value = strings.TrimSpace(rule.Value)
	switch rule.Type {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
		if !domainPattern.MatchString(rule.Value) {
			return rule, errors.New("use a domain or keyword in ASCII/Punycode")
		}
	case "IP-CIDR", "IP-CIDR6":
		prefix, err := netip.ParsePrefix(rule.Value)
		if err != nil || (rule.Type == "IP-CIDR") != prefix.Addr().Is4() {
			return rule, errors.New("invalid CIDR or mismatched address family")
		}
		rule.Value = prefix.Masked().String()
	case "DST-PORT":
		parts := strings.Split(rule.Value, "-")
		if len(parts) > 2 {
			return rule, errors.New("use a port or a port range")
		}
		start := 0
		for _, part := range parts {
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 || port < start || strconv.Itoa(port) != part {
				return rule, errors.New("invalid port or range")
			}
			start = port
		}
	case "NETWORK":
		rule.Value = strings.ToLower(rule.Value)
		if rule.Value != "tcp" && rule.Value != "udp" {
			return rule, errors.New("network must be TCP or UDP")
		}
	default:
		return rule, fmt.Errorf("unsupported rule type %q", rule.Type)
	}
	return rule, nil
}

func processPattern(path string) string {
	pattern := regexp.QuoteMeta(path)
	pattern = strings.NewReplacer(`\(`, `\x28`, `\)`, `\x29`, ",", `\x2c`).Replace(pattern)
	return "^" + pattern + "$"
}

func (c *Config) render(controller, secret string, tun bool) ([]byte, error) {
	aliases := map[string]string{}
	proxies := []map[string]any{}
	for _, original := range c.Nodes {
		if !usableProxy(original) {
			return nil, errors.New("configuration contains an unsupported node")
		}
		name := original["name"].(string)
		if aliases[name] != "" {
			return nil, fmt.Errorf("duplicate node %q", name)
		}
		alias := fmt.Sprintf("FortenNode%04d", len(proxies)+1)
		aliases[name] = alias
		copy := make(map[string]any, len(original))
		for key, value := range original {
			copy[key] = value
		}
		copy["name"] = alias
		proxies = append(proxies, copy)
	}
	defaultNode := aliases[c.Default]
	if defaultNode == "" {
		return nil, errors.New("select a default proxy node first")
	}
	target := func(node string) (string, error) {
		if node == "REJECT" {
			return node, nil
		}
		if alias := aliases[node]; alias != "" {
			return alias, nil
		}
		return "", fmt.Errorf("node %q is unavailable", node)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// Permit subscription refresh through the selected node while unbound
	// application traffic is rejected. No local proxy port is exposed.
	rules := []string{"PROCESS-PATH-REGEX," + processPattern(self) + "," + defaultNode}
	subRules := map[string][]string{}
	seen := map[string]bool{}
	for index, policy := range c.Policies {
		path, err := exePath(policy.Exe)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(path)
		if seen[key] {
			return nil, fmt.Errorf("duplicate application %s", path)
		}
		seen[key] = true
		node, err := target(policy.Node)
		if err != nil {
			return nil, err
		}
		sub := fmt.Sprintf("forten-app-%d", index)
		rules = append(rules, "SUB-RULE,(PROCESS-PATH-REGEX,"+processPattern(path)+"),"+sub)
		for _, input := range policy.Rules {
			rule, err := normalizedRule(input)
			if err != nil {
				return nil, err
			}
			dest, err := target(rule.Node)
			if err != nil {
				return nil, err
			}
			line := rule.Type + "," + rule.Value + "," + dest
			if strings.HasPrefix(rule.Type, "IP-CIDR") {
				line += ",no-resolve"
			}
			subRules[sub] = append(subRules[sub], line)
		}
		subRules[sub] = append(subRules[sub], "MATCH,"+node)
	}
	fallback := "REJECT"
	if len(c.Policies) == 0 {
		fallback = defaultNode
	}
	rules = append(rules, "MATCH,"+fallback)
	return yaml.Marshal(map[string]any{
		"mode": "rule", "log-level": "warning", "ipv6": true, "find-process-mode": "always",
		"external-controller": controller, "secret": secret,
		"allow-lan": false, "proxies": proxies, "rules": rules, "sub-rules": subRules,
		"tun": map[string]any{
			"enable": tun, "device": adapter, "stack": "mixed", "auto-route": true,
			"auto-detect-interface": true, "strict-route": true, "dns-hijack": []string{"any:53", "tcp://any:53"},
			"inet6-address": []string{"fd6a:4f52:5445::1/126"},
		},
		"dns": map[string]any{
			// Mihomo derives the TUN IPv4 address from the fake-IP range.
			"enable": true, "ipv6": true, "enhanced-mode": "fake-ip", "fake-ip-range": tunnelIPv4 + "/16",
			"use-hosts": false, "use-system-hosts": false,
			"default-nameserver": []string{doh}, "proxy-server-nameserver": []string{doh},
			"nameserver": []string{doh + "#" + defaultNode},
		},
		"sniffer": map[string]any{
			"enable": true, "force-dns-mapping": true, "parse-pure-ip": true,
			"override-destination": false,
			"sniff":                map[string]any{"HTTP": map[string]any{"ports": []string{"80", "8080"}}, "TLS": map[string]any{"ports": []int{443, 8443}}, "QUIC": map[string]any{"ports": []int{443, 8443}}},
		},
	})
}

func loopbackEndpoint() (string, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}
