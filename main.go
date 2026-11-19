package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var commands = []string{
	"status", "nodes", "policies", "connections", "validate", "start", "stop", "release",
	"subscription import (--url HTTPS_URL | --file YAML | --stdin)", "subscription refresh",
	"node select --name NAME", "policy set --exe PATH --node NAME [--rules JSON_FILE|-]",
	"policy remove --exe PATH",
}

func main() {
	result, err := run(os.Args[1:])
	if err != nil {
		writeJSON(os.Stderr, map[string]any{"ok": false, "error": err.Error()})
		os.Exit(1)
	}
	if result != nil {
		if err := writeJSON(os.Stdout, result); err != nil {
			os.Exit(1)
		}
	}
}

func nodeNames(c Config) []string {
	names := make([]string, 0, len(c.Nodes))
	for _, node := range c.Nodes {
		name, _ := node["name"].(string)
		names = append(names, name)
	}
	return names
}

func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}

func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	return nil
}

func run(args []string) (any, error) {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		return map[string]any{"name": "Forten", "api_version": 1, "commands": commands}, nil
	}
	s, err := openStore()
	if err != nil {
		return nil, err
	}
	if args[0] == "_worker" && len(args) == 2 && elevated() {
		return nil, s.worker(args[1])
	}
	var c Config
	// Every CLI operation takes the same lock so status and config revisions
	// are consistent with concurrent edits and runtime transitions.
	lock, err := s.lock("control.lock")
	if err != nil {
		return nil, err
	}
	if lock == nil {
		return nil, errors.New("another Forten command is running; retry shortly")
	}
	defer lock.Close()
	if err := s.read(configFile, &c); err != nil {
		if !(len(args) == 1 && (args[0] == "release" || args[0] == "stop")) {
			return nil, fmt.Errorf("read settings: %w", err)
		}
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	revision := fmt.Sprintf("%x", sha256.Sum256(encoded))
	ok := map[string]any{"ok": true}
	if len(args) == 1 {
		switch args[0] {
		case "nodes":
			return map[string]any{"nodes": nodeNames(c), "selected": c.Default}, nil
		case "policies":
			if c.Policies == nil {
				c.Policies = []Policy{}
			}
			return map[string]any{"policies": c.Policies}, nil
		case "status":
			return s.status(c, revision)
		case "connections":
			return s.connections()
		case "validate":
			return ok, s.start(c, revision, true)
		case "start":
			return ok, s.start(c, revision, false)
		case "stop", "release":
			if !elevated() {
				return nil, errors.New("run this command from an Administrator terminal")
			}
			if err := s.stop(); err != nil {
				return nil, err
			}
			if args[0] == "release" {
				return ok, s.release()
			}
			return ok, nil
		}
	}
	if len(args) < 2 {
		return nil, errors.New("unknown command; run forten help")
	}
	switch args[0] + " " + args[1] {
	case "subscription import", "subscription refresh":
		f := flags("subscription")
		url := f.String("url", "", "")
		file := f.String("file", "", "")
		stdin := f.Bool("stdin", false, "")
		if err := parse(f, args[2:]); err != nil {
			return nil, err
		}
		source, remote := *file, false
		if args[1] == "refresh" {
			if len(args) != 2 || c.Subscription == "" {
				return nil, errors.New("refresh requires a saved HTTPS subscription and no flags")
			}
			source, remote = c.Subscription, true
		} else {
			if *stdin {
				if *url != "" || *file != "" {
					return nil, errors.New("choose exactly one subscription source")
				}
				raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
				if err != nil || len(raw) > 8192 {
					return nil, errors.New("invalid subscription URL on stdin")
				}
				*url = strings.TrimSpace(string(raw))
			}
			if (*url == "") == (*file == "") {
				return nil, errors.New("choose exactly one of --url, --stdin, or --file")
			}
			if *url != "" {
				source, remote = *url, true
			}
		}
		nodes, err := importNodes(source, remote)
		if err != nil {
			return nil, err
		}
		c.Nodes, c.Subscription = nodes, ""
		if remote {
			c.Subscription = source
		}
		if c.Default == "" || (args[1] == "import" && !hasNode(c, c.Default)) {
			c.Default = nodeNames(c)[0]
		}
		if err := s.checkCore(c); err != nil {
			return nil, err
		}
		ok["nodes"] = nodeNames(c)
		ok["selected"] = c.Default
	case "node select":
		f := flags("node select")
		name := f.String("name", "", "")
		if err := parse(f, args[2:]); err != nil {
			return nil, err
		}
		if !hasNode(c, *name) {
			return nil, errors.New("unknown node; use forten nodes to list available names")
		}
		c.Default = *name
	case "policy set", "policy remove":
		if err := editPolicy(&c, args[1], args[2:]); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown command; run forten help")
	}
	if _, err := c.render("", "", false); err != nil {
		return nil, err
	}
	ok["requires_start"] = true
	return ok, s.write(configFile, c)
}

func hasNode(c Config, name string) bool {
	for _, node := range c.Nodes {
		if node["name"] == name {
			return true
		}
	}
	return false
}

func editPolicy(c *Config, action string, args []string) error {
	f := flags("policy " + action)
	path := f.String("exe", "", "")
	var node, rules *string
	if action == "set" {
		node = f.String("node", "", "")
		rules = f.String("rules", "", "")
	}
	if err := parse(f, args); err != nil {
		return err
	}
	clean, err := exePath(*path)
	if err != nil {
		return err
	}
	index := len(c.Policies)
	for i, p := range c.Policies {
		if strings.EqualFold(clean, p.Exe) {
			index = i
			break
		}
	}
	if action == "remove" {
		if index == len(c.Policies) {
			return errors.New("application policy does not exist")
		}
		c.Policies = append(c.Policies[:index], c.Policies[index+1:]...)
		return nil
	}
	policy := Policy{Exe: clean, Node: *node, Rules: []Rule{}}
	if index < len(c.Policies) {
		policy.Rules = c.Policies[index].Rules
	}
	if *rules != "" {
		raw, err := readInput(*rules)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &policy.Rules); err != nil {
			return fmt.Errorf("rules must be a JSON array: %w", err)
		}
		for i, rule := range policy.Rules {
			policy.Rules[i], err = normalizedRule(rule)
			if err != nil {
				return fmt.Errorf("rule %d: %w", i+1, err)
			}
		}
	}
	if index == len(c.Policies) {
		c.Policies = append(c.Policies, policy)
	} else {
		c.Policies[index] = policy
	}
	return nil
}

func (s Store) release() error {
	paths := []string{}
	if err := s.read(guardFile, &paths); err != nil {
		return err
	}
	if len(paths) > 0 {
		if err := releaseBlocks(paths); err != nil {
			return err
		}
	}
	return s.write(guardFile, []string{})
}

func (s Store) status(c Config, revision string) (any, error) {
	var state Runtime
	if err := s.read(stateFile, &state); err != nil {
		return nil, err
	}
	paths := []string{}
	if err := s.read(guardFile, &paths); err != nil {
		return nil, err
	}
	phase := state.Phase
	if phase == "" {
		phase = "stopped"
	}
	// Phase alone is stale after an abrupt worker exit.
	if phase == "starting" || phase == "running" {
		luid, tunnelErr := tunLUID()
		if phase == "running" && (tunnelErr != nil || luid != state.LUID || state.api("/version", nil) != nil) {
			phase = "offline"
		}
	}
	guard, err := filtersPresent(paths, 0)
	guardState := "absent"
	switch {
	case err != nil:
		guardState = "unknown"
	case !guard:
		guardState = "incomplete"
	case len(paths) > 0:
		guardState = "installed"
	}
	if phase == "running" {
		if permits, err := filtersPresent(state.Apps, state.LUID); !permits || err != nil {
			phase = "degraded"
		}
	}
	return map[string]any{
		"api_version": 1, "state": phase, "elevated": elevated(), "selected": c.Default,
		"guard": guardState, "guarded_executables": paths, "active_executables": state.Apps,
		"configured_policies": len(c.Policies), "subscription_saved": c.Subscription != "",
		"pending": c.Default != "" && revision != state.Revision, "failure": state.Failure,
	}, nil
}

func (s Store) connections() (any, error) {
	var state Runtime
	if err := s.read(stateFile, &state); err != nil {
		return nil, err
	}
	if state.Phase != "running" {
		return nil, errors.New("Forten is not running")
	}
	var response struct {
		Connections []struct {
			Metadata map[string]any `json:"metadata"`
			Chains   []string       `json:"chains"`
			Rule     string         `json:"rule"`
			Upload   int64          `json:"upload"`
			Download int64          `json:"download"`
		} `json:"connections"`
	}
	if err := state.api("/connections", &response); err != nil {
		return nil, err
	}
	result := []map[string]any{}
	for _, conn := range response.Connections {
		for i, chain := range conn.Chains {
			if n, err := strconv.Atoi(strings.TrimPrefix(chain, "FortenNode")); strings.HasPrefix(chain, "FortenNode") && err == nil && n > 0 && n <= len(state.Nodes) {
				conn.Chains[i] = state.Nodes[n-1]
			}
		}
		result = append(result, map[string]any{
			"process": conn.Metadata["processPath"], "host": conn.Metadata["host"],
			"destination_ip": conn.Metadata["destinationIP"], "destination_port": conn.Metadata["destinationPort"],
			"network": conn.Metadata["network"], "nodes": conn.Chains, "rule": conn.Rule,
			"upload": conn.Upload, "download": conn.Download,
		})
	}
	return map[string]any{"connections": result}, nil
}
