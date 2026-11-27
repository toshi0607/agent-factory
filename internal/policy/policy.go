package policy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Policy struct {
	Product   Product           `yaml:"product"`
	Toolchain Toolchain         `yaml:"toolchain"`
	Egress    map[string]Rule   `yaml:"egress"`
	Roles     map[string]Role   `yaml:"roles"`
	Pricing   map[string]Prices `yaml:"pricing,omitempty"`
	Reflect   Reflect           `yaml:"reflect"`
}

type Product struct {
	Repository string `yaml:"repository"`
	Module     string `yaml:"module"`
}

type Toolchain struct {
	Go Go `yaml:"go"`
}

type Go struct {
	Version   string `yaml:"version"`
	Filename  string `yaml:"filename"`
	URL       string `yaml:"url"`
	SHA256    string `yaml:"sha256"`
	SizeBytes int64  `yaml:"size_bytes"`
}

type Rule struct {
	AllowedHosts []string   `yaml:"allowed_hosts"`
	PathRules    []PathRule `yaml:"path_rules,omitempty"`
}

type PathRule struct {
	Host         string   `yaml:"host" json:"host"`
	PathPrefixes []string `yaml:"path_prefixes,omitempty" json:"path_prefixes,omitempty"`
}

type Prices struct {
	Input        float64 `yaml:"input" json:"input"`
	Output       float64 `yaml:"output" json:"output"`
	CacheWrite5m float64 `yaml:"cache_write_5m" json:"cache_write_5m"`
	CacheWrite1h float64 `yaml:"cache_write_1h" json:"cache_write_1h"`
	CacheRead    float64 `yaml:"cache_read" json:"cache_read"`
}

type Role struct {
	Agent  string   `yaml:"agent"`
	Model  string   `yaml:"model"`
	Prompt string   `yaml:"prompt"`
	Egress []string `yaml:"egress"`
	Budget Budget   `yaml:"budget"`
	Write  []string `yaml:"write"`
}

type Budget struct {
	LLMUSDCents int `yaml:"llm_usd_cents"`
	Minutes     int `yaml:"minutes"`
}

var goArchive = regexp.MustCompile(`^go[A-Za-z0-9.]+\.linux-amd64\.tar\.gz$`)
var hostname = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var numericHost = regexp.MustCompile(`^[0-9.]+$`)

func Load(path string) (Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return Policy{}, err
	}
	defer f.Close()

	p, err := Decode(f)
	if err != nil {
		return Policy{}, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, nil
}

// Decode reads and validates one policy document.
func Decode(r io.Reader) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Policy{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return Policy{}, err
		}
		return Policy{}, errors.New("expected a single YAML document")
	}
	return p, p.validate()
}

func (p Policy) validate() error {
	goTool := p.Toolchain.Go
	for _, field := range []struct{ name, value string }{
		{"product.repository", p.Product.Repository},
		{"product.module", p.Product.Module},
		{"toolchain.go.version", goTool.Version},
		{"toolchain.go.filename", goTool.Filename},
		{"toolchain.go.url", goTool.URL},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	if !goArchive.MatchString(goTool.Filename) {
		return errors.New("toolchain.go.filename must match go*.linux-amd64.tar.gz")
	}
	u, err := url.Parse(goTool.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return errors.New("toolchain.go.url must be an HTTP or HTTPS download URL")
	}
	if _, err := hex.DecodeString(goTool.SHA256); len(goTool.SHA256) != 64 || err != nil {
		return errors.New("toolchain.go.sha256 must contain 64 hex characters")
	}
	if goTool.SizeBytes <= 0 {
		return errors.New("toolchain.go.size_bytes must be positive")
	}
	if len(p.Egress) == 0 || len(p.Roles) == 0 {
		return errors.New("egress and roles are required")
	}
	for model, prices := range p.Pricing {
		if strings.TrimSpace(model) == "" {
			return errors.New("pricing requires a model name")
		}
		for _, price := range []float64{prices.Input, prices.Output, prices.CacheWrite5m, prices.CacheWrite1h, prices.CacheRead} {
			if price <= 0 || math.IsNaN(price) || math.IsInf(price, 0) {
				return fmt.Errorf("pricing for %q requires positive finite prices", model)
			}
		}
	}
	for name, rule := range p.Egress {
		if strings.TrimSpace(name) == "" || len(rule.AllowedHosts)+len(rule.PathRules) == 0 {
			return fmt.Errorf("egress %q must have a name and non-empty allowed_hosts or path_rules", name)
		}
		for _, host := range rule.AllowedHosts {
			if !validHost(host) {
				return fmt.Errorf("egress %q contains an invalid lowercase hostname in allowed_hosts", name)
			}
		}
		for _, entry := range rule.PathRules {
			if !validHost(entry.Host) || len(entry.PathPrefixes) == 0 {
				return fmt.Errorf("egress %q path_rules require a lowercase hostname and path prefixes", name)
			}
			if slices.Contains(rule.AllowedHosts, entry.Host) {
				return fmt.Errorf("egress %q: host %q appears in both allowed_hosts and path_rules", name, entry.Host)
			}
			for _, prefix := range entry.PathPrefixes {
				if !strings.HasPrefix(prefix, "/") {
					return fmt.Errorf("egress %q path_rules prefixes must start with /", name)
				}
			}
		}
	}
	for name, role := range p.Roles {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(role.Agent) == "" ||
			strings.TrimSpace(role.Model) == "" || strings.TrimSpace(role.Prompt) == "" || len(role.Egress) == 0 {
			return fmt.Errorf("role %q requires a name, agent, model, prompt, and egress", name)
		}
		hosts := make(map[string]bool)
		for _, ruleName := range role.Egress {
			rule, ok := p.Egress[ruleName]
			if !ok {
				return fmt.Errorf("role %q references unknown egress %q", name, ruleName)
			}
			for _, host := range rule.AllowedHosts {
				if err := addHost(hosts, host, false); err != nil {
					return fmt.Errorf("role %q: %w", name, err)
				}
			}
			for _, entry := range rule.PathRules {
				if err := addHost(hosts, entry.Host, true); err != nil {
					return fmt.Errorf("role %q: %w", name, err)
				}
			}
		}
		if role.Budget.LLMUSDCents <= 0 || role.Budget.Minutes <= 0 {
			return fmt.Errorf("role %q budget values must be positive", name)
		}
	}
	return p.validateReflect()
}

func validHost(host string) bool {
	return len(host) <= 253 && hostname.MatchString(host) && !numericHost.MatchString(host)
}

func addHost(hosts map[string]bool, host string, restricted bool) error {
	if previous, ok := hosts[host]; ok && previous != restricted {
		return fmt.Errorf("host %q appears in both allowed_hosts and path_rules", host)
	}
	hosts[host] = restricted
	return nil
}
