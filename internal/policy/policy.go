package policy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Policy struct {
	Product   Product         `yaml:"product"`
	Toolchain Toolchain       `yaml:"toolchain"`
	Egress    map[string]Rule `yaml:"egress"`
	Roles     map[string]Role `yaml:"roles"`
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
	AllowedHosts []string `yaml:"allowed_hosts"`
}

type Role struct {
	Agent  string   `yaml:"agent"`
	Model  string   `yaml:"model"`
	Prompt string   `yaml:"prompt"`
	Egress []string `yaml:"egress"`
	Budget Budget   `yaml:"budget"`
}

type Budget struct {
	LLMUSDCents int `yaml:"llm_usd_cents"`
	Minutes     int `yaml:"minutes"`
}

var goArchive = regexp.MustCompile(`^go[A-Za-z0-9.]+\.linux-amd64\.tar\.gz$`)

func Load(path string) (Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return Policy{}, err
	}
	defer f.Close()

	p, err := decode(f)
	if err != nil {
		return Policy{}, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, nil
}

func decode(r io.Reader) (Policy, error) {
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
	for name, rule := range p.Egress {
		if strings.TrimSpace(name) == "" || len(rule.AllowedHosts) == 0 {
			return fmt.Errorf("egress %q must have a name and non-empty allowed_hosts", name)
		}
		for _, host := range rule.AllowedHosts {
			if strings.TrimSpace(host) == "" {
				return fmt.Errorf("egress %q contains an empty allowed host", name)
			}
		}
	}
	for name, role := range p.Roles {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(role.Agent) == "" ||
			strings.TrimSpace(role.Model) == "" || strings.TrimSpace(role.Prompt) == "" || len(role.Egress) == 0 {
			return fmt.Errorf("role %q requires a name, agent, model, prompt, and egress", name)
		}
		for _, rule := range role.Egress {
			if _, ok := p.Egress[rule]; !ok {
				return fmt.Errorf("role %q references unknown egress %q", name, rule)
			}
		}
		if role.Budget.LLMUSDCents <= 0 || role.Budget.Minutes <= 0 {
			return fmt.Errorf("role %q budget values must be positive", name)
		}
	}
	return nil
}
