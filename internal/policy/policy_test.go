package policy

import (
	"os"
	"strings"
	"testing"
)

func TestPolicy(t *testing.T) {
	p, err := Load("../../policy/google-cloud-emulator.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Product.Module != "github.com/toshi0607/google-cloud-emulator" ||
		p.Toolchain.Go.SizeBytes != 66999944 || p.Roles["fixer"].Budget.LLMUSDCents != 300 {
		t.Fatalf("unexpected policy: %+v", p)
	}
}

func TestInvalidPolicies(t *testing.T) {
	data, err := os.ReadFile("../../policy/google-cloud-emulator.yaml")
	if err != nil {
		t.Fatal(err)
	}
	valid := string(data)
	for _, tt := range []struct {
		name, old, replacement, want string
	}{
		{"unknown root", "product:", "unknown: true\nproduct:", "field unknown"},
		{"unknown nested", "      minutes: 30", "      minutes: 30\n      retries: 2", "field retries"},
		{"missing module", "  module: github.com/toshi0607/google-cloud-emulator\n", "", "product.module"},
		{"bad filename", "filename: go1.26.11", "filename: ../../go1.26.11", "filename"},
		{"short checksum", "9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec", "00", "64 hex"},
		{"non-hex checksum", "9849f4e0", "Z849f4e0", "64 hex"},
		{"no hosts", "allowed_hosts:\n      - proxy.golang.org\n      - sum.golang.org", "allowed_hosts: []", "allowed_hosts"},
		{"unknown egress", "egress: [gomod]", "egress: [other]", "unknown egress"},
		{"zero budget", "llm_usd_cents: 300", "llm_usd_cents: 0", "positive"},
		{"negative minutes", "minutes: 30", "minutes: -1", "positive"},
		{"extra document", "minutes: 30\n", "minutes: 30\n---\n{}\n", "single YAML document"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decode(strings.NewReader(strings.Replace(valid, tt.old, tt.replacement, 1)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}
