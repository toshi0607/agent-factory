// Package factorystate keeps the factory's shared state, the stop flag and the
// in-progress record, as objects in a Cloud Storage bucket. Requests use
// short-lived credentials from GitHub Actions OIDC through Workload Identity
// Federation and service-account impersonation; no keys are involved.
package factorystate

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/toshi0607/agent-factory/internal/claudeauth"
)

const (
	EnvProvider       = "FACTORY_GCP_WIF_PROVIDER"
	EnvServiceAccount = "FACTORY_GCP_SERVICE_ACCOUNT"
	EnvBucket         = "FACTORY_STATE_BUCKET"
)

type Config struct {
	Provider       string
	ServiceAccount string
	Bucket         string
}

var (
	providerPattern       = regexp.MustCompile(`^projects/[0-9]{1,20}/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$`)
	serviceAccountPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	bucketPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)
)

// ConfigFromEnv reports whether state is configured. Setting only some of
// the variables is an error, and the values never appear in errors.
func ConfigFromEnv(getenv func(string) string) (Config, bool, error) {
	cfg := Config{Provider: getenv(EnvProvider), ServiceAccount: getenv(EnvServiceAccount), Bucket: getenv(EnvBucket)}
	var missing []string
	for _, v := range []struct{ name, value string }{
		{EnvProvider, cfg.Provider}, {EnvServiceAccount, cfg.ServiceAccount}, {EnvBucket, cfg.Bucket},
	} {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	switch len(missing) {
	case 3:
		return Config{}, false, nil
	case 0:
	default:
		return Config{}, false, fmt.Errorf("factory state is partially configured; set %s as well, or none of the three", strings.Join(missing, " and "))
	}
	return cfg, true, cfg.Validate()
}

func (c Config) Validate() error {
	var errs []error
	if !providerPattern.MatchString(c.Provider) {
		errs = append(errs, errors.New(EnvProvider+" must be projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>"))
	}
	if !serviceAccountPattern.MatchString(c.ServiceAccount) {
		errs = append(errs, errors.New(EnvServiceAccount+" must be a service-account e-mail ending in .iam.gserviceaccount.com"))
	}
	if !bucketPattern.MatchString(c.Bucket) {
		errs = append(errs, errors.New(EnvBucket+" must be a bucket name"))
	}
	return errors.Join(errs...)
}

// FromEnv returns nil without error when state is not configured.
func FromEnv(client *http.Client) (*Store, error) {
	cfg, ok, err := ConfigFromEnv(os.Getenv)
	if err != nil || !ok {
		return nil, err
	}
	return New(cfg, client, claudeauth.ConfigFromEnv())
}
