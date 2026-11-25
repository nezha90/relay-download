package center

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen            string   `yaml:"listen"`
	TLSCert           string   `yaml:"tls_cert"`
	TLSKey            string   `yaml:"tls_key"`
	CACert            string   `yaml:"ca_cert"`
	CAKey             string   `yaml:"ca_key"`              // optional: required for one-click A node TLS cert issuance
	PublicURL         string   `yaml:"public_url"`          // optional: e.g. "https://5.6.7.8:8440", written into deployed agents
	ReleasesDir       string   `yaml:"releases_dir"`        // directory storing uploaded agent binaries
	SSHKeyPath        string   `yaml:"ssh_key_path"`        // optional: default SSH private key path on Center host
	DBPath            string   `yaml:"db_path"`
	JWTSecret         string   `yaml:"jwt_secret"`
	CenterSecret      string   `yaml:"center_secret"`
	AdminToken        string   `yaml:"admin_token"`
	AdminTrustedCIDRs []string `yaml:"admin_trusted_cidrs"` // optional: direct client IPs or CIDRs granted passwordless admin console access
	NodeOfflineSec    int      `yaml:"node_offline_sec"`
	JWTTTLSec         int      `yaml:"jwt_ttl_sec"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse center config: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) ApplyDefaults() {
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8440"
	}
	if c.DBPath == "" {
		c.DBPath = "./data-center/center.db"
	}
	if c.ReleasesDir == "" {
		c.ReleasesDir = "./data-center/releases"
	}
	if c.NodeOfflineSec <= 0 {
		c.NodeOfflineSec = 20
	}
	if c.JWTTTLSec <= 0 {
		c.JWTTTLSec = 900 // 15 minutes
	}
}

func (c *Config) Validate() error {
	if c.TLSCert == "" || c.TLSKey == "" {
		return errors.New("tls_cert and tls_key are required")
	}
	if c.JWTSecret == "" {
		return errors.New("jwt_secret is required")
	}
	if c.CenterSecret == "" {
		return errors.New("center_secret is required")
	}
	if c.AdminToken == "" {
		return errors.New("admin_token is required")
	}
	if _, err := c.ParseAdminTrustedPrefixes(); err != nil {
		return err
	}
	return nil
}

func (c *Config) ParseAdminTrustedPrefixes() ([]netip.Prefix, error) {
	if len(c.AdminTrustedCIDRs) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(c.AdminTrustedCIDRs))
	for _, raw := range c.AdminTrustedCIDRs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("invalid admin_trusted_cidrs entry %q: %w", raw, err)
			}
			out = append(out, pfx.Masked())
		} else {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("invalid admin_trusted_cidrs entry %q: %w", raw, err)
			}
			addr = addr.Unmap()
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return out, nil
}

func (c *Config) NodeOfflineTimeout() time.Duration {
	return time.Duration(c.NodeOfflineSec) * time.Second
}

func (c *Config) JWTTTL() time.Duration {
	return time.Duration(c.JWTTTLSec) * time.Second
}
