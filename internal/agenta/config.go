package agenta

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	NodeID               string   `yaml:"node_id"`
	NodeName             string   `yaml:"node_name"`
	PublicAddr           string   `yaml:"public_addr"` // e.g. "https://1.2.3.4:8443"
	CenterURL            string   `yaml:"center_url"`  // e.g. "https://5.6.7.8:8440"
	CenterToken          string   `yaml:"center_token"`
	JWTSecret            string   `yaml:"jwt_secret"`
	CenterSecret         string   `yaml:"center_secret"`
	Projects             []string `yaml:"projects"` // empty = allow any project
	LocalListen          string   `yaml:"local_listen"`
	LocalToken           string   `yaml:"local_token"`
	PublicListen         string   `yaml:"public_listen"`
	TLSCert              string   `yaml:"tls_cert"`
	TLSKey               string   `yaml:"tls_key"`
	CACert               string   `yaml:"ca_cert"`
	DataDir              string   `yaml:"data_dir"`
	MaxDiskUsagePct      float64  `yaml:"max_disk_usage_pct"`
	MinFreeDiskBytes     uint64   `yaml:"min_free_disk_bytes"`
	LeaseTTLSec          int      `yaml:"lease_ttl_sec"`
	MaxConcurrentStreams int      `yaml:"max_concurrent_streams"`
	RateLimitMBps        float64  `yaml:"rate_limit_mbps"`
	HeartbeatIntervalSec int      `yaml:"heartbeat_interval_sec"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse agent-a config: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) ApplyDefaults() {
	if c.NodeName == "" {
		c.NodeName = c.NodeID
	}
	if c.LocalListen == "" {
		c.LocalListen = "127.0.0.1:18081"
	}
	if c.PublicListen == "" {
		c.PublicListen = "0.0.0.0:8443"
	}
	if c.DataDir == "" {
		c.DataDir = "./data-a"
	}
	if c.MaxDiskUsagePct <= 0 {
		c.MaxDiskUsagePct = 85.0
	}
	if c.LeaseTTLSec <= 0 {
		c.LeaseTTLSec = 300
	}
	if c.MaxConcurrentStreams <= 0 {
		c.MaxConcurrentStreams = 16
	}
	if c.HeartbeatIntervalSec <= 0 {
		c.HeartbeatIntervalSec = 5
	}
}

func (c *Config) Validate() error {
	if c.NodeID == "" {
		return errors.New("node_id is required")
	}
	if c.PublicAddr == "" {
		return errors.New("public_addr is required")
	}
	if u, err := url.Parse(c.PublicAddr); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("public_addr must be a valid https:// URL (got %q)", c.PublicAddr)
	}
	if c.CenterURL == "" {
		return errors.New("center_url is required")
	}
	if c.CenterToken == "" {
		return errors.New("center_token is required")
	}
	if c.JWTSecret == "" {
		return errors.New("jwt_secret is required")
	}
	if c.CenterSecret == "" {
		return errors.New("center_secret is required")
	}
	if c.LocalToken == "" {
		return errors.New("local_token is required")
	}
	host, _, err := net.SplitHostPort(c.LocalListen)
	if err != nil {
		return fmt.Errorf("invalid local_listen %q: %w", c.LocalListen, err)
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("local_listen must bind to a loopback address (got %q)", c.LocalListen)
		}
	}
	if c.TLSCert == "" || c.TLSKey == "" {
		return errors.New("tls_cert and tls_key are required for public listener")
	}
	return nil
}

func (c *Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatIntervalSec) * time.Second
}

func (c *Config) DefaultLeaseTTL() time.Duration {
	return time.Duration(c.LeaseTTLSec) * time.Second
}

func (c *Config) AllowsProject(projectID string) bool {
	if len(c.Projects) == 0 {
		return true
	}
	for _, p := range c.Projects {
		if p == projectID {
			return true
		}
	}
	return false
}
