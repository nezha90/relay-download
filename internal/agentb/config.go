package agentb

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	NodeID               string            `yaml:"node_id"`
	NodeName             string            `yaml:"node_name"`
	CenterURL            string            `yaml:"center_url"`
	CenterToken          string            `yaml:"center_token"`
	CACert               string            `yaml:"ca_cert"`
	Projects             map[string]string `yaml:"projects"` // project_id -> local dest directory
	StateDir             string            `yaml:"state_dir"`
	MaxConcurrent        int               `yaml:"max_concurrent"`
	MinFreeDiskBytes     uint64            `yaml:"min_free_disk_bytes"`
	RateLimitMBps        float64           `yaml:"rate_limit_mbps"`
	PollIntervalSec      int               `yaml:"poll_interval_sec"`
	HeartbeatIntervalSec int               `yaml:"heartbeat_interval_sec"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse agent-b config: %w", err)
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
	if c.StateDir == "" {
		c.StateDir = "./data-b"
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 3
	}
	if c.PollIntervalSec <= 0 {
		c.PollIntervalSec = 10
	}
	if c.HeartbeatIntervalSec <= 0 {
		c.HeartbeatIntervalSec = 2
	}
}

func (c *Config) Validate() error {
	if c.NodeID == "" {
		return errors.New("node_id is required")
	}
	if c.CenterURL == "" {
		return errors.New("center_url is required")
	}
	if c.CenterToken == "" {
		return errors.New("center_token is required")
	}
	if len(c.Projects) == 0 {
		return errors.New("at least one project destination mapping is required")
	}
	return nil
}

func (c *Config) ProjectIDs() []string {
	ids := make([]string, 0, len(c.Projects))
	for k := range c.Projects {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	return ids
}

func (c *Config) PollInterval() time.Duration {
	return time.Duration(c.PollIntervalSec) * time.Second
}

func (c *Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatIntervalSec) * time.Second
}
