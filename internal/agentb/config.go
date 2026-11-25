package agentb

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	NodeID               string              `yaml:"node_id"`
	NodeName             string              `yaml:"node_name"`
	CenterURL            string              `yaml:"center_url"`
	CenterToken          string              `yaml:"center_token"`
	CACert               string              `yaml:"ca_cert"`
	Projects             map[string]string   `yaml:"projects,omitempty"`     // project_id -> single local dest directory
	ProjectDirs          map[string][]string `yaml:"project_dirs,omitempty"` // project_id -> multiple local dest directories for balanced multi-disk placement
	StateDir             string              `yaml:"state_dir"`
	MaxConcurrent        int                 `yaml:"max_concurrent"`
	StreamConns          int                 `yaml:"stream_conns,omitempty"`          // independent TLS 1.3 + HTTP/2 TCP sockets to saturate 1Gbps WAN links
	ClaimBatchSize       int                 `yaml:"claim_batch_size,omitempty"`      // max files claimed per RPC
	AckBatchIntervalMs   int                 `yaml:"ack_batch_interval_ms,omitempty"` // ms to buffer verified on-disk ACKs before batch-ack (<=0 = immediate)
	AckBatchSize         int                 `yaml:"ack_batch_size,omitempty"`        // flush early once pending ACKs hit this count
	MinFreeDiskBytes     uint64              `yaml:"min_free_disk_bytes"`
	RateLimitMBps        float64             `yaml:"rate_limit_mbps"`
	PollIntervalSec      int                 `yaml:"poll_interval_sec"`
	HeartbeatIntervalSec int                 `yaml:"heartbeat_interval_sec"`
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
	if c.StreamConns <= 0 {
		c.StreamConns = c.MaxConcurrent
		if c.StreamConns > 8 {
			c.StreamConns = 8
		}
		if c.StreamConns < 1 {
			c.StreamConns = 1
		}
	}
	if c.StreamConns > 32 {
		c.StreamConns = 32
	}
	if c.ClaimBatchSize <= 0 {
		c.ClaimBatchSize = 16
	}
	if c.ClaimBatchSize > 64 {
		c.ClaimBatchSize = 64
	}
	if c.AckBatchSize <= 0 {
		c.AckBatchSize = 50
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
	if len(c.ProjectIDs()) == 0 {
		return errors.New("at least one project destination mapping is required")
	}
	return nil
}

// DestDirsFor returns all configured destination directories for a project (deduplicated, preserving order).
func (c *Config) DestDirsFor(projectID string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(d string) {
		d = strings.TrimSpace(d)
		if d == "" {
			return
		}
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	for _, d := range c.ProjectDirs[projectID] {
		add(d)
	}
	if d, ok := c.Projects[projectID]; ok {
		add(d)
	}
	return out
}

func (c *Config) ProjectIDs() []string {
	seen := make(map[string]struct{})
	for k, v := range c.Projects {
		if strings.TrimSpace(v) != "" {
			seen[k] = struct{}{}
		}
	}
	for k, dirs := range c.ProjectDirs {
		for _, d := range dirs {
			if strings.TrimSpace(d) != "" {
				seen[k] = struct{}{}
				break
			}
		}
	}
	ids := make([]string, 0, len(seen))
	for k := range seen {
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
