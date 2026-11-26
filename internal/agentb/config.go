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
	OnlyProject          string              `yaml:"only_project,omitempty"` // optional: strictly restrict this receiver node to download ONLY this single project
	DestDir              string              `yaml:"dest_dir,omitempty"`     // optional shorthand single destination directory when only_project is set
	DestDirs             []string            `yaml:"dest_dirs,omitempty"`    // optional shorthand multiple destination directories when only_project is set
	Projects             map[string]string   `yaml:"projects,omitempty"`     // project_id -> single local dest directory
	ProjectDirs          map[string][]string `yaml:"project_dirs,omitempty"` // project_id -> multiple local dest directories for balanced multi-disk placement
	StateDir             string              `yaml:"state_dir"`
	MaxConcurrent        int                 `yaml:"max_concurrent"`
	StreamProtocol       string              `yaml:"stream_protocol,omitempty"`       // "h2" (default, TLS 1.3 HTTP/2) or "h1" (TLS 1.3 HTTP/1.1, removes 4MiB H2 flow-control cap for 10Gbps)
	StreamConns          int                 `yaml:"stream_conns,omitempty"`          // independent TLS 1.3 TCP sockets for h2 pool (or idle pool floor for h1)
	StreamConnMaxAgeSec  int                 `yaml:"stream_conn_max_age_sec,omitempty"` // if >0, staggered rotation of stream transports every N seconds (evades ISP long-flow QoS throttling; 0 = keepalive forever)
	MaxTotalStreams      int                 `yaml:"max_total_streams,omitempty"`     // global cap on simultaneous active HTTP range streams across all workers
	ChunkConcurrency     int                 `yaml:"chunk_concurrency,omitempty"`     // parallel range streams per large file (<=1 disables chunking)
	ChunkSizeMB          int                 `yaml:"chunk_size_mb,omitempty"`         // range chunk size in MiB (default 4; auto-scales to 16/32MiB for large files)
	ChunkThresholdMB     int                 `yaml:"chunk_threshold_mb,omitempty"`    // minimum file size in MiB to activate parallel range chunking (default 4)
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
	c.OnlyProject = strings.TrimSpace(c.OnlyProject)
	c.DestDir = strings.TrimSpace(c.DestDir)
	if c.NodeName == "" {
		c.NodeName = c.NodeID
	}
	if c.StateDir == "" {
		c.StateDir = "./data-b"
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 3
	}
	c.StreamProtocol = strings.ToLower(strings.TrimSpace(c.StreamProtocol))
	if c.StreamProtocol == "" {
		c.StreamProtocol = "h2"
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
	if c.StreamConns > 512 {
		c.StreamConns = 512
	}
	if c.ChunkConcurrency < 1 {
		c.ChunkConcurrency = 1
	}
	if c.ChunkConcurrency > 128 {
		c.ChunkConcurrency = 128
	}
	if c.ChunkSizeMB <= 0 {
		c.ChunkSizeMB = 4
	}
	if c.ChunkThresholdMB <= 0 {
		c.ChunkThresholdMB = c.ChunkSizeMB
	}
	if c.MaxTotalStreams <= 0 {
		c.MaxTotalStreams = c.MaxConcurrent * c.ChunkConcurrency
		if c.MaxTotalStreams > 1024 {
			c.MaxTotalStreams = 1024
		}
		if c.MaxTotalStreams < c.MaxConcurrent {
			c.MaxTotalStreams = c.MaxConcurrent
		}
	}
	if c.MaxTotalStreams > 1024 {
		c.MaxTotalStreams = 1024
	}
	if c.ClaimBatchSize <= 0 {
		c.ClaimBatchSize = 16
	}
	if c.ClaimBatchSize > 256 {
		c.ClaimBatchSize = 256
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
	if c.StreamProtocol != "h2" && c.StreamProtocol != "h1" {
		return fmt.Errorf("stream_protocol must be 'h2' or 'h1' (got %q)", c.StreamProtocol)
	}
	if len(c.ProjectIDs()) == 0 {
		if c.OnlyProject != "" {
			return fmt.Errorf("only_project %q requires a destination directory (dest_dir, dest_dirs, projects, or project_dirs)", c.OnlyProject)
		}
		return errors.New("at least one project destination mapping is required")
	}
	return nil
}

// DestDirsFor returns all configured destination directories for a project (deduplicated, preserving order).
// When only_project is set, all other projects return nil so this receiver downloads strictly one project.
func (c *Config) DestDirsFor(projectID string) []string {
	only := strings.TrimSpace(c.OnlyProject)
	if only != "" && projectID != only {
		return nil
	}
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
	if only != "" && projectID == only {
		for _, d := range c.DestDirs {
			add(d)
		}
		add(c.DestDir)
	}
	return out
}

func (c *Config) ProjectIDs() []string {
	if only := strings.TrimSpace(c.OnlyProject); only != "" {
		if len(c.DestDirsFor(only)) > 0 {
			return []string{only}
		}
		return nil
	}
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
