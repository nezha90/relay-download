package agentb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"relay-download/internal/protocol"
)

type Config struct {
	NodeID               string              `yaml:"node_id"`
	NodeName             string              `yaml:"node_name"`
	CenterURL            string              `yaml:"center_url"`
	CenterToken          string              `yaml:"center_token"`
	CACert               string              `yaml:"ca_cert"`
	StorageDirs          []string            `yaml:"storage_dirs,omitempty"`         // managed disk pool roots: any project lands in <storage_dir>/<project_id>/
	AwaitDiskSelection   bool                `yaml:"await_disk_selection,omitempty"` // if true, activate online & scan host disks, stay standby until Center assigns storage_dirs
	ProjectSchedule      string              `yaml:"project_schedule,omitempty"`     // default multi-project schedule: "fifo" | "fair" | "random" (overridable by Center)
	DiskPolicy           string              `yaml:"disk_policy,omitempty"`          // default disk placement: "affinity_hash" | "most_free" | "round_robin" | "first" | "rolling_window" (overridable by Center)
	ActiveDiskWindow     int                 `yaml:"active_disk_window,omitempty"`   // concurrent active disks for rolling_window policy (default 10; 1..256)
	ConcurrencyMode      string              `yaml:"concurrency_mode,omitempty"`     // default concurrency control: "auto" (adaptive BBR/AIMD) | "manual" (overridable by Center)
	OnlyProject          string              `yaml:"only_project,omitempty"`         // optional: strictly restrict this receiver node locally to download ONLY this single project
	DestDir              string              `yaml:"dest_dir,omitempty"`             // optional shorthand single destination directory when only_project is set
	DestDirs             []string            `yaml:"dest_dirs,omitempty"`            // optional shorthand multiple destination directories when only_project is set
	Projects             map[string]string   `yaml:"projects,omitempty"`             // project_id -> single local dest directory
	ProjectDirs          map[string][]string `yaml:"project_dirs,omitempty"`         // project_id -> multiple local dest directories for balanced multi-disk placement
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
	MaxDiskUsagePct      float64             `yaml:"max_disk_usage_pct,omitempty"`    // mandatory per-disk watermark ceiling (default 90.0%)
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
	if len(c.StorageDirs) > 0 {
		clean := make([]string, 0, len(c.StorageDirs))
		seen := make(map[string]struct{}, len(c.StorageDirs))
		for _, d := range c.StorageDirs {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			d = filepath.Clean(d)
			if _, dup := seen[d]; !dup {
				seen[d] = struct{}{}
				clean = append(clean, d)
			}
		}
		c.StorageDirs = clean
	}
	c.ProjectSchedule = strings.ToLower(strings.TrimSpace(c.ProjectSchedule))
	if c.ProjectSchedule == "" {
		c.ProjectSchedule = protocol.ScheduleFIFO
	}
	c.DiskPolicy = strings.ToLower(strings.TrimSpace(c.DiskPolicy))
	if c.DiskPolicy == "" {
		c.DiskPolicy = protocol.DiskPolicyAffinityHash
	}
	if c.ActiveDiskWindow <= 0 {
		c.ActiveDiskWindow = 10
	}
	if c.ActiveDiskWindow > 256 {
		c.ActiveDiskWindow = 256
	}
	c.ConcurrencyMode = strings.ToLower(strings.TrimSpace(c.ConcurrencyMode))
	if c.ConcurrencyMode == "" {
		c.ConcurrencyMode = protocol.ConcurrencyAuto
	}
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
	if c.MaxDiskUsagePct <= 0 {
		c.MaxDiskUsagePct = 90.0
	}
	if c.MaxDiskUsagePct > 95.0 {
		c.MaxDiskUsagePct = 95.0
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
	switch c.ProjectSchedule {
	case protocol.ScheduleFIFO, protocol.ScheduleFair, protocol.ScheduleRandom:
	default:
		return fmt.Errorf("project_schedule must be 'fifo', 'fair', or 'random' (got %q)", c.ProjectSchedule)
	}
	switch c.DiskPolicy {
	case protocol.DiskPolicyAffinityHash, protocol.DiskPolicyMostFree, protocol.DiskPolicyRoundRobin, protocol.DiskPolicyFirst, protocol.DiskPolicyRollingWindow:
	default:
		return fmt.Errorf("disk_policy must be 'affinity_hash', 'most_free', 'round_robin', 'first', or 'rolling_window' (got %q)", c.DiskPolicy)
	}
	switch c.ConcurrencyMode {
	case protocol.ConcurrencyAuto, protocol.ConcurrencyManual:
	default:
		return fmt.Errorf("concurrency_mode must be 'auto' or 'manual' (got %q)", c.ConcurrencyMode)
	}
	if !c.AwaitDiskSelection && len(c.ProjectIDs()) == 0 && len(c.StorageDirs) == 0 {
		if c.OnlyProject != "" {
			return fmt.Errorf("only_project %q requires a destination directory (storage_dirs, dest_dir, dest_dirs, projects, or project_dirs)", c.OnlyProject)
		}
		return errors.New("at least one storage_dirs root or project destination mapping is required")
	}
	if !c.AwaitDiskSelection && c.OnlyProject != "" && len(c.DestDirsFor(c.OnlyProject)) == 0 {
		return fmt.Errorf("only_project %q requires a valid destination directory", c.OnlyProject)
	}
	return nil
}

// SafeProjectSubdir enforces a strict identifier allowlist ([A-Za-z0-9._-], 1-64 chars)
// when dynamically joining <storage_dir>/<project_id> to prevent path traversal or shell metacharacters.
func SafeProjectSubdir(projectID string) bool {
	p := strings.TrimSpace(projectID)
	if len(p) == 0 || len(p) > 64 || p == "." || p == ".." || strings.Contains(p, "..") {
		return false
	}
	for i := 0; i < len(p); i++ {
		ch := p[i]
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-'
		if !ok {
			return false
		}
	}
	return true
}

// DestDirsFor returns all configured destination directories for a project (deduplicated, preserving order).
// When only_project is set, all other projects return nil so this receiver downloads strictly one project.
// If no explicit per-project directory is mapped, storage_dirs roots expand to <storage_dir>/<project_id>.
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
		d = filepath.Clean(d)
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
	if len(out) == 0 && len(c.StorageDirs) > 0 && SafeProjectSubdir(projectID) {
		for _, sd := range c.StorageDirs {
			add(filepath.Join(sd, projectID))
		}
	}
	return out
}

// DiskRoots returns the ordered list of physical disk roots configured on this receiver
// (storage_dirs first, plus any standalone explicit project directories outside storage_dirs).
func (c *Config) DiskRoots() []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(c.StorageDirs))
	add := func(d string) {
		d = strings.TrimSpace(d)
		if d == "" {
			return
		}
		d = filepath.Clean(d)
		if _, dup := seen[d]; !dup {
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	for _, sd := range c.StorageDirs {
		add(sd)
	}
	underStorageRoot := func(dir string) bool {
		clean := filepath.Clean(dir)
		for _, sd := range c.StorageDirs {
			if clean == sd || strings.HasPrefix(clean, sd+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	extra := make([]string, 0)
	for _, d := range c.DestDirs {
		if d = strings.TrimSpace(d); d != "" && !underStorageRoot(d) {
			extra = append(extra, d)
		}
	}
	if d := strings.TrimSpace(c.DestDir); d != "" && !underStorageRoot(d) {
		extra = append(extra, d)
	}
	keys := make([]string, 0, len(c.Projects)+len(c.ProjectDirs))
	keySeen := make(map[string]struct{})
	for k := range c.Projects {
		keySeen[k] = struct{}{}
		keys = append(keys, k)
	}
	for k := range c.ProjectDirs {
		if _, ok := keySeen[k]; !ok {
			keySeen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, d := range c.ProjectDirs[k] {
			if d = strings.TrimSpace(d); d != "" && !underStorageRoot(d) {
				extra = append(extra, d)
			}
		}
		if d := strings.TrimSpace(c.Projects[k]); d != "" && !underStorageRoot(d) {
			extra = append(extra, d)
		}
	}
	for _, d := range extra {
		add(d)
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
