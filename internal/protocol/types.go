package protocol

import (
	"encoding/json"
	"time"
)

const (
	HeaderNodeID         = "X-Node-ID"
	HeaderNodeToken      = "X-Node-Token"
	HeaderLeaseToken     = "X-Lease-Token"
	HeaderLocalToken     = "X-Local-Token"
	HeaderCenterSecret   = "X-Center-Secret"
	HeaderAdminToken     = "X-Admin-Token"
	HeaderProject        = "X-Project"
	HeaderFilename       = "X-Filename"
	HeaderExpectedSHA256 = "X-Expected-SHA256"
)

const (
	RoleAgentA = "agent_a"
	RoleAgentB = "agent_b"
)

const (
	AccountRoleAdmin    = "admin"
	AccountRoleCustomer = "customer"
)

type AccountRecord struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`               // "customer"
	Projects   []string   `json:"projects"`           // empty = all projects; non-empty = restricted allowlist
	Enabled    bool       `json:"enabled"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

const (
	ConflictOverwrite  = "overwrite"
	ConflictAutoRename = "auto_rename"
	ConflictSkip       = "skip"
)

const (
	FileStatusReady   = "ready"
	FileStatusClaimed = "claimed"
)

const (
	EventUploaded  = "uploaded"
	EventCompleted = "completed"
	EventFailed    = "failed"
)

const (
	ScheduleFIFO   = "fifo"   // drain projects sequentially in creation / configured order
	ScheduleFair   = "fair"   // share concurrency and bandwidth evenly across projects
	ScheduleRandom = "random" // legacy randomized scan
)

const (
	DiskPolicyAffinityHash = "affinity_hash" // media-stem FNV hash (paired files on same disk) + auto spillover
	DiskPolicyMostFree     = "most_free"     // always prefer disk with the most available free space
	DiskPolicyRoundRobin   = "round_robin"   // strict per-file round-robin across enabled disks
	DiskPolicyFirst        = "first"         // fill first enabled disk in order before spilling to next
)

const (
	ConcurrencyAuto   = "auto"   // intelligent adaptive concurrency (gradient throughput probing + AIMD backpressure)
	ConcurrencyManual = "manual" // fixed concurrency ceiling
)

type DiskStatus struct {
	Path       string  `json:"path"`
	TotalBytes uint64  `json:"total_bytes"`
	FreeBytes  uint64  `json:"free_bytes"`
	UsedPct    float64 `json:"used_pct"`
	Enabled    bool    `json:"enabled"`
	LowSpace   bool    `json:"low_space,omitempty"`
	Writable   bool    `json:"writable"`
}

type ReceiverDirective struct {
	Paused             bool     `json:"paused,omitempty"`               // true: stop claiming new files (in-flight drains cleanly)
	ProjectMode        string   `json:"project_mode,omitempty"`         // "all" | "selected"
	AllowedProjects    []string `json:"allowed_projects,omitempty"`     // explicit ordered allowlist when project_mode=="selected"
	KnownProjects      []string `json:"known_projects,omitempty"`       // all projects ordered by created_at ASC
	ProjectSchedule    string   `json:"project_schedule,omitempty"`     // "fifo" | "fair" | "random"
	DiskPolicy         string   `json:"disk_policy,omitempty"`          // "affinity_hash" | "most_free" | "round_robin" | "first"
	DisabledDisks      []string `json:"disabled_disks,omitempty"`       // storage root dirs disabled via console
	ConcurrencyMode    string   `json:"concurrency_mode,omitempty"`     // "auto" | "manual"
	MaxConcurrent      int      `json:"max_concurrent,omitempty"`       // >0 overrides effective upper concurrency cap
	SuggestedStreamCap int      `json:"suggested_stream_cap,omitempty"` // >0 cluster-wide fair-share stream ceiling from dispatch capacity
	RateLimitMBps      float64  `json:"rate_limit_mbps,omitempty"`      // >0 hot rate cap in MB/s (0 = unlimited)
}

type Project struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Description        string    `json:"description"`
	ConflictPolicy     string    `json:"conflict_policy"`
	LeaseTTLSec        int       `json:"lease_ttl_sec"`
	GroupAffinity      *bool     `json:"group_affinity,omitempty"`       // default true: route paired files (<video_id>.*) to same receiver
	MaxTotalConcurrent int       `json:"max_total_concurrent,omitempty"` // optional cluster-wide concurrency cap across all receivers (0 = unlimited)
	MaxTotalRateMBps   float64   `json:"max_total_rate_mbps,omitempty"`  // optional cluster-wide bandwidth cap in MB/s across all receivers (0 = unlimited)
	CreatedAt          time.Time `json:"created_at"`
}

func (p Project) GroupAffinityEnabled() bool {
	if p.GroupAffinity == nil {
		return true
	}
	return *p.GroupAffinity
}

type NodeRecord struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	Role                  string    `json:"role"`
	Projects              []string  `json:"projects"`
	ProjectSchedule       string    `json:"project_schedule,omitempty"`
	DiskPolicy            string    `json:"disk_policy,omitempty"`
	DisabledDisks         []string  `json:"disabled_disks,omitempty"`
	ConcurrencyMode       string    `json:"concurrency_mode,omitempty"`
	MaxConcurrentOverride int       `json:"max_concurrent_override,omitempty"`
	RateLimitMBps         float64   `json:"rate_limit_mbps,omitempty"`
	Paused                bool      `json:"paused,omitempty"`
	PublicAddr            string    `json:"public_addr,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
}

type ProjectAvailability struct {
	ProjectID    string `json:"project_id"`
	ReadyCount   int    `json:"ready_count"`
	ClaimedCount int    `json:"claimed_count"`
	ReadyBytes   int64  `json:"ready_bytes"`
}

type AgentAHeartbeatReq struct {
	NodeID           string                `json:"node_id"`
	Name             string                `json:"name"`
	PublicAddr       string                `json:"public_addr"`
	Projects         []string              `json:"projects"`
	Version          string                `json:"version,omitempty"`
	OS               string                `json:"os,omitempty"`
	Arch             string                `json:"arch,omitempty"`
	UpgradeAttemptID string                `json:"upgrade_attempt_id,omitempty"`
	UpgradeStatus    string                `json:"upgrade_status,omitempty"`
	UpgradeError     string                `json:"upgrade_error,omitempty"`
	DiskTotalBytes   uint64                `json:"disk_total_bytes"`
	DiskFreeBytes    uint64                `json:"disk_free_bytes"`
	DiskUsedPct      float64               `json:"disk_used_pct"`
	DiskAlarm            bool                  `json:"disk_alarm"`
	Paused               bool                  `json:"paused,omitempty"`
	ActiveStreams        int                   `json:"active_streams,omitempty"`
	MaxConcurrentStreams int                   `json:"max_concurrent_streams,omitempty"`
	Availability         []ProjectAvailability `json:"availability"`
}

type SummaryEvent struct {
	EventID    string    `json:"event_id"`
	ProjectID  string    `json:"project_id"`
	ANodeID    string    `json:"a_node_id"`
	BNodeID    string    `json:"b_node_id,omitempty"`
	EventType  string    `json:"event_type"`
	Bytes      int64     `json:"bytes"`
	DurationMs int64     `json:"duration_ms"`
	Timestamp  time.Time `json:"timestamp"`
}

type SummaryEventsReq struct {
	Events []SummaryEvent `json:"events"`
}

type AgentBHeartbeatReq struct {
	NodeID                string            `json:"node_id"`
	Name                  string            `json:"name"`
	Projects              []string          `json:"projects"`
	StorageDirs           []string          `json:"storage_dirs,omitempty"`
	Disks                 []DiskStatus      `json:"disks,omitempty"`
	ProjectSchedule       string            `json:"project_schedule,omitempty"`
	DiskPolicy            string            `json:"disk_policy,omitempty"`
	ConcurrencyMode       string            `json:"concurrency_mode,omitempty"`
	EffectiveConcurrent   int               `json:"effective_concurrent,omitempty"`
	MaxConcurrentCap      int               `json:"max_concurrent_cap,omitempty"`
	EffectiveStreams      int               `json:"effective_streams,omitempty"`
	EffectiveRateMBps     float64           `json:"effective_rate_mbps,omitempty"`
	AdaptiveState         string            `json:"adaptive_state,omitempty"`
	AdaptiveReason        string            `json:"adaptive_reason,omitempty"`
	Version               string            `json:"version,omitempty"`
	OS                    string            `json:"os,omitempty"`
	Arch                  string            `json:"arch,omitempty"`
	UpgradeAttemptID      string            `json:"upgrade_attempt_id,omitempty"`
	UpgradeStatus         string            `json:"upgrade_status,omitempty"`
	UpgradeError          string            `json:"upgrade_error,omitempty"`
	DiskTotalBytes        uint64            `json:"disk_total_bytes"`
	DiskFreeBytes         uint64            `json:"disk_free_bytes"`
	DiskUsedPct           float64           `json:"disk_used_pct"`
	Paused                bool              `json:"paused,omitempty"`
	ActiveCount           int               `json:"active_count"`
	LegacyActiveTransfers []json.RawMessage `json:"active_transfers,omitempty"`
}

type UpgradeDirective struct {
	ReleaseID   string `json:"release_id"`
	AttemptID   string `json:"attempt_id,omitempty"`
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	DownloadURL string `json:"download_url"`
}

type HeartbeatResp struct {
	Paused          bool                `json:"paused,omitempty"`
	Upgrade         *UpgradeDirective   `json:"upgrade,omitempty"`
	AllowedProjects []string            `json:"allowed_projects,omitempty"`
	Directive       *ReceiverDirective  `json:"directive,omitempty"`
	ActiveReceivers map[string][]string `json:"active_receivers,omitempty"` // for agent_a: project_id -> sorted online receiver IDs
	ProjectAffinity map[string]bool     `json:"project_affinity,omitempty"` // for agent_a: project_id -> enable asset-group affinity (default true)
}

type DiscoverCandidate struct {
	ANodeID    string `json:"a_node_id"`
	AName      string `json:"a_name"`
	PublicAddr string `json:"public_addr"`
	ReadyCount int    `json:"ready_count"`
	ReadyBytes int64  `json:"ready_bytes"`
	AccessJWT  string `json:"access_jwt"`
}

type DiscoverResp struct {
	ProjectID      string              `json:"project_id"`
	ConflictPolicy string              `json:"conflict_policy"`
	LeaseTTLSec    int                 `json:"lease_ttl_sec"`
	Candidates     []DiscoverCandidate `json:"candidates"`
}

type ClaimReq struct {
	ProjectID          string `json:"project_id"`
	BNodeID            string `json:"b_node_id"`
	AvailableDiskBytes uint64 `json:"available_disk_bytes"`
	LeaseTTLSec        int    `json:"lease_ttl_sec,omitempty"`
}

type ClaimResp struct {
	FileID         string    `json:"file_id"`
	ProjectID      string    `json:"project_id"`
	Filename       string    `json:"filename"`
	Size           int64     `json:"size"`
	SHA256         string    `json:"sha256"`
	LeaseID        string    `json:"lease_id"`
	LeaseToken     string    `json:"lease_token"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	UploadedAt     time.Time `json:"uploaded_at"`
}

type ClaimBatchReq struct {
	ProjectID          string `json:"project_id"`
	BNodeID            string `json:"b_node_id"`
	AvailableDiskBytes uint64 `json:"available_disk_bytes"`
	LeaseTTLSec        int    `json:"lease_ttl_sec,omitempty"`
	MaxCount           int    `json:"max_count"`
}

type ClaimBatchResp struct {
	Items []ClaimResp `json:"items"`
}

type RenewReq struct {
	LeaseID     string `json:"lease_id"`
	BNodeID     string `json:"b_node_id"`
	LeaseTTLSec int    `json:"lease_ttl_sec,omitempty"`
}

type RenewResp struct {
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

type AckReq struct {
	LeaseID    string `json:"lease_id"`
	BNodeID    string `json:"b_node_id"`
	SHA256     string `json:"sha256"`
	DurationMs int64  `json:"duration_ms"`
}

type AckResp struct {
	Status string `json:"status"` // "deleted" | "already_deleted"
}

type BatchAckItem struct {
	FileID     string `json:"file_id"`
	LeaseID    string `json:"lease_id"`
	LeaseToken string `json:"lease_token"`
	SHA256     string `json:"sha256"`
	DurationMs int64  `json:"duration_ms"`
}

type BatchAckReq struct {
	BNodeID string         `json:"b_node_id"`
	Items   []BatchAckItem `json:"items"`
}

type BatchAckItemResult struct {
	FileID string `json:"file_id"`
	Status string `json:"status"` // "deleted" | "already_deleted" | "not_found" | "lease_invalid" | "checksum_failed" | "error"
	Error  string `json:"error,omitempty"`
}

type BatchAckResp struct {
	Results []BatchAckItemResult `json:"results"`
}

type NackReq struct {
	LeaseID string `json:"lease_id"`
	BNodeID string `json:"b_node_id"`
	Reason  string `json:"reason"`
}

type LocalUploadResp struct {
	FileID    string `json:"file_id"`
	ProjectID string `json:"project_id"`
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Status    string `json:"status"`
}

type LocalRegisterReq struct {
	ProjectID      string `json:"project_id"`
	LocalPath      string `json:"local_path"`
	Filename       string `json:"filename"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	Mode           string `json:"mode,omitempty"` // "move" (default) | "hardlink"
}

type LocalRegisterBatchReq struct {
	Items []LocalRegisterReq `json:"items"`
}

type LocalRegisterBatchItemResult struct {
	Index int              `json:"index"`
	File  *LocalUploadResp `json:"file,omitempty"`
	Error string           `json:"error,omitempty"`
}

type LocalRegisterBatchResp struct {
	Results []LocalRegisterBatchItemResult `json:"results"`
}

type LiveFileItem struct {
	FileID         string     `json:"file_id"`
	ProjectID      string     `json:"project_id"`
	Filename       string     `json:"filename"`
	Size           int64      `json:"size"`
	SHA256         string     `json:"sha256"`
	Status         string     `json:"status"`
	ClaimedBy      string     `json:"claimed_by,omitempty"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	UploadedAt     time.Time  `json:"uploaded_at"`
	RetryCount     int        `json:"retry_count"`
}

type LiveFilesResp struct {
	ANodeID      string         `json:"a_node_id"`
	AName        string         `json:"a_name"`
	PublicAddr   string         `json:"public_addr,omitempty"`
	Files        []LiveFileItem `json:"files"`
	TotalFiles   int            `json:"total_files,omitempty"`
	Truncated    bool           `json:"truncated,omitempty"`
	ReadyCount   int            `json:"ready_count,omitempty"`
	ClaimedCount int            `json:"claimed_count,omitempty"`
	ReadyBytes   int64          `json:"ready_bytes,omitempty"`
	ClaimedBytes int64          `json:"claimed_bytes,omitempty"`
	DiskTotal    uint64         `json:"disk_total_bytes"`
	DiskFree     uint64         `json:"disk_free_bytes"`
	DiskUsedPct  float64        `json:"disk_used_pct"`
	DiskAlarm    bool           `json:"disk_alarm"`
	Error        string         `json:"error,omitempty"`
}

type DailyStat struct {
	Date             string `json:"date"`
	ProjectID        string `json:"project_id"`
	ANodeID          string `json:"a_node_id"`
	FilesUploaded    int64  `json:"files_uploaded"`
	FilesCompleted   int64  `json:"files_completed"`
	FilesFailed      int64  `json:"files_failed"`
	BytesTransferred int64  `json:"bytes_transferred"`
	TotalDurationMs  int64  `json:"total_duration_ms"`
}

type IntervalStat struct {
	BucketStart      time.Time `json:"bucket_start"`
	BucketEnd        time.Time `json:"bucket_end"`
	BucketSec        int64     `json:"bucket_sec"`
	EffectiveSec     int64     `json:"effective_sec"`
	FilesUploaded    int64     `json:"files_uploaded"`
	FilesCompleted   int64     `json:"files_completed"`
	FilesFailed      int64     `json:"files_failed"`
	BytesTransferred int64     `json:"bytes_transferred"`
	AvgSpeedBps      int64     `json:"avg_speed_bps"`
}

type IntervalStatsResp struct {
	GeneratedAt       time.Time      `json:"generated_at"`
	WindowStart       time.Time      `json:"window_start"`
	WindowEnd         time.Time      `json:"window_end"`
	WindowHours       int            `json:"window_hours"`
	BucketMinutes     int            `json:"bucket_minutes"`
	ProjectID         string         `json:"project_id,omitempty"`
	ANodeID           string         `json:"a_node_id,omitempty"`
	BNodeID           string         `json:"b_node_id,omitempty"`
	TotalUploaded     int64          `json:"total_uploaded"`
	TotalCompleted    int64          `json:"total_completed"`
	TotalFailed       int64          `json:"total_failed"`
	TotalBytes        int64          `json:"total_bytes"`
	WindowAvgSpeedBps int64          `json:"window_avg_speed_bps"`
	ActiveAvgSpeedBps int64          `json:"active_avg_speed_bps"`
	PeakSpeedBps      int64          `json:"peak_speed_bps"`
	Buckets           []IntervalStat `json:"buckets"`
}

type ProjectSummary struct {
	Project           Project             `json:"project"`
	TotalUploaded     int64               `json:"total_uploaded"`
	TotalCompleted    int64               `json:"total_completed"`
	TotalFailed       int64               `json:"total_failed"`
	TotalBytes        int64               `json:"total_bytes"`
	WindowCompleted   int64               `json:"window_completed"`
	WindowFailed      int64               `json:"window_failed"`
	WindowBytes       int64               `json:"window_bytes"`
	WindowAvgSpeedBps int64               `json:"window_avg_speed_bps"`
	ActiveAvgSpeedBps int64               `json:"active_avg_speed_bps"`
	QueuedFiles       int                 `json:"queued_files"`
	QueuedBytes       int64               `json:"queued_bytes"`
	OnlineANodes      int                 `json:"online_a_nodes"`
	OnlineBNodes      int                 `json:"online_b_nodes"`
	ANodeAvailability []ANodeAvailSummary `json:"a_node_availability"`
}

type ANodeAvailSummary struct {
	ANodeID      string `json:"a_node_id"`
	AName        string `json:"a_name"`
	PublicAddr   string `json:"public_addr"`
	ReadyCount   int    `json:"ready_count"`
	ClaimedCount int    `json:"claimed_count"`
	ReadyBytes   int64  `json:"ready_bytes"`
	DiskAlarm    bool   `json:"disk_alarm"`
}

type LiveNodeView struct {
	ID                    string                `json:"id"`
	Name                  string                `json:"name"`
	Role                  string                `json:"role"`
	Projects              []string              `json:"projects"`
	ProjectSchedule       string                `json:"project_schedule,omitempty"`
	DiskPolicy            string                `json:"disk_policy,omitempty"`
	DisabledDisks         []string              `json:"disabled_disks,omitempty"`
	ConcurrencyMode       string                `json:"concurrency_mode,omitempty"`
	MaxConcurrentOverride int                   `json:"max_concurrent_override,omitempty"`
	RateLimitMBps         float64               `json:"rate_limit_mbps,omitempty"`
	Paused                bool                  `json:"paused,omitempty"`
	EffectiveConcurrent   int                   `json:"effective_concurrent,omitempty"`
	MaxConcurrentCap      int                   `json:"max_concurrent_cap,omitempty"`
	EffectiveStreams      int                   `json:"effective_streams,omitempty"`
	EffectiveRateMBps     float64               `json:"effective_rate_mbps,omitempty"`
	AdaptiveState         string                `json:"adaptive_state,omitempty"`
	AdaptiveReason        string                `json:"adaptive_reason,omitempty"`
	StorageDirs           []string              `json:"storage_dirs,omitempty"`
	Disks                 []DiskStatus          `json:"disks,omitempty"`
	PublicAddr            string                `json:"public_addr,omitempty"`
	Online                bool                  `json:"online"`
	Version           string                `json:"version,omitempty"`
	OS                string                `json:"os,omitempty"`
	Arch              string                `json:"arch,omitempty"`
	TargetVersion     string                `json:"target_version,omitempty"`
	UpgradeStatus     string                `json:"upgrade_status,omitempty"`
	UpgradeMessage    string                `json:"upgrade_message,omitempty"`
	LastSeenAt        *time.Time            `json:"last_seen_at,omitempty"`
	DiskTotalBytes    uint64                `json:"disk_total_bytes"`
	DiskFreeBytes     uint64                `json:"disk_free_bytes"`
	DiskUsedPct       float64               `json:"disk_used_pct"`
	DiskAlarm         bool                  `json:"disk_alarm"`
	WindowHours       int                   `json:"window_hours"`
	WindowCompleted   int64                 `json:"window_completed"`
	WindowFailed      int64                 `json:"window_failed"`
	WindowBytes       int64                 `json:"window_bytes"`
	WindowAvgSpeedBps int64                 `json:"window_avg_speed_bps"`
	ActiveAvgSpeedBps int64                 `json:"active_avg_speed_bps"`
	Availability      []ProjectAvailability `json:"availability,omitempty"`
}

type OverviewResp struct {
	GeneratedAt        time.Time        `json:"generated_at"`
	AuthTrustedIP      bool             `json:"auth_trusted_ip,omitempty"`
	AuthRole           string           `json:"auth_role,omitempty"`
	AuthAccountID      string           `json:"auth_account_id,omitempty"`
	AuthAccountName    string           `json:"auth_account_name,omitempty"`
	AuthProjects       []string         `json:"auth_projects,omitempty"`
	WindowStart        time.Time        `json:"window_start"`
	WindowEnd          time.Time        `json:"window_end"`
	WindowHours        int              `json:"window_hours"`
	BucketMinutes      int              `json:"bucket_minutes"`
	ProjectFilter      string           `json:"project_filter,omitempty"`
	TotalProjects      int              `json:"total_projects"`
	OnlineANodes       int              `json:"online_a_nodes"`
	TotalANodes        int              `json:"total_a_nodes"`
	OnlineBNodes       int              `json:"online_b_nodes"`
	TotalBNodes        int              `json:"total_b_nodes"`
	QueuedFiles        int              `json:"queued_files"`
	QueuedBytes        int64            `json:"queued_bytes"`
	WindowCompleted    int64            `json:"window_completed"`
	WindowBytes        int64            `json:"window_bytes"`
	WindowFailed       int64            `json:"window_failed"`
	WindowAvgSpeedBps  int64            `json:"window_avg_speed_bps"`
	ActiveAvgSpeedBps  int64            `json:"active_avg_speed_bps"`
	WindowPeakSpeedBps int64            `json:"window_peak_speed_bps"`
	TodayCompleted     int64            `json:"today_completed"`
	TodayBytes         int64            `json:"today_bytes"`
	TodayFailed        int64            `json:"today_failed"`
	AllTimeCompleted   int64            `json:"all_time_completed"`
	AllTimeBytes       int64            `json:"all_time_bytes"`
	AllTimeFailed      int64            `json:"all_time_failed"`
	IntervalCurve      []IntervalStat   `json:"interval_curve"`
	DailyTrend         []DailyStat      `json:"daily_trend"`
	Projects           []ProjectSummary `json:"projects"`
}

type ErrorResp struct {
	Error string `json:"error"`
}

// --- Releases, Batch Upgrades & One-Click Deployment ---

type ReleaseRecord struct {
	ID        string    `json:"id"`
	Role      string    `json:"role"` // "agent_a" | "agent_b"
	Version   string    `json:"version"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	Filename  string    `json:"filename"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type NodeUpgradeRecord struct {
	NodeID        string    `json:"node_id"`
	ReleaseID     string    `json:"release_id"`
	AttemptID     string    `json:"attempt_id"`
	TargetVersion string    `json:"target_version"`
	Status        string    `json:"status"` // "pending" | "downloading" | "restarting" | "completed" | "failed"
	Message       string    `json:"message,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type BatchUpgradeReq struct {
	ReleaseID string   `json:"release_id"`
	NodeIDs   []string `json:"node_ids"`
}

type BatchUpgradeResult struct {
	Queued  []string          `json:"queued"`
	Skipped map[string]string `json:"skipped,omitempty"`
}

type DeployPrecheckReq struct {
	Host          string `json:"host"`
	SSHPort       int    `json:"ssh_port,omitempty"`
	SSHUser       string `json:"ssh_user,omitempty"`
	SSHPassword   string `json:"ssh_password,omitempty"`
	SSHPrivateKey string `json:"ssh_private_key,omitempty"`
	NodeID        string `json:"node_id,omitempty"`
	PublicPort    int    `json:"public_port,omitempty"`
	LocalPort     int    `json:"local_port,omitempty"`
	InstallDir    string `json:"install_dir,omitempty"`
	DataDir       string `json:"data_dir,omitempty"`
	ReleaseID     string `json:"release_id,omitempty"`
}

type PrecheckItem struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Status string `json:"status"` // "pass" | "warn" | "fail"
	Detail string `json:"detail"`
}

type RemoteHostInfo struct {
	OS              string  `json:"os"`
	Arch            string  `json:"arch"`
	Distro          string  `json:"distro"`
	Hostname        string  `json:"hostname"`
	HostFingerprint string  `json:"host_fingerprint,omitempty"`
	IsRoot          bool    `json:"is_root"`
	HasSystemd      bool    `json:"has_systemd"`
	DiskTotalBytes  uint64  `json:"disk_total_bytes"`
	DiskFreeBytes   uint64  `json:"disk_free_bytes"`
	DiskUsedPct     float64 `json:"disk_used_pct"`
	ExistingService string  `json:"existing_service,omitempty"`
	ExistingVersion string  `json:"existing_version,omitempty"`
}

type DeployPrecheckResp struct {
	OK             bool           `json:"ok"`
	CanForce       bool           `json:"can_force"`
	HostInfo       RemoteHostInfo `json:"host_info"`
	Checks         []PrecheckItem `json:"checks"`
	MatchedRelease *ReleaseRecord `json:"matched_release,omitempty"`
}

type DeployAgentAReq struct {
	Host                   string   `json:"host"`
	SSHPort                int      `json:"ssh_port,omitempty"`
	SSHUser                string   `json:"ssh_user,omitempty"`
	SSHPassword            string   `json:"ssh_password,omitempty"`
	SSHPrivateKey          string   `json:"ssh_private_key,omitempty"`
	NodeID                 string   `json:"node_id"`
	NodeName               string   `json:"node_name,omitempty"`
	Projects               []string `json:"projects,omitempty"`
	PublicPort             int      `json:"public_port,omitempty"`
	LocalPort              int      `json:"local_port,omitempty"`
	InstallDir             string   `json:"install_dir,omitempty"`
	DataDir                string   `json:"data_dir,omitempty"`
	ReleaseID              string   `json:"release_id,omitempty"`
	MaxDiskUsagePct        float64  `json:"max_disk_usage_pct,omitempty"`
	MinFreeDiskBytes       uint64   `json:"min_free_disk_bytes,omitempty"`
	LeaseTTLSec            int      `json:"lease_ttl_sec,omitempty"`
	MaxConcurrentStreams   int      `json:"max_concurrent_streams,omitempty"`
	RateLimitMBps          float64  `json:"rate_limit_mbps,omitempty"`
	DeleteBatchIntervalSec int      `json:"delete_batch_interval_sec,omitempty"`
	ForceOverwrite         bool     `json:"force_overwrite,omitempty"`
}

type DeployTask struct {
	ID             string     `json:"id"`
	NodeID         string     `json:"node_id"`
	Host           string     `json:"host"`
	Status         string     `json:"status"` // "running" | "succeeded" | "failed"
	Step           string     `json:"step"`
	Logs           []string   `json:"logs"`
	Error          string     `json:"error,omitempty"`
	LocalToken     string     `json:"local_token,omitempty"`
	PublicAddr     string     `json:"public_addr,omitempty"`
	ReleaseVersion string     `json:"release_version,omitempty"`
	StartedAt      time.Time  `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

type AgentBScriptReq struct {
	NodeID             string              `json:"node_id"`
	NodeToken          string              `json:"node_token,omitempty"`
	RotateToken        bool                `json:"rotate_token,omitempty"`
	InstallDir         string              `json:"install_dir,omitempty"`
	StateDir           string              `json:"state_dir,omitempty"`
	StorageDirs        []string            `json:"storage_dirs,omitempty"`
	OnlyProject        string              `json:"only_project,omitempty"`
	DestDirs           []string            `json:"dest_dirs,omitempty"`
	Projects           map[string]string   `json:"projects,omitempty"`
	ProjectDirs        map[string][]string `json:"project_dirs,omitempty"`
	MaxConcurrent      int                 `json:"max_concurrent,omitempty"`
	MinFreeDiskBytes   uint64              `json:"min_free_disk_bytes,omitempty"`
	AckBatchIntervalMs int                 `json:"ack_batch_interval_ms,omitempty"`
	ReleaseID          string              `json:"release_id,omitempty"`
}

type AgentBScriptResp struct {
	NodeID       string `json:"node_id"`
	Script       string `json:"script"`
	RotatedToken string `json:"rotated_token,omitempty"`
}

type AgentAScriptReq struct {
	NodeID               string  `json:"node_id"`
	NodeToken            string  `json:"node_token,omitempty"`
	RotateToken          bool    `json:"rotate_token,omitempty"`
	PublicAddr           string  `json:"public_addr,omitempty"`
	PublicPort           int     `json:"public_port,omitempty"`
	LocalPort            int     `json:"local_port,omitempty"`
	InstallDir           string  `json:"install_dir,omitempty"`
	DataDir              string  `json:"data_dir,omitempty"`
	MaxDiskUsagePct      float64 `json:"max_disk_usage_pct,omitempty"`
	LeaseTTLSec          int     `json:"lease_ttl_sec,omitempty"`
	MaxConcurrentStreams int     `json:"max_concurrent_streams,omitempty"`
	RateLimitMBps        float64 `json:"rate_limit_mbps,omitempty"`
	ReleaseID            string  `json:"release_id,omitempty"`
}

type AgentAScriptResp struct {
	NodeID       string `json:"node_id"`
	Script       string `json:"script"`
	PublicAddr   string `json:"public_addr"`
	LocalToken   string `json:"local_token"`
	RotatedToken string `json:"rotated_token,omitempty"`
}
