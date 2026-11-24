package protocol

import "time"

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

type Project struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	ConflictPolicy string    `json:"conflict_policy"`
	LeaseTTLSec    int       `json:"lease_ttl_sec"`
	CreatedAt      time.Time `json:"created_at"`
}

type NodeRecord struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Role       string    `json:"role"`
	Projects   []string  `json:"projects"`
	PublicAddr string    `json:"public_addr,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type ProjectAvailability struct {
	ProjectID    string `json:"project_id"`
	ReadyCount   int    `json:"ready_count"`
	ClaimedCount int    `json:"claimed_count"`
	ReadyBytes   int64  `json:"ready_bytes"`
}

type AgentAHeartbeatReq struct {
	NodeID         string                `json:"node_id"`
	Name           string                `json:"name"`
	PublicAddr     string                `json:"public_addr"`
	Projects       []string              `json:"projects"`
	DiskTotalBytes uint64                `json:"disk_total_bytes"`
	DiskFreeBytes  uint64                `json:"disk_free_bytes"`
	DiskUsedPct    float64               `json:"disk_used_pct"`
	DiskAlarm      bool                  `json:"disk_alarm"`
	ActiveStreams  int                   `json:"active_streams"`
	OutSpeedBps    int64                 `json:"out_speed_bps"`
	Availability   []ProjectAvailability `json:"availability"`
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

type BActiveTransfer struct {
	ProjectID        string    `json:"project_id"`
	ANodeID          string    `json:"a_node_id"`
	FileID           string    `json:"file_id"`
	Filename         string    `json:"filename"`
	TransferredBytes int64     `json:"transferred_bytes"`
	TotalBytes       int64     `json:"total_bytes"`
	SpeedBps         int64     `json:"speed_bps"`
	StartedAt        time.Time `json:"started_at"`
}

type AgentBHeartbeatReq struct {
	NodeID          string            `json:"node_id"`
	Name            string            `json:"name"`
	Projects        []string          `json:"projects"`
	DiskTotalBytes  uint64            `json:"disk_total_bytes"`
	DiskFreeBytes   uint64            `json:"disk_free_bytes"`
	DiskUsedPct     float64           `json:"disk_used_pct"`
	ActiveTransfers []BActiveTransfer `json:"active_transfers"`
	InSpeedBps      int64             `json:"in_speed_bps"`
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
	ANodeID       string         `json:"a_node_id"`
	AName         string         `json:"a_name"`
	PublicAddr    string         `json:"public_addr,omitempty"`
	Files         []LiveFileItem `json:"files"`
	DiskTotal     uint64         `json:"disk_total_bytes"`
	DiskFree      uint64         `json:"disk_free_bytes"`
	DiskUsedPct   float64        `json:"disk_used_pct"`
	DiskAlarm     bool           `json:"disk_alarm"`
	Error         string         `json:"error,omitempty"`
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

type ProjectSummary struct {
	Project           Project               `json:"project"`
	TotalUploaded     int64                 `json:"total_uploaded"`
	TotalCompleted    int64                 `json:"total_completed"`
	TotalFailed       int64                 `json:"total_failed"`
	TotalBytes        int64                 `json:"total_bytes"`
	LiveReadyCount    int                   `json:"live_ready_count"`
	LiveClaimedCount  int                   `json:"live_claimed_count"`
	LiveReadyBytes    int64                 `json:"live_ready_bytes"`
	OnlineANodes      int                   `json:"online_a_nodes"`
	OnlineBNodes      int                   `json:"online_b_nodes"`
	ANodeAvailability []ANodeAvailSummary   `json:"a_node_availability"`
	ActiveTransfers   []BActiveTransferView `json:"active_transfers"`
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

type BActiveTransferView struct {
	BNodeID          string    `json:"b_node_id"`
	BName            string    `json:"b_name"`
	ProjectID        string    `json:"project_id"`
	ANodeID          string    `json:"a_node_id"`
	FileID           string    `json:"file_id"`
	Filename         string    `json:"filename"`
	TransferredBytes int64     `json:"transferred_bytes"`
	TotalBytes       int64     `json:"total_bytes"`
	SpeedBps         int64     `json:"speed_bps"`
	StartedAt        time.Time `json:"started_at"`
}

type LiveNodeView struct {
	ID              string                `json:"id"`
	Name            string                `json:"name"`
	Role            string                `json:"role"`
	Projects        []string              `json:"projects"`
	PublicAddr      string                `json:"public_addr,omitempty"`
	Online          bool                  `json:"online"`
	LastSeenAt      *time.Time            `json:"last_seen_at,omitempty"`
	DiskTotalBytes  uint64                `json:"disk_total_bytes"`
	DiskFreeBytes   uint64                `json:"disk_free_bytes"`
	DiskUsedPct     float64               `json:"disk_used_pct"`
	DiskAlarm       bool                  `json:"disk_alarm"`
	ActiveStreams   int                   `json:"active_streams"`
	SpeedBps        int64                 `json:"speed_bps"`
	Availability    []ProjectAvailability `json:"availability,omitempty"`
	ActiveTransfers []BActiveTransfer     `json:"active_transfers,omitempty"`
}

type OverviewResp struct {
	TotalProjects      int                   `json:"total_projects"`
	OnlineANodes       int                   `json:"online_a_nodes"`
	TotalANodes        int                   `json:"total_a_nodes"`
	OnlineBNodes       int                   `json:"online_b_nodes"`
	TotalBNodes        int                   `json:"total_b_nodes"`
	LiveReadyFiles     int                   `json:"live_ready_files"`
	LiveReadyBytes     int64                 `json:"live_ready_bytes"`
	LiveActiveFiles    int                   `json:"live_active_files"`
	LiveTotalSpeedBps  int64                 `json:"live_total_speed_bps"`
	TodayCompleted     int64                 `json:"today_completed"`
	TodayBytes         int64                 `json:"today_bytes"`
	TodayFailed        int64                 `json:"today_failed"`
	AllTimeCompleted   int64                 `json:"all_time_completed"`
	AllTimeBytes       int64                 `json:"all_time_bytes"`
	AllTimeFailed      int64                 `json:"all_time_failed"`
	DailyTrend         []DailyStat           `json:"daily_trend"`
	Projects           []ProjectSummary      `json:"projects"`
	ActiveTransfers    []BActiveTransferView `json:"active_transfers"`
}

type ErrorResp struct {
	Error string `json:"error"`
}
