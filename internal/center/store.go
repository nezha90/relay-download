package center

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"relay-download/internal/auth"
	"relay-download/internal/protocol"
	"relay-download/internal/transfer"
)

const BaseIntervalSec int64 = 300 // 5-minute persisted summary buckets

type WindowSummary struct {
	Completed         int64
	Failed            int64
	Bytes             int64
	WindowAvgSpeedBps int64
	ActiveAvgSpeedBps int64
}

type IntervalQuery struct {
	Now             time.Time
	Start           time.Time
	End             time.Time
	Hours           int
	BucketMinutes   int
	ProjectID       string
	AllowedProjects []string
	ScopeRestricted bool // true for customer accounts: empty AllowedProjects returns zero data (default-deny)
	ANodeID         string
	BNodeID         string
}

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
)

type Store struct {
	db *sql.DB
}

type StoredNode struct {
	protocol.NodeRecord
	TokenHash string
}

type ProjectTotals struct {
	ProjectID      string
	TotalUploaded  int64
	TotalCompleted int64
	TotalFailed    int64
	TotalBytes     int64
}

func OpenStore(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open center sqlite: %w", err)
	}
	// Single writer pool avoids SQLITE_BUSY under high concurrency in SQLite.
	db.SetMaxOpenConns(1)
	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func initSchema(db *sql.DB) error {
	// NOTE: Intentionally NO per-file table! File queues live only on A nodes.
	// Center only persists projects, nodes, aggregated summary stats, and 24h event dedup IDs.
	const schema = `
CREATE TABLE IF NOT EXISTS projects (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	conflict_policy TEXT NOT NULL DEFAULT 'overwrite',
	lease_ttl_sec INTEGER NOT NULL DEFAULT 300,
	created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	role TEXT NOT NULL,
	projects_json TEXT NOT NULL DEFAULT '[]',
	project_schedule TEXT NOT NULL DEFAULT 'fifo',
	disk_policy TEXT NOT NULL DEFAULT 'affinity_hash',
	disabled_disks_json TEXT NOT NULL DEFAULT '[]',
	public_addr TEXT NOT NULL DEFAULT '',
	token_hash TEXT NOT NULL,
	created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS stats_daily (
	date TEXT NOT NULL,
	project_id TEXT NOT NULL,
	a_node_id TEXT NOT NULL,
	files_uploaded INTEGER NOT NULL DEFAULT 0,
	files_completed INTEGER NOT NULL DEFAULT 0,
	files_failed INTEGER NOT NULL DEFAULT 0,
	bytes_transferred INTEGER NOT NULL DEFAULT 0,
	total_duration_ms INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (date, project_id, a_node_id)
);

CREATE TABLE IF NOT EXISTS stats_intervals (
	bucket_ts INTEGER NOT NULL,
	project_id TEXT NOT NULL,
	a_node_id TEXT NOT NULL,
	b_node_id TEXT NOT NULL DEFAULT '',
	files_uploaded INTEGER NOT NULL DEFAULT 0,
	files_completed INTEGER NOT NULL DEFAULT 0,
	files_failed INTEGER NOT NULL DEFAULT 0,
	bytes_transferred INTEGER NOT NULL DEFAULT 0,
	total_duration_ms INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (bucket_ts, project_id, a_node_id, b_node_id)
);
CREATE INDEX IF NOT EXISTS idx_stats_intervals_ts ON stats_intervals(bucket_ts);

CREATE TABLE IF NOT EXISTS stats_project_total (
	project_id TEXT PRIMARY KEY,
	total_uploaded INTEGER NOT NULL DEFAULT 0,
	total_completed INTEGER NOT NULL DEFAULT 0,
	total_failed INTEGER NOT NULL DEFAULT 0,
	total_bytes INTEGER NOT NULL DEFAULT 0,
	total_duration_ms INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS event_dedup (
	event_id TEXT PRIMARY KEY,
	created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_event_dedup_created ON event_dedup(created_at);

CREATE TABLE IF NOT EXISTS releases (
	id TEXT PRIMARY KEY,
	role TEXT NOT NULL,
	version TEXT NOT NULL,
	os TEXT NOT NULL,
	arch TEXT NOT NULL,
	sha256 TEXT NOT NULL,
	size INTEGER NOT NULL,
	filename TEXT NOT NULL,
	notes TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS node_upgrades (
	node_id TEXT PRIMARY KEY,
	release_id TEXT NOT NULL,
	attempt_id TEXT NOT NULL DEFAULT '',
	target_version TEXT NOT NULL,
	status TEXT NOT NULL,
	message TEXT NOT NULL DEFAULT '',
	updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'customer',
	projects_json TEXT NOT NULL DEFAULT '[]',
	enabled INTEGER NOT NULL DEFAULT 1,
	token_hash TEXT NOT NULL UNIQUE,
	created_at TIMESTAMP NOT NULL,
	last_used_at TIMESTAMP
);
`
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	// Idempotent schema migrations for pre-v1.9.0 databases.
	migrations := []string{
		`ALTER TABLE nodes ADD COLUMN project_schedule TEXT NOT NULL DEFAULT 'fifo'`,
		`ALTER TABLE nodes ADD COLUMN disk_policy TEXT NOT NULL DEFAULT 'affinity_hash'`,
		`ALTER TABLE nodes ADD COLUMN disabled_disks_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE nodes ADD COLUMN concurrency_mode TEXT NOT NULL DEFAULT 'auto'`,
		`ALTER TABLE nodes ADD COLUMN max_concurrent_override INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN rate_limit_mbps REAL NOT NULL DEFAULT 0`,
		`ALTER TABLE projects ADD COLUMN group_affinity INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE projects ADD COLUMN max_total_concurrent INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE projects ADD COLUMN max_total_rate_mbps REAL NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN paused INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN storage_dirs_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE nodes ADD COLUMN unplug_locked_disks_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE nodes ADD COLUMN disk_gen INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE nodes ADD COLUMN active_disk_window INTEGER NOT NULL DEFAULT 10`,
		`ALTER TABLE nodes ADD COLUMN owner_account_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN max_disk_usage_pct REAL NOT NULL DEFAULT 85`,
		`ALTER TABLE nodes ADD COLUMN disk_affinity INTEGER NOT NULL DEFAULT 1`,
	}
	for _, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return err
		}
	}
	return nil
}

// EnsureProjects idempotently inserts newly discovered project IDs so projects uploaded to
// dispatch nodes automatically appear in the console and in receiver scheduling queues.
func (s *Store) EnsureProjects(ctx context.Context, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	inserted := 0
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		res, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO projects (id, name, description, conflict_policy, lease_ttl_sec, created_at)
VALUES (?, ?, '上传自动发现创建', 'overwrite', 300, ?)
`, id, id, now)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

func (s *Store) ListProjectIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM projects ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) UpsertProject(ctx context.Context, p protocol.Project) error {
	if p.ConflictPolicy == "" {
		p.ConflictPolicy = protocol.ConflictOverwrite
	}
	if p.LeaseTTLSec <= 0 {
		p.LeaseTTLSec = 300
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	affInt := 1
	if !p.GroupAffinityEnabled() {
		affInt = 0
	}
	if p.MaxTotalConcurrent < 0 {
		p.MaxTotalConcurrent = 0
	}
	if p.MaxTotalRateMBps < 0 {
		p.MaxTotalRateMBps = 0
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO projects (id, name, description, conflict_policy, lease_ttl_sec, group_affinity, max_total_concurrent, max_total_rate_mbps, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name=excluded.name,
	description=excluded.description,
	conflict_policy=excluded.conflict_policy,
	lease_ttl_sec=excluded.lease_ttl_sec,
	group_affinity=excluded.group_affinity,
	max_total_concurrent=excluded.max_total_concurrent,
	max_total_rate_mbps=excluded.max_total_rate_mbps
`, p.ID, p.Name, p.Description, p.ConflictPolicy, p.LeaseTTLSec, affInt, p.MaxTotalConcurrent, p.MaxTotalRateMBps, p.CreatedAt)
	return err
}

func (s *Store) GetProject(ctx context.Context, id string) (*protocol.Project, error) {
	var p protocol.Project
	var affInt int
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, description, conflict_policy, lease_ttl_sec, group_affinity, max_total_concurrent, max_total_rate_mbps, created_at
FROM projects WHERE id = ?
`, id).Scan(&p.ID, &p.Name, &p.Description, &p.ConflictPolicy, &p.LeaseTTLSec, &affInt, &p.MaxTotalConcurrent, &p.MaxTotalRateMBps, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	aff := affInt != 0
	p.GroupAffinity = &aff
	return &p, nil
}

func (s *Store) ListProjects(ctx context.Context) ([]protocol.Project, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, description, conflict_policy, lease_ttl_sec, group_affinity, max_total_concurrent, max_total_rate_mbps, created_at
FROM projects ORDER BY created_at ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]protocol.Project, 0)
	for rows.Next() {
		var p protocol.Project
		var affInt int
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.ConflictPolicy, &p.LeaseTTLSec, &affInt, &p.MaxTotalConcurrent, &p.MaxTotalRateMBps, &p.CreatedAt); err != nil {
			return nil, err
		}
		aff := affInt != 0
		p.GroupAffinity = &aff
		list = append(list, p)
	}
	return list, rows.Err()
}

func (s *Store) DeleteProject(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func normalizeProjectSchedule(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case protocol.ScheduleFair:
		return protocol.ScheduleFair
	case protocol.ScheduleRandom:
		return protocol.ScheduleRandom
	case protocol.ScheduleFIFO, "":
		return protocol.ScheduleFIFO
	default:
		return ""
	}
}

func normalizeDiskPolicy(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case protocol.DiskPolicyMostFree:
		return protocol.DiskPolicyMostFree
	case protocol.DiskPolicyRoundRobin:
		return protocol.DiskPolicyRoundRobin
	case protocol.DiskPolicyFirst:
		return protocol.DiskPolicyFirst
	case protocol.DiskPolicyRollingWindow:
		return protocol.DiskPolicyRollingWindow
	case protocol.DiskPolicyAffinityHash, "":
		return protocol.DiskPolicyAffinityHash
	default:
		return ""
	}
}

func normalizeConcurrencyMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case protocol.ConcurrencyManual:
		return protocol.ConcurrencyManual
	case protocol.ConcurrencyAuto, "":
		return protocol.ConcurrencyAuto
	default:
		return ""
	}
}

func (s *Store) UpsertNode(ctx context.Context, n protocol.NodeRecord, rawToken string) error {
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	if sched := normalizeProjectSchedule(n.ProjectSchedule); sched != "" {
		n.ProjectSchedule = sched
	} else {
		n.ProjectSchedule = protocol.ScheduleFIFO
	}
	if dp := normalizeDiskPolicy(n.DiskPolicy); dp != "" {
		n.DiskPolicy = dp
	} else {
		n.DiskPolicy = protocol.DiskPolicyAffinityHash
	}
	if cm := normalizeConcurrencyMode(n.ConcurrencyMode); cm != "" {
		n.ConcurrencyMode = cm
	} else {
		n.ConcurrencyMode = protocol.ConcurrencyAuto
	}
	if n.MaxConcurrentOverride < 0 {
		n.MaxConcurrentOverride = 0
	}
	if n.RateLimitMBps < 0 {
		n.RateLimitMBps = 0
	}
	if n.ActiveDiskWindow <= 0 {
		n.ActiveDiskWindow = 10
	}
	if n.ActiveDiskWindow > 256 {
		n.ActiveDiskWindow = 256
	}
	n.MaxDiskUsagePct = transfer.NormalizeMaxDiskUsagePct(n.MaxDiskUsagePct)
	projJSON, _ := json.Marshal(n.Projects)
	if n.Projects == nil {
		projJSON = []byte("[]")
	}
	storageDirsJSON, _ := json.Marshal(n.StorageDirs)
	if n.StorageDirs == nil {
		storageDirsJSON = []byte("[]")
	}
	disDisksJSON, _ := json.Marshal(n.DisabledDisks)
	if n.DisabledDisks == nil {
		disDisksJSON = []byte("[]")
	}
	unplugLockedJSON, _ := json.Marshal(n.UnplugLockedDisks)
	if n.UnplugLockedDisks == nil {
		unplugLockedJSON = []byte("[]")
	}
	pausedInt := 0
	if n.Paused {
		pausedInt = 1
	}
	diskAffInt := 1
	if !n.DiskAffinityEnabled() {
		diskAffInt = 0
	}
	tokHash := auth.HashToken(rawToken)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO nodes (id, name, role, owner_account_id, projects_json, project_schedule, disk_policy, disk_affinity, active_disk_window, storage_dirs_json, disabled_disks_json, unplug_locked_disks_json, disk_gen, max_disk_usage_pct, concurrency_mode, max_concurrent_override, rate_limit_mbps, paused, public_addr, token_hash, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name=excluded.name,
	role=excluded.role,
	owner_account_id=excluded.owner_account_id,
	projects_json=excluded.projects_json,
	project_schedule=excluded.project_schedule,
	disk_policy=excluded.disk_policy,
	disk_affinity=excluded.disk_affinity,
	active_disk_window=excluded.active_disk_window,
	storage_dirs_json=excluded.storage_dirs_json,
	disabled_disks_json=excluded.disabled_disks_json,
	unplug_locked_disks_json=excluded.unplug_locked_disks_json,
	disk_gen=excluded.disk_gen,
	max_disk_usage_pct=excluded.max_disk_usage_pct,
	concurrency_mode=excluded.concurrency_mode,
	max_concurrent_override=excluded.max_concurrent_override,
	rate_limit_mbps=excluded.rate_limit_mbps,
	paused=excluded.paused,
	public_addr=excluded.public_addr,
	token_hash=CASE WHEN ? != '' THEN excluded.token_hash ELSE nodes.token_hash END
`, n.ID, n.Name, n.Role, strings.TrimSpace(n.OwnerAccountID), string(projJSON), n.ProjectSchedule, n.DiskPolicy, diskAffInt, n.ActiveDiskWindow, string(storageDirsJSON), string(disDisksJSON), string(unplugLockedJSON), n.DiskGen, n.MaxDiskUsagePct, n.ConcurrencyMode, n.MaxConcurrentOverride, n.RateLimitMBps, pausedInt, n.PublicAddr, tokHash, n.CreatedAt, rawToken)
	return err
}

// AutoLockUnpluggedDisks atomically adds newly unplugged/swapped disk paths to disabled_disks_json
// and unplug_locked_disks_json ONLY IF the node's disk_gen still equals expectedGen (so a stale
// heartbeat can never overwrite an operator's concurrent manual re-enable).
func (s *Store) AutoLockUnpluggedDisks(ctx context.Context, nodeID string, expectedGen int64, disks []string) ([]string, []string, bool, error) {
	if len(disks) == 0 {
		return nil, nil, false, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, false, err
	}
	defer tx.Rollback()

	var disJSON, lockJSON string
	var curGen int64
	err = tx.QueryRowContext(ctx, `SELECT disabled_disks_json, unplug_locked_disks_json, disk_gen FROM nodes WHERE id = ?`, nodeID).Scan(&disJSON, &lockJSON, &curGen)
	if err != nil {
		return nil, nil, false, err
	}
	if curGen != expectedGen {
		return nil, nil, false, nil
	}
	var curDis, curLock []string
	_ = json.Unmarshal([]byte(disJSON), &curDis)
	_ = json.Unmarshal([]byte(lockJSON), &curLock)

	disSet := make(map[string]struct{}, len(curDis)+len(disks))
	for _, p := range curDis {
		disSet[p] = struct{}{}
	}
	lockSet := make(map[string]struct{}, len(curLock)+len(disks))
	for _, p := range curLock {
		lockSet[p] = struct{}{}
	}

	changed := false
	for _, raw := range disks {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if _, ok := disSet[p]; !ok {
			disSet[p] = struct{}{}
			curDis = append(curDis, p)
			changed = true
		}
		if _, ok := lockSet[p]; !ok {
			lockSet[p] = struct{}{}
			curLock = append(curLock, p)
			changed = true
		}
	}
	if !changed {
		return curDis, curLock, false, nil
	}
	newDisJSON, _ := json.Marshal(curDis)
	newLockJSON, _ := json.Marshal(curLock)
	res, err := tx.ExecContext(ctx, `
UPDATE nodes SET disabled_disks_json = ?, unplug_locked_disks_json = ?
WHERE id = ? AND disk_gen = ?
`, string(newDisJSON), string(newLockJSON), nodeID, expectedGen)
	if err != nil {
		return nil, nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, false, err
	}
	rows, _ := res.RowsAffected()
	return curDis, curLock, rows > 0, nil
}

func (s *Store) AuthenticateNode(ctx context.Context, id, rawToken, expectedRole string) (*StoredNode, error) {
	var sn StoredNode
	var projJSON, storageDirsJSON, disDisksJSON, unplugLockedJSON string
	var pausedInt, diskAffInt int
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, role, owner_account_id, projects_json, project_schedule, disk_policy, disk_affinity, active_disk_window, storage_dirs_json, disabled_disks_json, unplug_locked_disks_json, disk_gen, max_disk_usage_pct, concurrency_mode, max_concurrent_override, rate_limit_mbps, paused, public_addr, token_hash, created_at
FROM nodes WHERE id = ?
`, id).Scan(&sn.ID, &sn.Name, &sn.Role, &sn.OwnerAccountID, &projJSON, &sn.ProjectSchedule, &sn.DiskPolicy, &diskAffInt, &sn.ActiveDiskWindow, &storageDirsJSON, &disDisksJSON, &unplugLockedJSON, &sn.DiskGen, &sn.MaxDiskUsagePct, &sn.ConcurrencyMode, &sn.MaxConcurrentOverride, &sn.RateLimitMBps, &pausedInt, &sn.PublicAddr, &sn.TokenHash, &sn.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sn.Paused = pausedInt != 0
	aff := diskAffInt != 0
	sn.DiskAffinity = &aff
	if expectedRole != "" && sn.Role != expectedRole {
		return nil, errors.New("role mismatch")
	}
	if !auth.VerifyTokenHash(rawToken, sn.TokenHash) {
		return nil, errors.New("invalid node token")
	}
	_ = json.Unmarshal([]byte(projJSON), &sn.Projects)
	_ = json.Unmarshal([]byte(storageDirsJSON), &sn.StorageDirs)
	_ = json.Unmarshal([]byte(disDisksJSON), &sn.DisabledDisks)
	_ = json.Unmarshal([]byte(unplugLockedJSON), &sn.UnplugLockedDisks)
	if sn.ProjectSchedule == "" {
		sn.ProjectSchedule = protocol.ScheduleFIFO
	}
	if sn.DiskPolicy == "" {
		sn.DiskPolicy = protocol.DiskPolicyAffinityHash
	}
	if sn.ActiveDiskWindow <= 0 {
		sn.ActiveDiskWindow = 10
	}
	sn.MaxDiskUsagePct = transfer.NormalizeMaxDiskUsagePct(sn.MaxDiskUsagePct)
	if sn.ConcurrencyMode == "" {
		sn.ConcurrencyMode = protocol.ConcurrencyAuto
	}
	return &sn, nil
}

func (s *Store) ListNodes(ctx context.Context) ([]protocol.NodeRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, role, owner_account_id, projects_json, project_schedule, disk_policy, disk_affinity, active_disk_window, storage_dirs_json, disabled_disks_json, unplug_locked_disks_json, disk_gen, max_disk_usage_pct, concurrency_mode, max_concurrent_override, rate_limit_mbps, paused, public_addr, created_at
FROM nodes ORDER BY role ASC, created_at ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]protocol.NodeRecord, 0)
	for rows.Next() {
		var n protocol.NodeRecord
		var projJSON, storageDirsJSON, disDisksJSON, unplugLockedJSON string
		var pausedInt, diskAffInt int
		if err := rows.Scan(&n.ID, &n.Name, &n.Role, &n.OwnerAccountID, &projJSON, &n.ProjectSchedule, &n.DiskPolicy, &diskAffInt, &n.ActiveDiskWindow, &storageDirsJSON, &disDisksJSON, &unplugLockedJSON, &n.DiskGen, &n.MaxDiskUsagePct, &n.ConcurrencyMode, &n.MaxConcurrentOverride, &n.RateLimitMBps, &pausedInt, &n.PublicAddr, &n.CreatedAt); err != nil {
			return nil, err
		}
		n.Paused = pausedInt != 0
		aff := diskAffInt != 0
		n.DiskAffinity = &aff
		_ = json.Unmarshal([]byte(projJSON), &n.Projects)
		_ = json.Unmarshal([]byte(storageDirsJSON), &n.StorageDirs)
		_ = json.Unmarshal([]byte(disDisksJSON), &n.DisabledDisks)
		_ = json.Unmarshal([]byte(unplugLockedJSON), &n.UnplugLockedDisks)
		if n.ProjectSchedule == "" {
			n.ProjectSchedule = protocol.ScheduleFIFO
		}
		if n.DiskPolicy == "" {
			n.DiskPolicy = protocol.DiskPolicyAffinityHash
		}
		if n.ActiveDiskWindow <= 0 {
			n.ActiveDiskWindow = 10
		}
		n.MaxDiskUsagePct = transfer.NormalizeMaxDiskUsagePct(n.MaxDiskUsagePct)
		if n.ConcurrencyMode == "" {
			n.ConcurrencyMode = protocol.ConcurrencyAuto
		}
		list = append(list, n)
	}
	return list, rows.Err()
}

func (s *Store) GetNode(ctx context.Context, id string) (*protocol.NodeRecord, error) {
	var n protocol.NodeRecord
	var projJSON, storageDirsJSON, disDisksJSON, unplugLockedJSON string
	var pausedInt, diskAffInt int
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, role, owner_account_id, projects_json, project_schedule, disk_policy, disk_affinity, active_disk_window, storage_dirs_json, disabled_disks_json, unplug_locked_disks_json, disk_gen, max_disk_usage_pct, concurrency_mode, max_concurrent_override, rate_limit_mbps, paused, public_addr, created_at
FROM nodes WHERE id = ?
`, id).Scan(&n.ID, &n.Name, &n.Role, &n.OwnerAccountID, &projJSON, &n.ProjectSchedule, &n.DiskPolicy, &diskAffInt, &n.ActiveDiskWindow, &storageDirsJSON, &disDisksJSON, &unplugLockedJSON, &n.DiskGen, &n.MaxDiskUsagePct, &n.ConcurrencyMode, &n.MaxConcurrentOverride, &n.RateLimitMBps, &pausedInt, &n.PublicAddr, &n.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	n.Paused = pausedInt != 0
	aff := diskAffInt != 0
	n.DiskAffinity = &aff
	_ = json.Unmarshal([]byte(projJSON), &n.Projects)
	_ = json.Unmarshal([]byte(storageDirsJSON), &n.StorageDirs)
	_ = json.Unmarshal([]byte(disDisksJSON), &n.DisabledDisks)
	_ = json.Unmarshal([]byte(unplugLockedJSON), &n.UnplugLockedDisks)
	if n.ProjectSchedule == "" {
		n.ProjectSchedule = protocol.ScheduleFIFO
	}
	if n.DiskPolicy == "" {
		n.DiskPolicy = protocol.DiskPolicyAffinityHash
	}
	if n.ActiveDiskWindow <= 0 {
		n.ActiveDiskWindow = 10
	}
	n.MaxDiskUsagePct = transfer.NormalizeMaxDiskUsagePct(n.MaxDiskUsagePct)
	if n.ConcurrencyMode == "" {
		n.ConcurrencyMode = protocol.ConcurrencyAuto
	}
	return &n, nil
}

func (s *Store) DeleteNode(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordSummaryEvents idempotently aggregates summary events into stats_daily and stats_project_total.
func (s *Store) RecordSummaryEvents(ctx context.Context, events []protocol.SummaryEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	applied := 0
	for _, ev := range events {
		if ev.EventID == "" || ev.ProjectID == "" {
			continue
		}
		ts := ev.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO event_dedup (event_id, created_at) VALUES (?, ?)`, ev.EventID, ts)
		if err != nil {
			return 0, err
		}
		rows, _ := res.RowsAffected()
		if rows == 0 {
			// Duplicate event already counted; skip idempotently.
			continue
		}

		var up, cmp, fail, bytes, dur int64
		switch ev.EventType {
		case protocol.EventUploaded:
			up = 1
		case protocol.EventCompleted:
			cmp = 1
			bytes = ev.Bytes
			dur = ev.DurationMs
		case protocol.EventFailed:
			fail = 1
		default:
			continue
		}

		day := ts.UTC().Format("2006-01-02")
		_, err = tx.ExecContext(ctx, `
INSERT INTO stats_daily (date, project_id, a_node_id, files_uploaded, files_completed, files_failed, bytes_transferred, total_duration_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(date, project_id, a_node_id) DO UPDATE SET
	files_uploaded = files_uploaded + excluded.files_uploaded,
	files_completed = files_completed + excluded.files_completed,
	files_failed = files_failed + excluded.files_failed,
	bytes_transferred = bytes_transferred + excluded.bytes_transferred,
	total_duration_ms = total_duration_ms + excluded.total_duration_ms
`, day, ev.ProjectID, ev.ANodeID, up, cmp, fail, bytes, dur)
		if err != nil {
			return 0, err
		}

		bucketTs := (ts.UTC().Unix() / BaseIntervalSec) * BaseIntervalSec
		_, err = tx.ExecContext(ctx, `
INSERT INTO stats_intervals (bucket_ts, project_id, a_node_id, b_node_id, files_uploaded, files_completed, files_failed, bytes_transferred, total_duration_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(bucket_ts, project_id, a_node_id, b_node_id) DO UPDATE SET
	files_uploaded = files_uploaded + excluded.files_uploaded,
	files_completed = files_completed + excluded.files_completed,
	files_failed = files_failed + excluded.files_failed,
	bytes_transferred = bytes_transferred + excluded.bytes_transferred,
	total_duration_ms = total_duration_ms + excluded.total_duration_ms
`, bucketTs, ev.ProjectID, ev.ANodeID, ev.BNodeID, up, cmp, fail, bytes, dur)
		if err != nil {
			return 0, err
		}

		_, err = tx.ExecContext(ctx, `
INSERT INTO stats_project_total (project_id, total_uploaded, total_completed, total_failed, total_bytes, total_duration_ms)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(project_id) DO UPDATE SET
	total_uploaded = total_uploaded + excluded.total_uploaded,
	total_completed = total_completed + excluded.total_completed,
	total_failed = total_failed + excluded.total_failed,
	total_bytes = total_bytes + excluded.total_bytes,
	total_duration_ms = total_duration_ms + excluded.total_duration_ms
`, ev.ProjectID, up, cmp, fail, bytes, dur)
		if err != nil {
			return 0, err
		}
		applied++
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return applied, nil
}

func (s *Store) GetAllProjectTotals(ctx context.Context) (map[string]ProjectTotals, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT project_id, total_uploaded, total_completed, total_failed, total_bytes
FROM stats_project_total
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]ProjectTotals)
	for rows.Next() {
		var t ProjectTotals
		if err := rows.Scan(&t.ProjectID, &t.TotalUploaded, &t.TotalCompleted, &t.TotalFailed, &t.TotalBytes); err != nil {
			return nil, err
		}
		out[t.ProjectID] = t
	}
	return out, rows.Err()
}

func sqlPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?,", n-1) + "?"
}

func (s *Store) GetDailyStats(ctx context.Context, projectID string, days int) ([]protocol.DailyStat, error) {
	return s.GetDailyStatsScoped(ctx, projectID, nil, days)
}

func (s *Store) GetDailyStatsScoped(ctx context.Context, projectID string, allowedProjects []string, days int) ([]protocol.DailyStat, error) {
	if days <= 0 {
		days = 14
	}
	since := time.Now().UTC().AddDate(0, 0, -(days - 1)).Format("2006-01-02")

	where := []string{"date >= ?"}
	args := []any{since}
	selectProj := "''"
	groupBy := "date"
	if projectID != "" {
		where = append(where, "project_id = ?")
		args = append(args, projectID)
		selectProj = "project_id"
		groupBy = "date, project_id"
	}
	if len(allowedProjects) > 0 {
		where = append(where, "project_id IN ("+sqlPlaceholders(len(allowedProjects))+")")
		for _, pid := range allowedProjects {
			args = append(args, pid)
		}
	}

	query := fmt.Sprintf(`
SELECT date, %s, '', SUM(files_uploaded), SUM(files_completed), SUM(files_failed), SUM(bytes_transferred), SUM(total_duration_ms)
FROM stats_daily
WHERE %s
GROUP BY %s
ORDER BY date ASC
`, selectProj, strings.Join(where, " AND "), groupBy)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]protocol.DailyStat, 0)
	for rows.Next() {
		var d protocol.DailyStat
		if err := rows.Scan(&d.Date, &d.ProjectID, &d.ANodeID, &d.FilesUploaded, &d.FilesCompleted, &d.FilesFailed, &d.BytesTransferred, &d.TotalDurationMs); err != nil {
			return nil, err
		}
		list = append(list, d)
	}
	return list, rows.Err()
}

func (s *Store) CleanupOldDedup(ctx context.Context, retention time.Duration) error {
	cutoff := time.Now().UTC().Add(-retention)
	_, err := s.db.ExecContext(ctx, `DELETE FROM event_dedup WHERE created_at < ?`, cutoff)
	return err
}

func (s *Store) CleanupOldIntervals(ctx context.Context, retention time.Duration) error {
	cutoff := time.Now().UTC().Add(-retention).Unix()
	_, err := s.db.ExecContext(ctx, `DELETE FROM stats_intervals WHERE bucket_ts < ?`, cutoff)
	return err
}

func normalizeBucketMinutes(hours, requested int) int {
	if requested <= 0 {
		switch {
		case hours <= 6:
			return 10
		case hours <= 24:
			return 30
		case hours <= 72:
			return 120
		case hours <= 168:
			return 360
		default:
			return 1440
		}
	}
	if requested < 5 {
		requested = 5
	}
	if requested > 1440 {
		requested = 1440
	}
	// Snap to a multiple of 5 minutes (base storage bucket).
	snapped := ((requested + 2) / 5) * 5
	if snapped < 5 {
		snapped = 5
	}
	return snapped
}

func effectiveBucketSec(bucketStart, bucketSec, nowUnix int64) int64 {
	bucketEnd := bucketStart + bucketSec
	if nowUnix >= bucketEnd {
		return bucketSec
	}
	elapsed := nowUnix - bucketStart
	if elapsed < 15 {
		elapsed = 15
	}
	if elapsed > bucketSec {
		elapsed = bucketSec
	}
	return elapsed
}

func (s *Store) QueryIntervalStats(ctx context.Context, q IntervalQuery) (*protocol.IntervalStatsResp, error) {
	now := q.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	var (
		startTime    time.Time
		endTime      time.Time
		hours        int
		customWindow bool
	)
	if !q.Start.IsZero() && !q.End.IsZero() && q.End.After(q.Start) {
		customWindow = true
		startTime = q.Start.UTC()
		endTime = q.End.UTC()
		if endTime.Sub(startTime) > 31*24*time.Hour {
			startTime = endTime.Add(-31 * 24 * time.Hour)
		}
		hours = int((endTime.Sub(startTime) + time.Hour - 1) / time.Hour)
		if hours < 1 {
			hours = 1
		}
	} else {
		hours = q.Hours
		if hours <= 0 {
			hours = 24
		}
		if hours > 720 {
			hours = 720
		}
		endTime = now
		startTime = endTime.Add(-time.Duration(hours) * time.Hour)
	}

	bucketMin := normalizeBucketMinutes(hours, q.BucketMinutes)
	bucketSec := int64(bucketMin) * 60

	lastSlot := (endTime.Unix() / bucketSec) * bucketSec
	var firstSlot int64
	if customWindow {
		firstSlot = (startTime.Unix() / bucketSec) * bucketSec
	} else {
		nSlots := int((int64(hours) * 3600) / bucketSec)
		if nSlots < 1 {
			nSlots = 1
		}
		firstSlot = lastSlot - int64(nSlots-1)*bucketSec
	}
	if firstSlot > lastSlot {
		firstSlot = lastSlot
	}
	nSlots := int((lastSlot-firstSlot)/bucketSec) + 1
	if nSlots > 1000 {
		firstSlot = lastSlot - int64(999)*bucketSec
		nSlots = 1000
	}

	where := []string{"bucket_ts >= ?", "bucket_ts < ?"}
	args := []any{bucketSec, bucketSec, firstSlot, lastSlot + bucketSec}
	if q.ScopeRestricted && len(q.AllowedProjects) == 0 {
		// Customer with zero assigned projects: default-deny returns empty zeroed buckets cleanly.
		where = append(where, "1 = 0")
	} else if len(q.AllowedProjects) > 0 {
		where = append(where, "project_id IN ("+sqlPlaceholders(len(q.AllowedProjects))+")")
		for _, pid := range q.AllowedProjects {
			args = append(args, pid)
		}
	}
	if q.ProjectID != "" {
		where = append(where, "project_id = ?")
		args = append(args, q.ProjectID)
	}
	if q.ANodeID != "" {
		where = append(where, "a_node_id = ?")
		args = append(args, q.ANodeID)
	}
	if q.BNodeID != "" {
		where = append(where, "b_node_id = ?")
		args = append(args, q.BNodeID)
	}

	query := fmt.Sprintf(`
SELECT (bucket_ts / ?) * ? AS coarse_ts,
       SUM(files_uploaded), SUM(files_completed), SUM(files_failed), SUM(bytes_transferred)
FROM stats_intervals
WHERE %s
GROUP BY coarse_ts
ORDER BY coarse_ts ASC
`, strings.Join(where, " AND "))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type rawAgg struct {
		up, cmp, fail, bytes int64
	}
	bySlot := make(map[int64]rawAgg, nSlots)
	for rows.Next() {
		var slot int64
		var a rawAgg
		if err := rows.Scan(&slot, &a.up, &a.cmp, &a.fail, &a.bytes); err != nil {
			return nil, err
		}
		bySlot[slot] = a
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	nowUnix := now.Unix()
	refEndUnix := endTime.Unix()
	if refEndUnix > nowUnix {
		refEndUnix = nowUnix
	}

	buckets := make([]protocol.IntervalStat, 0, nSlots)
	var (
		totalUp, totalCmp, totalFail, totalBytes int64
		activeBytes, activeSec                   int64
		peakSpeed                                int64
		totalElapsedSec                          int64
	)
	for i := 0; i < nSlots; i++ {
		slot := firstSlot + int64(i)*bucketSec
		slotEnd := slot + bucketSec
		agg := bySlot[slot]
		effSec := effectiveBucketSec(slot, bucketSec, refEndUnix)
		var avgSpeed int64
		if agg.bytes > 0 && effSec > 0 {
			avgSpeed = agg.bytes / effSec
		}
		if avgSpeed > peakSpeed {
			peakSpeed = avgSpeed
		}
		totalUp += agg.up
		totalCmp += agg.cmp
		totalFail += agg.fail
		totalBytes += agg.bytes
		if agg.bytes > 0 {
			activeBytes += agg.bytes
			activeSec += effSec
		}
		if refEndUnix >= slotEnd {
			totalElapsedSec += bucketSec
		} else if refEndUnix > slot {
			totalElapsedSec += refEndUnix - slot
		}
		buckets = append(buckets, protocol.IntervalStat{
			BucketStart:      time.Unix(slot, 0).UTC(),
			BucketEnd:        time.Unix(slotEnd, 0).UTC(),
			BucketSec:        bucketSec,
			EffectiveSec:     effSec,
			FilesUploaded:    agg.up,
			FilesCompleted:   agg.cmp,
			FilesFailed:      agg.fail,
			BytesTransferred: agg.bytes,
			AvgSpeedBps:      avgSpeed,
		})
	}
	if totalElapsedSec < activeSec {
		totalElapsedSec = activeSec
	}
	if totalElapsedSec <= 0 {
		totalElapsedSec = bucketSec
	}

	resp := &protocol.IntervalStatsResp{
		GeneratedAt:       now,
		WindowStart:       time.Unix(firstSlot, 0).UTC(),
		WindowEnd:         endTime,
		WindowHours:       hours,
		BucketMinutes:     bucketMin,
		ProjectID:         q.ProjectID,
		ANodeID:           q.ANodeID,
		BNodeID:           q.BNodeID,
		TotalUploaded:     totalUp,
		TotalCompleted:    totalCmp,
		TotalFailed:       totalFail,
		TotalBytes:        totalBytes,
		WindowAvgSpeedBps: totalBytes / totalElapsedSec,
		PeakSpeedBps:      peakSpeed,
		Buckets:           buckets,
	}
	if activeSec > 0 {
		resp.ActiveAvgSpeedBps = activeBytes / activeSec
	}
	return resp, nil
}

func (s *Store) GetWindowEntityStats(ctx context.Context, now time.Time, hours int) (
	aStats map[string]WindowSummary,
	bStats map[string]WindowSummary,
	projStats map[string]WindowSummary,
	err error,
) {
	return s.GetWindowEntityStatsScoped(ctx, now, hours, nil)
}

func (s *Store) GetWindowEntityStatsScoped(ctx context.Context, now time.Time, hours int, allowedProjects []string) (
	aStats map[string]WindowSummary,
	bStats map[string]WindowSummary,
	projStats map[string]WindowSummary,
	err error,
) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if hours <= 0 {
		hours = 24
	}
	if hours > 720 {
		hours = 720
	}
	windowSec := int64(hours) * 3600
	nowUnix := now.Unix()
	startSlot := ((nowUnix - windowSec) / BaseIntervalSec) * BaseIntervalSec

	where := []string{"bucket_ts >= ?"}
	args := []any{startSlot}
	if len(allowedProjects) > 0 {
		where = append(where, "project_id IN ("+sqlPlaceholders(len(allowedProjects))+")")
		for _, pid := range allowedProjects {
			args = append(args, pid)
		}
	}
	query := fmt.Sprintf(`
SELECT bucket_ts, project_id, a_node_id, b_node_id,
       SUM(files_completed), SUM(files_failed), SUM(bytes_transferred)
FROM stats_intervals
WHERE %s
GROUP BY bucket_ts, project_id, a_node_id, b_node_id
`, strings.Join(where, " AND "))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()

	type accum struct {
		cmp, fail, bytes int64
		activeSlots      map[int64]struct{}
	}
	add := func(m map[string]*accum, key string, slot, cmp, fail, bytes int64) {
		if key == "" {
			return
		}
		ac, ok := m[key]
		if !ok {
			ac = &accum{activeSlots: make(map[int64]struct{})}
			m[key] = ac
		}
		ac.cmp += cmp
		ac.fail += fail
		ac.bytes += bytes
		if bytes > 0 {
			ac.activeSlots[slot] = struct{}{}
		}
	}

	aAcc := make(map[string]*accum)
	bAcc := make(map[string]*accum)
	pAcc := make(map[string]*accum)
	for rows.Next() {
		var slot, cmp, fail, bytes int64
		var projID, aID, bID string
		if err := rows.Scan(&slot, &projID, &aID, &bID, &cmp, &fail, &bytes); err != nil {
			return nil, nil, nil, err
		}
		add(pAcc, projID, slot, cmp, fail, bytes)
		add(aAcc, aID, slot, cmp, fail, bytes)
		add(bAcc, bID, slot, cmp, fail, bytes)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}

	finalize := func(src map[string]*accum) map[string]WindowSummary {
		out := make(map[string]WindowSummary, len(src))
		for k, ac := range src {
			var activeSec int64
			for slot := range ac.activeSlots {
				activeSec += effectiveBucketSec(slot, BaseIntervalSec, nowUnix)
			}
			ws := WindowSummary{
				Completed:         ac.cmp,
				Failed:            ac.fail,
				Bytes:             ac.bytes,
				WindowAvgSpeedBps: ac.bytes / windowSec,
			}
			if activeSec > 0 {
				ws.ActiveAvgSpeedBps = ac.bytes / activeSec
			}
			out[k] = ws
		}
		return out
	}

	return finalize(aAcc), finalize(bAcc), finalize(pAcc), nil
}

func (s *Store) TableNames(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func (s *Store) InsertRelease(ctx context.Context, r protocol.ReleaseRecord) error {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO releases (id, role, version, os, arch, sha256, size, filename, notes, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, r.ID, r.Role, r.Version, r.OS, r.Arch, r.SHA256, r.Size, r.Filename, r.Notes, r.CreatedAt)
	return err
}

func (s *Store) ListReleases(ctx context.Context, role string) ([]protocol.ReleaseRecord, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if role != "" {
		rows, err = s.db.QueryContext(ctx, `
SELECT id, role, version, os, arch, sha256, size, filename, notes, created_at
FROM releases WHERE role = ? ORDER BY created_at DESC
`, role)
	} else {
		rows, err = s.db.QueryContext(ctx, `
SELECT id, role, version, os, arch, sha256, size, filename, notes, created_at
FROM releases ORDER BY created_at DESC
`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]protocol.ReleaseRecord, 0)
	for rows.Next() {
		var r protocol.ReleaseRecord
		if err := rows.Scan(&r.ID, &r.Role, &r.Version, &r.OS, &r.Arch, &r.SHA256, &r.Size, &r.Filename, &r.Notes, &r.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

func (s *Store) GetRelease(ctx context.Context, id string) (*protocol.ReleaseRecord, error) {
	var r protocol.ReleaseRecord
	err := s.db.QueryRowContext(ctx, `
SELECT id, role, version, os, arch, sha256, size, filename, notes, created_at
FROM releases WHERE id = ?
`, id).Scan(&r.ID, &r.Role, &r.Version, &r.OS, &r.Arch, &r.SHA256, &r.Size, &r.Filename, &r.Notes, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) LatestReleaseFor(ctx context.Context, role, osName, arch string) (*protocol.ReleaseRecord, error) {
	var r protocol.ReleaseRecord
	err := s.db.QueryRowContext(ctx, `
SELECT id, role, version, os, arch, sha256, size, filename, notes, created_at
FROM releases WHERE role = ? AND os = ? AND arch = ?
ORDER BY created_at DESC LIMIT 1
`, role, osName, arch).Scan(&r.ID, &r.Role, &r.Version, &r.OS, &r.Arch, &r.SHA256, &r.Size, &r.Filename, &r.Notes, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) DeleteRelease(ctx context.Context, id string) (*protocol.ReleaseRecord, error) {
	r, err := s.GetRelease(ctx, id)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM releases WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) UpsertNodeUpgrade(ctx context.Context, u protocol.NodeUpgradeRecord) error {
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO node_upgrades (node_id, release_id, attempt_id, target_version, status, message, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(node_id) DO UPDATE SET
	release_id=excluded.release_id,
	attempt_id=excluded.attempt_id,
	target_version=excluded.target_version,
	status=excluded.status,
	message=excluded.message,
	updated_at=excluded.updated_at
`, u.NodeID, u.ReleaseID, u.AttemptID, u.TargetVersion, u.Status, u.Message, u.UpdatedAt)
	return err
}

func (s *Store) GetNodeUpgrade(ctx context.Context, nodeID string) (*protocol.NodeUpgradeRecord, error) {
	var u protocol.NodeUpgradeRecord
	err := s.db.QueryRowContext(ctx, `
SELECT node_id, release_id, attempt_id, target_version, status, message, updated_at
FROM node_upgrades WHERE node_id = ?
`, nodeID).Scan(&u.NodeID, &u.ReleaseID, &u.AttemptID, &u.TargetVersion, &u.Status, &u.Message, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) ListNodeUpgrades(ctx context.Context) (map[string]protocol.NodeUpgradeRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT node_id, release_id, attempt_id, target_version, status, message, updated_at
FROM node_upgrades
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]protocol.NodeUpgradeRecord)
	for rows.Next() {
		var u protocol.NodeUpgradeRecord
		if err := rows.Scan(&u.NodeID, &u.ReleaseID, &u.AttemptID, &u.TargetVersion, &u.Status, &u.Message, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out[u.NodeID] = u
	}
	return out, rows.Err()
}

func (s *Store) DeleteNodeUpgrade(ctx context.Context, nodeID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM node_upgrades WHERE node_id = ?`, nodeID)
	return err
}

// --- Customer / Console Accounts ---

func (s *Store) CreateAccount(ctx context.Context, a protocol.AccountRecord, rawToken string) error {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.Role == "" {
		a.Role = protocol.AccountRoleCustomer
	}
	if a.Projects == nil {
		a.Projects = []string{}
	}
	projJSON, err := json.Marshal(a.Projects)
	if err != nil {
		return err
	}
	enInt := 0
	if a.Enabled {
		enInt = 1
	}
	tokHash := auth.HashToken(rawToken)
	_, err = s.db.ExecContext(ctx, `
INSERT INTO accounts (id, name, role, projects_json, enabled, token_hash, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
`, a.ID, a.Name, a.Role, string(projJSON), enInt, tokHash, a.CreatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (s *Store) UpdateAccount(ctx context.Context, a protocol.AccountRecord) error {
	if a.Projects == nil {
		a.Projects = []string{}
	}
	projJSON, err := json.Marshal(a.Projects)
	if err != nil {
		return err
	}
	enInt := 0
	if a.Enabled {
		enInt = 1
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE accounts SET name = ?, projects_json = ?, enabled = ?
WHERE id = ?
`, a.Name, string(projJSON), enInt, a.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RotateAccountToken(ctx context.Context, id, newRawToken string) (*protocol.AccountRecord, error) {
	tokHash := auth.HashToken(newRawToken)
	res, err := s.db.ExecContext(ctx, `UPDATE accounts SET token_hash = ? WHERE id = ?`, tokHash, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, ErrNotFound
	}
	return s.GetAccount(ctx, id)
}

func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetProjectCustomerAccounts atomically updates which customer accounts are authorized to access
// projectID (adding projectID to accounts in targetAccountIDs and removing it from all others).
// Returns the list of account IDs whose project permissions changed.
func (s *Store) SetProjectCustomerAccounts(ctx context.Context, projectID string, targetAccountIDs []string) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	targetSet := make(map[string]struct{}, len(targetAccountIDs))
	for _, id := range targetAccountIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			targetSet[id] = struct{}{}
		}
	}

	rows, err := tx.QueryContext(ctx, `SELECT id, projects_json FROM accounts`)
	if err != nil {
		return nil, err
	}
	type accRow struct {
		id       string
		projects []string
	}
	var all []accRow
	for rows.Next() {
		var id, projJSON string
		if err := rows.Scan(&id, &projJSON); err != nil {
			rows.Close()
			return nil, err
		}
		var projs []string
		_ = json.Unmarshal([]byte(projJSON), &projs)
		all = append(all, accRow{id: id, projects: projs})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	var changed []string
	for _, a := range all {
		_, want := targetSet[a.id]
		has := false
		filtered := make([]string, 0, len(a.projects)+1)
		for _, p := range a.projects {
			if p == projectID {
				has = true
				if want {
					filtered = append(filtered, p)
				}
			} else {
				filtered = append(filtered, p)
			}
		}
		if want && !has {
			filtered = append(filtered, projectID)
		}
		if want == has {
			continue
		}
		b, _ := json.Marshal(filtered)
		if _, err := tx.ExecContext(ctx, `UPDATE accounts SET projects_json = ? WHERE id = ?`, string(b), a.id); err != nil {
			return nil, err
		}
		changed = append(changed, a.id)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return changed, nil
}

func scanAccountRow(scanner interface{ Scan(dest ...any) error }) (*protocol.AccountRecord, string, error) {
	var a protocol.AccountRecord
	var projJSON, tokHash string
	var enInt int
	var lastUsed sql.NullTime
	if err := scanner.Scan(&a.ID, &a.Name, &a.Role, &projJSON, &enInt, &tokHash, &a.CreatedAt, &lastUsed); err != nil {
		return nil, "", err
	}
	_ = json.Unmarshal([]byte(projJSON), &a.Projects)
	if a.Projects == nil {
		a.Projects = []string{}
	}
	a.Enabled = enInt != 0
	if lastUsed.Valid {
		t := lastUsed.Time.UTC()
		a.LastUsedAt = &t
	}
	return &a, tokHash, nil
}

func (s *Store) GetAccount(ctx context.Context, id string) (*protocol.AccountRecord, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, role, projects_json, enabled, token_hash, created_at, last_used_at
FROM accounts WHERE id = ?
`, id)
	a, _, err := scanAccountRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) ListAccounts(ctx context.Context) ([]protocol.AccountRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, role, projects_json, enabled, token_hash, created_at, last_used_at
FROM accounts ORDER BY created_at DESC, id ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]protocol.AccountRecord, 0)
	for rows.Next() {
		a, _, err := scanAccountRow(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, *a)
	}
	return list, rows.Err()
}

func (s *Store) AuthenticateAccount(ctx context.Context, rawToken string) (*protocol.AccountRecord, error) {
	if rawToken == "" {
		return nil, ErrNotFound
	}
	hash := auth.HashToken(rawToken)
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, role, projects_json, enabled, token_hash, created_at, last_used_at
FROM accounts WHERE token_hash = ?
`, hash)
	a, dbHash, err := scanAccountRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !auth.EqualConstantTime(hash, dbHash) || !a.Enabled {
		return nil, ErrNotFound
	}
	now := time.Now().UTC()
	if a.LastUsedAt == nil || now.Sub(*a.LastUsedAt) >= time.Minute {
		_, _ = s.db.ExecContext(ctx, `UPDATE accounts SET last_used_at = ? WHERE id = ?`, now, a.ID)
		a.LastUsedAt = &now
	}
	return a, nil
}
