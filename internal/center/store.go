package center

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"relay-download/internal/auth"
	"relay-download/internal/protocol"
)

var (
	ErrNotFound = errors.New("not found")
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
`
	_, err := db.Exec(schema)
	return err
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
	_, err := s.db.ExecContext(ctx, `
INSERT INTO projects (id, name, description, conflict_policy, lease_ttl_sec, created_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name=excluded.name,
	description=excluded.description,
	conflict_policy=excluded.conflict_policy,
	lease_ttl_sec=excluded.lease_ttl_sec
`, p.ID, p.Name, p.Description, p.ConflictPolicy, p.LeaseTTLSec, p.CreatedAt)
	return err
}

func (s *Store) GetProject(ctx context.Context, id string) (*protocol.Project, error) {
	var p protocol.Project
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, description, conflict_policy, lease_ttl_sec, created_at
FROM projects WHERE id = ?
`, id).Scan(&p.ID, &p.Name, &p.Description, &p.ConflictPolicy, &p.LeaseTTLSec, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListProjects(ctx context.Context) ([]protocol.Project, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, description, conflict_policy, lease_ttl_sec, created_at
FROM projects ORDER BY created_at ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]protocol.Project, 0)
	for rows.Next() {
		var p protocol.Project
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.ConflictPolicy, &p.LeaseTTLSec, &p.CreatedAt); err != nil {
			return nil, err
		}
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

func (s *Store) UpsertNode(ctx context.Context, n protocol.NodeRecord, rawToken string) error {
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	projJSON, _ := json.Marshal(n.Projects)
	tokHash := auth.HashToken(rawToken)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO nodes (id, name, role, projects_json, public_addr, token_hash, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name=excluded.name,
	role=excluded.role,
	projects_json=excluded.projects_json,
	public_addr=excluded.public_addr,
	token_hash=CASE WHEN ? != '' THEN excluded.token_hash ELSE nodes.token_hash END
`, n.ID, n.Name, n.Role, string(projJSON), n.PublicAddr, tokHash, n.CreatedAt, rawToken)
	return err
}

func (s *Store) AuthenticateNode(ctx context.Context, id, rawToken, expectedRole string) (*StoredNode, error) {
	var sn StoredNode
	var projJSON string
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, role, projects_json, public_addr, token_hash, created_at
FROM nodes WHERE id = ?
`, id).Scan(&sn.ID, &sn.Name, &sn.Role, &projJSON, &sn.PublicAddr, &sn.TokenHash, &sn.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if expectedRole != "" && sn.Role != expectedRole {
		return nil, errors.New("role mismatch")
	}
	if !auth.VerifyTokenHash(rawToken, sn.TokenHash) {
		return nil, errors.New("invalid node token")
	}
	_ = json.Unmarshal([]byte(projJSON), &sn.Projects)
	return &sn, nil
}

func (s *Store) ListNodes(ctx context.Context) ([]protocol.NodeRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, role, projects_json, public_addr, created_at
FROM nodes ORDER BY role ASC, created_at ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]protocol.NodeRecord, 0)
	for rows.Next() {
		var n protocol.NodeRecord
		var projJSON string
		if err := rows.Scan(&n.ID, &n.Name, &n.Role, &projJSON, &n.PublicAddr, &n.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(projJSON), &n.Projects)
		list = append(list, n)
	}
	return list, rows.Err()
}

func (s *Store) GetNode(ctx context.Context, id string) (*protocol.NodeRecord, error) {
	var n protocol.NodeRecord
	var projJSON string
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, role, projects_json, public_addr, created_at
FROM nodes WHERE id = ?
`, id).Scan(&n.ID, &n.Name, &n.Role, &projJSON, &n.PublicAddr, &n.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(projJSON), &n.Projects)
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

func (s *Store) GetDailyStats(ctx context.Context, projectID string, days int) ([]protocol.DailyStat, error) {
	if days <= 0 {
		days = 14
	}
	since := time.Now().UTC().AddDate(0, 0, -(days - 1)).Format("2006-01-02")

	var (
		rows *sql.Rows
		err  error
	)
	if projectID != "" {
		rows, err = s.db.QueryContext(ctx, `
SELECT date, project_id, '', SUM(files_uploaded), SUM(files_completed), SUM(files_failed), SUM(bytes_transferred), SUM(total_duration_ms)
FROM stats_daily
WHERE date >= ? AND project_id = ?
GROUP BY date, project_id
ORDER BY date ASC
`, since, projectID)
	} else {
		rows, err = s.db.QueryContext(ctx, `
SELECT date, '', '', SUM(files_uploaded), SUM(files_completed), SUM(files_failed), SUM(bytes_transferred), SUM(total_duration_ms)
FROM stats_daily
WHERE date >= ?
GROUP BY date
ORDER BY date ASC
`, since)
	}
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
