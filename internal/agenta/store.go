package agenta

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"

	"relay-download/internal/auth"
	"relay-download/internal/protocol"
)

var (
	bucketFiles         = []byte("files")
	bucketPendingEvents = []byte("pending_events")

	ErrFileNotFound   = errors.New("file not found")
	ErrLeaseInvalid   = errors.New("lease invalid or expired")
	ErrChecksumFailed = errors.New("sha256 mismatch")
	ErrNoReadyFile    = errors.New("no ready file available")
)

type FileRecord struct {
	FileID         string     `json:"file_id"`
	ProjectID      string     `json:"project_id"`
	Filename       string     `json:"filename"`
	Size           int64      `json:"size"`
	SHA256         string     `json:"sha256"`
	Status         string     `json:"status"`
	ClaimedBy      string     `json:"claimed_by,omitempty"`
	LeaseID        string     `json:"lease_id,omitempty"`
	LeaseToken     string     `json:"lease_token,omitempty"`
	LeaseTTLSec    int        `json:"lease_ttl_sec,omitempty"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	NextRetryAt    *time.Time `json:"next_retry_at,omitempty"`
	UploadedAt     time.Time  `json:"uploaded_at"`
	RetryCount     int        `json:"retry_count"`
}

func cloneFileRecord(r FileRecord) FileRecord {
	cp := r
	if r.LeaseExpiresAt != nil {
		t := *r.LeaseExpiresAt
		cp.LeaseExpiresAt = &t
	}
	if r.NextRetryAt != nil {
		t := *r.NextRetryAt
		cp.NextRetryAt = &t
	}
	return cp
}

type deletedEntry struct {
	leaseID        string
	leaseTokenHash string
	bNodeID        string
	deletedAt      time.Time
}

type Store struct {
	db      *bolt.DB
	claimMu sync.Mutex

	idxMu   sync.RWMutex
	records map[string]FileRecord

	mu          sync.Mutex
	deleted     map[string]deletedEntry
	deletedList []string
}

func OpenStore(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, err
	}
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open agent-a boltdb: %w", err)
	}
	records := make(map[string]FileRecord)
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketFiles)
		if err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(bucketPendingEvents); err != nil {
			return err
		}
		// Hydrate synchronized in-memory index once at startup for O(1) 10Gbps hot-path reads.
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec FileRecord
			if err := json.Unmarshal(v, &rec); err == nil && rec.FileID != "" {
				records[rec.FileID] = rec
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{
		db:      db,
		records: records,
		deleted: make(map[string]deletedEntry),
	}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func putPendingEventTx(tx *bolt.Tx, ev *protocol.SummaryEvent) error {
	if ev == nil || ev.EventID == "" {
		return nil
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketPendingEvents).Put([]byte(ev.EventID), raw)
}

func (s *Store) PutReady(rec FileRecord, ev *protocol.SummaryEvent) error {
	rec.Status = protocol.FileStatusReady
	rec.ClaimedBy = ""
	rec.LeaseID = ""
	rec.LeaseToken = ""
	rec.LeaseExpiresAt = nil
	if rec.UploadedAt.IsZero() {
		rec.UploadedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	// Use db.Batch so concurrent PUT uploads coalesce into a single BoltDB fsync while preserving ACID durability.
	if err := s.db.Batch(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketFiles).Put([]byte(rec.FileID), raw); err != nil {
			return err
		}
		return putPendingEventTx(tx, ev)
	}); err != nil {
		return err
	}
	s.idxMu.Lock()
	s.records[rec.FileID] = cloneFileRecord(rec)
	s.idxMu.Unlock()
	return nil
}

func (s *Store) PutReadyBatch(recs []FileRecord, evs []*protocol.SummaryEvent) error {
	if len(recs) == 0 {
		return nil
	}
	now := time.Now().UTC()
	prepared := make([]FileRecord, len(recs))
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFiles)
		for i := range recs {
			rec := recs[i]
			rec.Status = protocol.FileStatusReady
			rec.ClaimedBy = ""
			rec.LeaseID = ""
			rec.LeaseToken = ""
			rec.LeaseExpiresAt = nil
			if rec.UploadedAt.IsZero() {
				rec.UploadedAt = now
			}
			raw, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(rec.FileID), raw); err != nil {
				return err
			}
			prepared[i] = rec
		}
		for _, ev := range evs {
			if err := putPendingEventTx(tx, ev); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.idxMu.Lock()
	for _, rec := range prepared {
		s.records[rec.FileID] = cloneFileRecord(rec)
	}
	s.idxMu.Unlock()
	return nil
}

// Get returns a file record in O(1) directly from the synchronized in-memory index.
func (s *Store) Get(fileID string) (*FileRecord, error) {
	s.idxMu.RLock()
	rec, ok := s.records[fileID]
	s.idxMu.RUnlock()
	if !ok {
		return nil, ErrFileNotFound
	}
	cp := cloneFileRecord(rec)
	return &cp, nil
}

// ClaimNext atomically picks the oldest READY file for projectID that fits availDiskBytes
// and transitions it to CLAIMED with a fresh lease.
func (s *Store) ClaimNext(projectID, bNodeID string, availDiskBytes uint64, leaseTTL time.Duration) (*FileRecord, error) {
	recs, err := s.ClaimBatch(projectID, bNodeID, availDiskBytes, leaseTTL, 1)
	if err != nil {
		return nil, err
	}
	cp := cloneFileRecord(recs[0])
	return &cp, nil
}

// ClaimBatch selects up to maxCount oldest eligible files from the in-memory index in microseconds
// and persists ONLY the claimed records in a single BoltDB write transaction.
func (s *Store) ClaimBatch(projectID, bNodeID string, availDiskBytes uint64, leaseTTL time.Duration, maxCount int) ([]FileRecord, error) {
	if maxCount <= 0 {
		maxCount = 1
	}
	if maxCount > 256 {
		maxCount = 256
	}

	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	now := time.Now().UTC()
	// Snapshot eligible candidates from RAM without touching BoltDB.
	s.idxMu.RLock()
	var candidates []FileRecord
	for _, rec := range s.records {
		if rec.ProjectID != projectID {
			continue
		}
		isReady := rec.Status == protocol.FileStatusReady && (rec.NextRetryAt == nil || !rec.NextRetryAt.After(now))
		if !isReady && rec.Status == protocol.FileStatusClaimed && rec.LeaseExpiresAt != nil && !rec.LeaseExpiresAt.After(now) {
			isReady = true
		}
		if !isReady {
			continue
		}
		if availDiskBytes > 0 && uint64(rec.Size) > availDiskBytes {
			continue
		}
		candidates = append(candidates, cloneFileRecord(rec))
	}
	s.idxMu.RUnlock()

	if len(candidates) == 0 {
		return nil, ErrNoReadyFile
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].UploadedAt.Equal(candidates[j].UploadedAt) {
			return candidates[i].FileID < candidates[j].FileID
		}
		return candidates[i].UploadedAt.Before(candidates[j].UploadedAt)
	})

	var chosen []FileRecord
	exp := now.Add(leaseTTL)
	ttlSec := int(leaseTTL / time.Second)
	remainingBudget := availDiskBytes

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFiles)
		for _, cand := range candidates {
			if len(chosen) >= maxCount {
				break
			}
			// Re-verify latest durable state inside tx in case Ack/Delete raced before claimMu.
			raw := b.Get([]byte(cand.FileID))
			if raw == nil {
				continue
			}
			var rec FileRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				continue
			}
			isReady := rec.Status == protocol.FileStatusReady && (rec.NextRetryAt == nil || !rec.NextRetryAt.After(now))
			if !isReady && rec.Status == protocol.FileStatusClaimed && rec.LeaseExpiresAt != nil && !rec.LeaseExpiresAt.After(now) {
				isReady = true
				rec.RetryCount++
			}
			if !isReady {
				continue
			}
			if availDiskBytes > 0 {
				if uint64(rec.Size) > remainingBudget {
					continue
				}
				remainingBudget -= uint64(rec.Size)
			}

			rec.Status = protocol.FileStatusClaimed
			rec.ClaimedBy = bNodeID
			rec.LeaseID = uuid.NewString()
			rec.LeaseToken = auth.GenerateRandomToken(24)
			rec.LeaseTTLSec = ttlSec
			e := exp
			rec.LeaseExpiresAt = &e
			rec.NextRetryAt = nil

			out, err := json.Marshal(&rec)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(rec.FileID), out); err != nil {
				return err
			}
			chosen = append(chosen, rec)
		}
		if len(chosen) == 0 {
			return ErrNoReadyFile
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.idxMu.Lock()
	for _, rec := range chosen {
		s.records[rec.FileID] = cloneFileRecord(rec)
	}
	s.idxMu.Unlock()
	return chosen, nil
}

// VerifyActiveLease checks the lease in O(1) from RAM — zero BoltDB reads on 10Gbps range streams.
func (s *Store) VerifyActiveLease(fileID, leaseToken string) (*FileRecord, error) {
	rec, err := s.Get(fileID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if rec.Status != protocol.FileStatusClaimed || rec.LeaseExpiresAt == nil || !rec.LeaseExpiresAt.After(now) {
		return nil, ErrLeaseInvalid
	}
	if !auth.EqualConstantTime(leaseToken, rec.LeaseToken) {
		return nil, ErrLeaseInvalid
	}
	return rec, nil
}

func (s *Store) RenewLease(fileID, leaseID, leaseToken, bNodeID string, leaseTTL time.Duration) (time.Time, error) {
	now := time.Now().UTC()
	// Fast O(1) RAM rejection for invalid/expired leases before hitting BoltDB.
	s.idxMu.RLock()
	cur, ok := s.records[fileID]
	s.idxMu.RUnlock()
	if !ok {
		return time.Time{}, ErrFileNotFound
	}
	if cur.Status != protocol.FileStatusClaimed || cur.LeaseExpiresAt == nil || !cur.LeaseExpiresAt.After(now) ||
		!auth.EqualConstantTime(leaseToken, cur.LeaseToken) ||
		(leaseID != "" && cur.LeaseID != leaseID) ||
		(bNodeID != "" && cur.ClaimedBy != bNodeID) {
		return time.Time{}, ErrLeaseInvalid
	}

	var newExp time.Time
	var updated FileRecord
	// Coalesce concurrent 10Gbps lease renewals via db.Batch.
	err := s.db.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFiles)
		raw := b.Get([]byte(fileID))
		if raw == nil {
			return ErrFileNotFound
		}
		var rec FileRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if rec.Status != protocol.FileStatusClaimed || rec.LeaseExpiresAt == nil || !rec.LeaseExpiresAt.After(now) {
			return ErrLeaseInvalid
		}
		if !auth.EqualConstantTime(leaseToken, rec.LeaseToken) {
			return ErrLeaseInvalid
		}
		if leaseID != "" && rec.LeaseID != leaseID {
			return ErrLeaseInvalid
		}
		if bNodeID != "" && rec.ClaimedBy != bNodeID {
			return ErrLeaseInvalid
		}
		newExp = now.Add(leaseTTL)
		e := newExp
		rec.LeaseExpiresAt = &e
		out, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(fileID), out); err != nil {
			return err
		}
		updated = rec
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}

	s.idxMu.Lock()
	if existing, ok := s.records[fileID]; ok && existing.LeaseID == updated.LeaseID {
		s.records[fileID] = cloneFileRecord(updated)
	}
	s.idxMu.Unlock()
	return newExp, nil
}

func (s *Store) IsRecentlyDeletedFor(fileID, leaseID, leaseToken, bNodeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ent, ok := s.deleted[fileID]
	if !ok {
		return false
	}
	if time.Since(ent.deletedAt) > 2*time.Hour {
		delete(s.deleted, fileID)
		return false
	}
	return ent.leaseID == leaseID && ent.bNodeID == bNodeID && auth.VerifyTokenHash(leaseToken, ent.leaseTokenHash)
}

func (s *Store) markDeleted(fileID, leaseID, leaseToken, bNodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.deleted[fileID]; !exists {
		s.deletedList = append(s.deletedList, fileID)
	}
	s.deleted[fileID] = deletedEntry{
		leaseID:        leaseID,
		leaseTokenHash: auth.HashToken(leaseToken),
		bNodeID:        bNodeID,
		deletedAt:      time.Now(),
	}
	const maxLRU = 100000
	for len(s.deletedList) > maxLRU {
		oldest := s.deletedList[0]
		s.deletedList = s.deletedList[1:]
		delete(s.deleted, oldest)
	}
}

// BatchAckAndRemove validates a batch of ACK items in a single BoltDB write transaction.
// Only items whose lease_id, lease_token, b_node_id, and sha256 ALL match the active record
// are removed from BoltDB and returned in deletedRecs for spool cleanup.
func (s *Store) BatchAckAndRemove(
	bNodeID string,
	items []protocol.BatchAckItem,
	removeFile func(fileID string) error,
	buildEvent func(rec FileRecord, durationMs int64) *protocol.SummaryEvent,
) ([]protocol.BatchAckItemResult, []FileRecord, error) {
	results := make([]protocol.BatchAckItemResult, len(items))
	type verifiedItem struct {
		rec        FileRecord
		leaseID    string
		leaseToken string
	}
	var verified []verifiedItem

	needTx := false
	for i, it := range items {
		results[i].FileID = it.FileID
		if it.FileID == "" || it.LeaseID == "" || it.LeaseToken == "" {
			results[i].Status = "lease_invalid"
			results[i].Error = "file_id, lease_id, and lease_token are required"
			continue
		}
		if s.IsRecentlyDeletedFor(it.FileID, it.LeaseID, it.LeaseToken, bNodeID) {
			results[i].Status = "already_deleted"
			continue
		}
		needTx = true
	}

	if needTx {
		err := s.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketFiles)
			for i, it := range items {
				if results[i].Status != "" {
					continue
				}
				raw := b.Get([]byte(it.FileID))
				if raw == nil {
					if s.IsRecentlyDeletedFor(it.FileID, it.LeaseID, it.LeaseToken, bNodeID) {
						results[i].Status = "already_deleted"
					} else {
						results[i].Status = "not_found"
						results[i].Error = "file not found"
					}
					continue
				}
				var rec FileRecord
				if err := json.Unmarshal(raw, &rec); err != nil {
					results[i].Status = "error"
					results[i].Error = err.Error()
					continue
				}
				if rec.Status != protocol.FileStatusClaimed ||
					!auth.EqualConstantTime(it.LeaseToken, rec.LeaseToken) ||
					rec.LeaseID != it.LeaseID ||
					rec.ClaimedBy != bNodeID {
					results[i].Status = "lease_invalid"
					results[i].Error = "lease invalid or expired"
					continue
				}
				if !strings.EqualFold(strings.TrimSpace(it.SHA256), rec.SHA256) {
					results[i].Status = "checksum_failed"
					results[i].Error = "sha256 mismatch"
					continue
				}
				if removeFile != nil {
					if err := removeFile(it.FileID); err != nil {
						results[i].Status = "error"
						results[i].Error = err.Error()
						continue
					}
				}
				if err := b.Delete([]byte(it.FileID)); err != nil {
					return err
				}
				if buildEvent != nil {
					if err := putPendingEventTx(tx, buildEvent(rec, it.DurationMs)); err != nil {
						return err
					}
				}
				results[i].Status = "deleted"
				verified = append(verified, verifiedItem{
					rec:        rec,
					leaseID:    it.LeaseID,
					leaseToken: it.LeaseToken,
				})
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}

	deletedRecs := make([]FileRecord, 0, len(verified))
	if len(verified) > 0 {
		s.idxMu.Lock()
		for _, v := range verified {
			delete(s.records, v.rec.FileID)
		}
		s.idxMu.Unlock()
		for _, v := range verified {
			s.markDeleted(v.rec.FileID, v.leaseID, v.leaseToken, bNodeID)
			deletedRecs = append(deletedRecs, v.rec)
		}
	}
	return results, deletedRecs, nil
}

// AckAndRemove validates the lease & SHA256, invokes removeFile to unlink the backing file,
// then deletes the active record and enqueues the summary event in BoltDB atomically
// (or returns nil, true if already deleted).
func (s *Store) AckAndRemove(fileID, leaseID, leaseToken, bNodeID, sha256Hex string, removeFile func(fileID string) error, buildEvent func(rec FileRecord) *protocol.SummaryEvent) (*FileRecord, bool, error) {
	if s.IsRecentlyDeletedFor(fileID, leaseID, leaseToken, bNodeID) {
		return nil, true, nil
	}
	var deletedRec FileRecord
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFiles)
		raw := b.Get([]byte(fileID))
		if raw == nil {
			return ErrFileNotFound
		}
		if err := json.Unmarshal(raw, &deletedRec); err != nil {
			return err
		}
		if deletedRec.Status != protocol.FileStatusClaimed {
			return ErrLeaseInvalid
		}
		if !auth.EqualConstantTime(leaseToken, deletedRec.LeaseToken) || deletedRec.LeaseID != leaseID || deletedRec.ClaimedBy != bNodeID {
			return ErrLeaseInvalid
		}
		if !strings.EqualFold(strings.TrimSpace(sha256Hex), deletedRec.SHA256) {
			return ErrChecksumFailed
		}
		if removeFile != nil {
			if err := removeFile(fileID); err != nil {
				return err
			}
		}
		if err := b.Delete([]byte(fileID)); err != nil {
			return err
		}
		if buildEvent != nil {
			return putPendingEventTx(tx, buildEvent(deletedRec))
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrFileNotFound) && s.IsRecentlyDeletedFor(fileID, leaseID, leaseToken, bNodeID) {
			return nil, true, nil
		}
		return nil, false, err
	}
	s.idxMu.Lock()
	delete(s.records, fileID)
	s.idxMu.Unlock()
	s.markDeleted(fileID, leaseID, leaseToken, bNodeID)
	return &deletedRec, false, nil
}

func (s *Store) Nack(fileID, leaseID, leaseToken, bNodeID string, buildEvent func(rec FileRecord) *protocol.SummaryEvent) (*FileRecord, error) {
	var rec FileRecord
	now := time.Now().UTC()
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFiles)
		raw := b.Get([]byte(fileID))
		if raw == nil {
			return ErrFileNotFound
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		if rec.Status != protocol.FileStatusClaimed {
			return ErrLeaseInvalid
		}
		if !auth.EqualConstantTime(leaseToken, rec.LeaseToken) || rec.LeaseID != leaseID || rec.ClaimedBy != bNodeID {
			return ErrLeaseInvalid
		}
		rec.Status = protocol.FileStatusReady
		rec.ClaimedBy = ""
		rec.LeaseID = ""
		rec.LeaseToken = ""
		rec.LeaseTTLSec = 0
		rec.LeaseExpiresAt = nil
		rec.RetryCount++
		shift := rec.RetryCount - 1
		if shift > 4 {
			shift = 4
		}
		delay := (2 * time.Second) << shift
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		nextAt := now.Add(delay)
		rec.NextRetryAt = &nextAt
		out, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(fileID), out); err != nil {
			return err
		}
		if buildEvent != nil {
			return putPendingEventTx(tx, buildEvent(rec))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.idxMu.Lock()
	s.records[fileID] = cloneFileRecord(rec)
	s.idxMu.Unlock()
	return &rec, nil
}

// ReapExpiredLeases checks the in-memory index first and skips BoltDB entirely when nothing expired.
func (s *Store) ReapExpiredLeases(now time.Time) (int, error) {
	s.idxMu.RLock()
	var expiredIDs []string
	for id, rec := range s.records {
		if (rec.Status == protocol.FileStatusClaimed && rec.LeaseExpiresAt != nil && !rec.LeaseExpiresAt.After(now)) ||
			(rec.Status == protocol.FileStatusReady && rec.NextRetryAt != nil && !rec.NextRetryAt.After(now)) {
			expiredIDs = append(expiredIDs, id)
		}
	}
	s.idxMu.RUnlock()
	if len(expiredIDs) == 0 {
		return 0, nil
	}

	s.claimMu.Lock()
	defer s.claimMu.Unlock()

	reaped := 0
	updated := make([]FileRecord, 0, len(expiredIDs))
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFiles)
		for _, id := range expiredIDs {
			raw := b.Get([]byte(id))
			if raw == nil {
				continue
			}
			var rec FileRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				continue
			}
			changed := false
			if rec.Status == protocol.FileStatusClaimed && rec.LeaseExpiresAt != nil && !rec.LeaseExpiresAt.After(now) {
				rec.Status = protocol.FileStatusReady
				rec.ClaimedBy = ""
				rec.LeaseID = ""
				rec.LeaseToken = ""
				rec.LeaseTTLSec = 0
				rec.LeaseExpiresAt = nil
				rec.NextRetryAt = nil
				rec.RetryCount++
				changed = true
			} else if rec.Status == protocol.FileStatusReady && rec.NextRetryAt != nil && !rec.NextRetryAt.After(now) {
				rec.NextRetryAt = nil
				changed = true
			}
			if changed {
				out, err := json.Marshal(rec)
				if err != nil {
					return err
				}
				if err := b.Put([]byte(id), out); err != nil {
					return err
				}
				updated = append(updated, rec)
				reaped++
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if len(updated) > 0 {
		s.idxMu.Lock()
		for _, rec := range updated {
			if _, ok := s.records[rec.FileID]; ok {
				s.records[rec.FileID] = cloneFileRecord(rec)
			}
		}
		s.idxMu.Unlock()
	}
	return reaped, nil
}

func (s *Store) ListLive(projectFilter string) ([]protocol.LiveFileItem, error) {
	items, _, _, err := s.ListLiveLimit(projectFilter, 0)
	return items, err
}

func (s *Store) ListLiveLimit(projectFilter string, limit int) ([]protocol.LiveFileItem, int, bool, error) {
	s.idxMu.RLock()
	items := make([]protocol.LiveFileItem, 0, len(s.records))
	for _, rec := range s.records {
		if projectFilter != "" && rec.ProjectID != projectFilter {
			continue
		}
		cp := cloneFileRecord(rec)
		items = append(items, protocol.LiveFileItem{
			FileID:         cp.FileID,
			ProjectID:      cp.ProjectID,
			Filename:       cp.Filename,
			Size:           cp.Size,
			SHA256:         cp.SHA256,
			Status:         cp.Status,
			ClaimedBy:      cp.ClaimedBy,
			LeaseExpiresAt: cp.LeaseExpiresAt,
			UploadedAt:     cp.UploadedAt,
			RetryCount:     cp.RetryCount,
		})
	}
	s.idxMu.RUnlock()

	sort.Slice(items, func(i, j int) bool {
		return items[i].UploadedAt.Before(items[j].UploadedAt)
	})
	total := len(items)
	truncated := false
	if limit > 0 && len(items) > limit {
		items = items[:limit]
		truncated = true
	}
	return items, total, truncated, nil
}

func (s *Store) ComputeStats(projectFilter string) (readyCount, claimedCount int, readyBytes, claimedBytes int64, err error) {
	s.idxMu.RLock()
	for _, rec := range s.records {
		if projectFilter != "" && rec.ProjectID != projectFilter {
			continue
		}
		switch rec.Status {
		case protocol.FileStatusReady:
			readyCount++
			readyBytes += rec.Size
		case protocol.FileStatusClaimed:
			claimedCount++
			claimedBytes += rec.Size
		}
	}
	s.idxMu.RUnlock()
	return readyCount, claimedCount, readyBytes, claimedBytes, nil
}

func (s *Store) ComputeAvailability() ([]protocol.ProjectAvailability, error) {
	byProj := make(map[string]*protocol.ProjectAvailability)
	now := time.Now().UTC()
	s.idxMu.RLock()
	for _, rec := range s.records {
		av, ok := byProj[rec.ProjectID]
		if !ok {
			av = &protocol.ProjectAvailability{ProjectID: rec.ProjectID}
			byProj[rec.ProjectID] = av
		}
		switch rec.Status {
		case protocol.FileStatusReady:
			if rec.NextRetryAt == nil || !rec.NextRetryAt.After(now) {
				av.ReadyCount++
				av.ReadyBytes += rec.Size
			}
		case protocol.FileStatusClaimed:
			av.ClaimedCount++
		}
	}
	s.idxMu.RUnlock()

	res := make([]protocol.ProjectAvailability, 0, len(byProj))
	for _, v := range byProj {
		res = append(res, *v)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].ProjectID < res[j].ProjectID
	})
	return res, nil
}

func (s *Store) DeleteRecord(fileID string) error {
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketFiles).Delete([]byte(fileID))
	}); err != nil {
		return err
	}
	s.idxMu.Lock()
	delete(s.records, fileID)
	s.idxMu.Unlock()
	return nil
}

func (s *Store) AllFileIDs() (map[string]struct{}, error) {
	s.idxMu.RLock()
	ids := make(map[string]struct{}, len(s.records))
	for id := range s.records {
		ids[id] = struct{}{}
	}
	s.idxMu.RUnlock()
	return ids, nil
}

func (s *Store) EnqueueEvent(ev protocol.SummaryEvent) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketPendingEvents).Put([]byte(ev.EventID), raw)
	})
}

func (s *Store) ListPendingEvents(limit int) ([]protocol.SummaryEvent, error) {
	var events []protocol.SummaryEvent
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketPendingEvents).Cursor()
		for k, v := c.First(); k != nil && len(events) < limit; k, v = c.Next() {
			var ev protocol.SummaryEvent
			if err := json.Unmarshal(v, &ev); err == nil {
				events = append(events, ev)
			}
		}
		return nil
	})
	return events, err
}

func (s *Store) DeletePendingEvents(ids []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPendingEvents)
		for _, id := range ids {
			if err := b.Delete([]byte(id)); err != nil {
				return err
			}
		}
		return nil
	})
}
