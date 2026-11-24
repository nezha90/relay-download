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

type deletedEntry struct {
	leaseID        string
	leaseTokenHash string
	bNodeID        string
	deletedAt      time.Time
}

type Store struct {
	db          *bolt.DB
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
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketFiles); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketPendingEvents)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{
		db:      db,
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
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFiles)
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := b.Put([]byte(rec.FileID), raw); err != nil {
			return err
		}
		return putPendingEventTx(tx, ev)
	})
}

func (s *Store) Get(fileID string) (*FileRecord, error) {
	var rec FileRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketFiles).Get([]byte(fileID))
		if raw == nil {
			return ErrFileNotFound
		}
		return json.Unmarshal(raw, &rec)
	})
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// ClaimNext atomically picks the oldest READY file for projectID that fits availDiskBytes
// and transitions it to CLAIMED with a fresh lease.
func (s *Store) ClaimNext(projectID, bNodeID string, availDiskBytes uint64, leaseTTL time.Duration) (*FileRecord, error) {
	var chosen *FileRecord
	now := time.Now().UTC()
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFiles)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec FileRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				continue
			}
			if rec.ProjectID != projectID {
				continue
			}
			// Also allow reclaiming an already-expired lease atomically.
			isReady := rec.Status == protocol.FileStatusReady && (rec.NextRetryAt == nil || !rec.NextRetryAt.After(now))
			if !isReady && rec.Status == protocol.FileStatusClaimed && rec.LeaseExpiresAt != nil && !rec.LeaseExpiresAt.After(now) {
				isReady = true
				rec.RetryCount++
			}
			if !isReady {
				continue
			}
			if availDiskBytes > 0 && uint64(rec.Size) > availDiskBytes {
				continue
			}
			if chosen == nil || rec.UploadedAt.Before(chosen.UploadedAt) {
				cp := rec
				chosen = &cp
			}
		}
		if chosen == nil {
			return ErrNoReadyFile
		}
		exp := now.Add(leaseTTL)
		chosen.Status = protocol.FileStatusClaimed
		chosen.ClaimedBy = bNodeID
		chosen.LeaseID = uuid.NewString()
		chosen.LeaseToken = auth.GenerateRandomToken(24)
		chosen.LeaseTTLSec = int(leaseTTL / time.Second)
		chosen.LeaseExpiresAt = &exp
		chosen.NextRetryAt = nil

		raw, err := json.Marshal(chosen)
		if err != nil {
			return err
		}
		return b.Put([]byte(chosen.FileID), raw)
	})
	if err != nil {
		return nil, err
	}
	return chosen, nil
}

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
	var newExp time.Time
	now := time.Now().UTC()
	err := s.db.Update(func(tx *bolt.Tx) error {
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
		rec.LeaseExpiresAt = &newExp
		out, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put([]byte(fileID), out)
	})
	return newExp, err
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
	const maxLRU = 10000
	for len(s.deletedList) > maxLRU {
		oldest := s.deletedList[0]
		s.deletedList = s.deletedList[1:]
		delete(s.deleted, oldest)
	}
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
	return &rec, nil
}

func (s *Store) ReapExpiredLeases(now time.Time) (int, error) {
	reaped := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFiles)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec FileRecord
			if err := json.Unmarshal(v, &rec); err != nil {
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
				if err := b.Put(k, out); err != nil {
					return err
				}
				reaped++
			}
		}
		return nil
	})
	return reaped, err
}

func (s *Store) ListLive(projectFilter string) ([]protocol.LiveFileItem, error) {
	items := make([]protocol.LiveFileItem, 0)
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketFiles).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec FileRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				continue
			}
			if projectFilter != "" && rec.ProjectID != projectFilter {
				continue
			}
			items = append(items, protocol.LiveFileItem{
				FileID:         rec.FileID,
				ProjectID:      rec.ProjectID,
				Filename:       rec.Filename,
				Size:           rec.Size,
				SHA256:         rec.SHA256,
				Status:         rec.Status,
				ClaimedBy:      rec.ClaimedBy,
				LeaseExpiresAt: rec.LeaseExpiresAt,
				UploadedAt:     rec.UploadedAt,
				RetryCount:     rec.RetryCount,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].UploadedAt.Before(items[j].UploadedAt)
	})
	return items, nil
}

func (s *Store) ComputeAvailability() ([]protocol.ProjectAvailability, error) {
	byProj := make(map[string]*protocol.ProjectAvailability)
	now := time.Now().UTC()
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketFiles).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec FileRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				continue
			}
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
		return nil
	})
	if err != nil {
		return nil, err
	}
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
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketFiles).Delete([]byte(fileID))
	})
}

func (s *Store) AllFileIDs() (map[string]struct{}, error) {
	ids := make(map[string]struct{})
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketFiles).Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			ids[string(k)] = struct{}{}
		}
		return nil
	})
	return ids, err
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
