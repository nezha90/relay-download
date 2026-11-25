package agentb

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketActiveDownloads = []byte("active_downloads")
	bucketPendingAcks     = []byte("pending_acks")
)

type ActiveDownload struct {
	FileID         string    `json:"file_id"`
	ProjectID      string    `json:"project_id"`
	ANodeID        string    `json:"a_node_id"`
	PublicAddr     string    `json:"public_addr"`
	Filename       string    `json:"filename"`
	Size           int64     `json:"size"`
	SHA256         string    `json:"sha256"`
	LeaseID        string    `json:"lease_id"`
	LeaseToken     string    `json:"lease_token"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	LeaseTTLSec    int       `json:"lease_ttl_sec"`
	ConflictPolicy string    `json:"conflict_policy"`
	DestDir        string    `json:"dest_dir"`
	PartPath       string    `json:"part_path"`
	StartedAt      time.Time `json:"started_at"`
}

type PendingAck struct {
	FileID     string    `json:"file_id"`
	ANodeID    string    `json:"a_node_id"`
	PublicAddr string    `json:"public_addr"`
	LeaseID    string    `json:"lease_id"`
	LeaseToken string    `json:"lease_token"`
	SHA256     string    `json:"sha256"`
	DurationMs int64     `json:"duration_ms"`
	DestDir    string    `json:"dest_dir,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type Store struct {
	db *bolt.DB
}

func OpenStore(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, err
	}
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open agent-b boltdb: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketActiveDownloads); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketPendingAcks)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) PutActive(dl ActiveDownload) error {
	raw, err := json.Marshal(dl)
	if err != nil {
		return err
	}
	return s.db.Batch(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketActiveDownloads).Put([]byte(dl.FileID), raw)
	})
}

func (s *Store) PutActiveBatch(dls []ActiveDownload) error {
	if len(dls) == 0 {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketActiveDownloads)
		for _, dl := range dls {
			raw, err := json.Marshal(dl)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(dl.FileID), raw); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) DeleteActive(fileID string) error {
	return s.db.Batch(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketActiveDownloads).Delete([]byte(fileID))
	})
}

func (s *Store) ListActive() ([]ActiveDownload, error) {
	var list []ActiveDownload
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketActiveDownloads).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var dl ActiveDownload
			if err := json.Unmarshal(v, &dl); err == nil {
				list = append(list, dl)
			}
		}
		return nil
	})
	return list, err
}

func (s *Store) PutPendingAck(ack PendingAck) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(ack)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketPendingAcks).Put([]byte(ack.FileID), raw)
	})
}

// CompleteActiveAndQueueAck atomically removes an active download record and persists its pending ACK.
// Uses db.Batch so concurrent completions coalesce into a single BoltDB fsync while preserving ACID durability.
func (s *Store) CompleteActiveAndQueueAck(fileID string, ack PendingAck) error {
	raw, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	return s.db.Batch(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketActiveDownloads).Delete([]byte(fileID)); err != nil {
			return err
		}
		return tx.Bucket(bucketPendingAcks).Put([]byte(ack.FileID), raw)
	})
}

func (s *Store) DeletePendingAck(fileID string) error {
	return s.db.Batch(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPendingAcks).Delete([]byte(fileID))
	})
}

func (s *Store) DeletePendingAcks(fileIDs []string) error {
	if len(fileIDs) == 0 {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPendingAcks)
		for _, id := range fileIDs {
			if err := b.Delete([]byte(id)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) PendingAckCount() int {
	var n int
	_ = s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(bucketPendingAcks).Stats().KeyN
		return nil
	})
	return n
}

func (s *Store) ListPendingAcks() ([]PendingAck, error) {
	var list []PendingAck
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketPendingAcks).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var ack PendingAck
			if err := json.Unmarshal(v, &ack); err == nil {
				list = append(list, ack)
			}
		}
		return nil
	})
	return list, err
}
