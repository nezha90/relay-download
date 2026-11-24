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
	return s.db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(dl)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketActiveDownloads).Put([]byte(dl.FileID), raw)
	})
}

func (s *Store) DeleteActive(fileID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
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

func (s *Store) DeletePendingAck(fileID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPendingAcks).Delete([]byte(fileID))
	})
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
