// Package store provides durable event, incident, and file-cursor state.
package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/policy"
	bolt "go.etcd.io/bbolt"
)

var (
	eventsBucket    = []byte("events")
	incidentsBucket = []byte("incidents")
	activeBucket    = []byte("active_incidents")
	cursorsBucket   = []byte("cursors")
	runtimeBucket   = []byte("runtime")
	runtimeKey      = []byte("state")
)

type IncidentStatus string

const (
	IncidentAudit     IncidentStatus = "audit"
	IncidentPending   IncidentStatus = "pending"
	IncidentContained IncidentStatus = "contained"
	IncidentFailed    IncidentStatus = "failed"
	IncidentReleased  IncidentStatus = "released"
)

type Incident struct {
	ID        string          `json:"id"`
	Mailbox   string          `json:"mailbox"`
	Status    IncidentStatus  `json:"status"`
	Decision  policy.Decision `json:"decision"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	ExpiresAt time.Time       `json:"expires_at"`
}

type Cursor struct {
	Path       string    `json:"path"`
	Offset     int64     `json:"offset"`
	PrefixHash string    `json:"prefix_hash"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// RuntimeState lets a new process distinguish a clean service restart from an
// abrupt termination that could not send an alert before dying.
type RuntimeState struct {
	StartedAt     time.Time `json:"started_at"`
	HeartbeatAt   time.Time `json:"heartbeat_at"`
	CleanShutdown bool      `json:"clean_shutdown"`
}

// Bolt wraps bbolt with a small schema owned by the agent.
type Bolt struct {
	db *bolt.DB
}

func Open(path string, readOnly bool) (*Bolt, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{
		Timeout:  time.Second,
		ReadOnly: readOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("open state database: %w", err)
	}
	store := &Bolt{db: db}
	if !readOnly {
		if err := db.Update(func(tx *bolt.Tx) error {
			for _, name := range [][]byte{eventsBucket, incidentsBucket, activeBucket, cursorsBucket, runtimeBucket} {
				if _, err := tx.CreateBucketIfNotExists(name); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			db.Close()
			return nil, fmt.Errorf("initialize state database: %w", err)
		}
	}
	return store, nil
}

func (s *Bolt) BeginRun(at time.Time) (RuntimeState, bool, error) {
	var previous RuntimeState
	found := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(runtimeBucket)
		if value := bucket.Get(runtimeKey); value != nil {
			if err := json.Unmarshal(value, &previous); err != nil {
				return fmt.Errorf("decode runtime state: %w", err)
			}
			found = true
		}
		current := RuntimeState{StartedAt: at, HeartbeatAt: at, CleanShutdown: false}
		encoded, err := json.Marshal(current)
		if err != nil {
			return err
		}
		return bucket.Put(runtimeKey, encoded)
	})
	return previous, found, err
}

func (s *Bolt) Heartbeat(at time.Time) error {
	return s.updateRuntime(at, false)
}

func (s *Bolt) EndRun(at time.Time) error {
	return s.updateRuntime(at, true)
}

func (s *Bolt) updateRuntime(at time.Time, clean bool) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(runtimeBucket)
		value := bucket.Get(runtimeKey)
		if value == nil {
			return fmt.Errorf("runtime state is not initialized")
		}
		var current RuntimeState
		if err := json.Unmarshal(value, &current); err != nil {
			return fmt.Errorf("decode runtime state: %w", err)
		}
		current.HeartbeatAt = at
		current.CleanShutdown = clean
		encoded, err := json.Marshal(current)
		if err != nil {
			return err
		}
		return bucket.Put(runtimeKey, encoded)
	})
}

func (s *Bolt) Close() error {
	return s.db.Close()
}

func (s *Bolt) AppendEvent(item event.Event) error {
	if err := item.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(eventsBucket)
		sequence, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		return bucket.Put(eventKey(item.Time, sequence), encoded)
	})
}

func (s *Bolt) RecentEvents(since time.Time) ([]event.Event, error) {
	result := make([]event.Event, 0)
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(eventsBucket)
		if bucket == nil {
			return nil
		}
		cursor := bucket.Cursor()
		for key, value := cursor.Seek(eventKey(since, 0)); key != nil; key, value = cursor.Next() {
			var item event.Event
			if err := json.Unmarshal(value, &item); err != nil {
				return fmt.Errorf("decode event: %w", err)
			}
			result = append(result, item)
		}
		return nil
	})
	return result, err
}

func (s *Bolt) PruneEvents(before time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(eventsBucket)
		cursor := bucket.Cursor()
		limit := eventKey(before, 0)
		for key, _ := cursor.First(); key != nil && bytes.Compare(key, limit) < 0; key, _ = cursor.Next() {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
		return nil
	})
}

// CreateIncident atomically deduplicates incidents by mailbox and cooldown.
func (s *Bolt) CreateIncident(candidate Incident) (Incident, bool, error) {
	if candidate.ID == "" || candidate.Mailbox == "" || candidate.CreatedAt.IsZero() {
		return Incident{}, false, fmt.Errorf("incident identity is incomplete")
	}
	encoded, err := json.Marshal(candidate)
	if err != nil {
		return Incident{}, false, err
	}
	var existing Incident
	created := false
	err = s.db.Update(func(tx *bolt.Tx) error {
		incidents := tx.Bucket(incidentsBucket)
		active := tx.Bucket(activeBucket)
		if id := active.Get([]byte(candidate.Mailbox)); id != nil {
			value := incidents.Get(id)
			if value != nil {
				if err := json.Unmarshal(value, &existing); err != nil {
					return err
				}
				if existing.Status != IncidentReleased &&
					candidate.CreatedAt.Before(existing.ExpiresAt) &&
					severityRank(existing.Decision.Severity) >= severityRank(candidate.Decision.Severity) {
					return nil
				}
			}
		}
		if err := incidents.Put([]byte(candidate.ID), encoded); err != nil {
			return err
		}
		if err := active.Put([]byte(candidate.Mailbox), []byte(candidate.ID)); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return Incident{}, false, err
	}
	if !created {
		return existing, false, nil
	}
	return candidate, true, nil
}

func severityRank(value policy.Severity) int {
	switch value {
	case policy.Contain:
		return 2
	case policy.Warning:
		return 1
	default:
		return 0
	}
}

func (s *Bolt) UpdateIncidentStatus(id string, status IncidentStatus, at time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		incidents := tx.Bucket(incidentsBucket)
		value := incidents.Get([]byte(id))
		if value == nil {
			return fmt.Errorf("incident %q not found", id)
		}
		var incident Incident
		if err := json.Unmarshal(value, &incident); err != nil {
			return err
		}
		incident.Status = status
		incident.UpdatedAt = at
		encoded, err := json.Marshal(incident)
		if err != nil {
			return err
		}
		if err := incidents.Put([]byte(id), encoded); err != nil {
			return err
		}
		if status == IncidentReleased {
			active := tx.Bucket(activeBucket)
			if string(active.Get([]byte(incident.Mailbox))) == id {
				return active.Delete([]byte(incident.Mailbox))
			}
		}
		return nil
	})
}

func (s *Bolt) Incidents() ([]Incident, error) {
	result := make([]Incident, 0)
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(incidentsBucket)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(_, value []byte) error {
			var incident Incident
			if err := json.Unmarshal(value, &incident); err != nil {
				return err
			}
			result = append(result, incident)
			return nil
		})
	})
	return result, err
}

func (s *Bolt) GetCursor(path string) (Cursor, bool, error) {
	var cursor Cursor
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(cursorsBucket)
		if bucket == nil {
			return nil
		}
		value := bucket.Get([]byte(path))
		if value == nil {
			return nil
		}
		return json.Unmarshal(value, &cursor)
	})
	if err != nil {
		return Cursor{}, false, err
	}
	return cursor, cursor.Path != "", nil
}

func (s *Bolt) PutCursor(cursor Cursor) error {
	if cursor.Path == "" || cursor.Offset < 0 {
		return fmt.Errorf("cursor is invalid")
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(cursorsBucket).Put([]byte(cursor.Path), encoded)
	})
}

func eventKey(when time.Time, sequence uint64) []byte {
	key := make([]byte, 16)
	binary.BigEndian.PutUint64(key[:8], uint64(when.UnixNano()))
	binary.BigEndian.PutUint64(key[8:], sequence)
	return key
}

// IsNotFound allows callers to distinguish absent state in future schemas.
func IsNotFound(err error) bool {
	return errors.Is(err, bolt.ErrBucketNotFound)
}
