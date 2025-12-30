package models

import (
	"sync"
	"time"
)

// Snowflake generates unique 64-bit IDs composed of timestamp and node/sequence bits.
// Layout: 1 bit unused + 41 bits timestamp(ms since custom epoch) + 10 bits node + 12 bits sequence.
// This is a minimal implementation suitable for single-process tests; node can be configured.
type Snowflake struct {
	epoch  int64
	nodeID int64 // 10 bits
	lastMs int64
	seq    int64 // 12 bits
	mu     sync.Mutex
}

func NewSnowflake(nodeID int64) *Snowflake {
	return &Snowflake{epoch: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli(), nodeID: nodeID & 0x3FF}
}

func (s *Snowflake) Next() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixMilli()
	if now == s.lastMs {
		s.seq = (s.seq + 1) & 0xFFF
		if s.seq == 0 { // sequence rollover, wait next ms
			for now <= s.lastMs {
				now = time.Now().UnixMilli()
			}
		}
	} else {
		s.seq = 0
	}
	s.lastMs = now
	ts := (now - s.epoch) & ((1 << 41) - 1)
	return (ts << (10 + 12)) | (s.nodeID << 12) | s.seq
}

// Client client model
type Client struct {
	ID     string
	Secret string
	Domain string
	Public bool
	UserID string
}

// GetID client id
func (c *Client) GetID() string {
	return c.ID
}

// GetSecret client secret
func (c *Client) GetSecret() string {
	return c.Secret
}

// GetDomain client domain
func (c *Client) GetDomain() string {
	return c.Domain
}

// IsPublic public
func (c *Client) IsPublic() bool {
	return c.Public
}

// GetUserID user id
func (c *Client) GetUserID() string {
	return c.UserID
}
