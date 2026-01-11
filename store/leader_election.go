package store

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	valkey "github.com/valkey-io/valkey-go"
)

const (
	// Default leader election settings
	defaultLeaderLockTTL     = 30 * time.Second
	defaultLeaderRenewPeriod = 10 * time.Second
	leaderLockKey            = "leader:revocation"
)

// LeaderElection provides Redis-based leader election for distributed tasks.
// Only one pod in the cluster will be elected as leader at a time.
type LeaderElection struct {
	client   valkey.Client
	prefix   string
	identity string

	lockTTL     time.Duration
	renewPeriod time.Duration

	mu       sync.RWMutex
	isLeader bool
	stopChan chan struct{}
	stopped  bool

	// Callbacks
	onStartedLeading func(ctx context.Context)
	onStoppedLeading func()
}

// LeaderElectionConfig holds configuration for leader election.
type LeaderElectionConfig struct {
	// LockTTL is how long the leader lock is valid
	LockTTL time.Duration
	// RenewPeriod is how often to renew the lock (should be less than LockTTL)
	RenewPeriod time.Duration
	// Identity is a unique identifier for this instance (defaults to hostname + uuid)
	Identity string
	// OnStartedLeading is called when this instance becomes the leader
	OnStartedLeading func(ctx context.Context)
	// OnStoppedLeading is called when this instance stops being the leader
	OnStoppedLeading func()
}

// DefaultLeaderElectionConfig returns the default configuration.
func DefaultLeaderElectionConfig() LeaderElectionConfig {
	hostname, _ := os.Hostname()
	return LeaderElectionConfig{
		LockTTL:     defaultLeaderLockTTL,
		RenewPeriod: defaultLeaderRenewPeriod,
		Identity:    fmt.Sprintf("%s-%s", hostname, uuid.New().String()[:8]),
	}
}

// NewLeaderElection creates a new leader election instance.
func NewLeaderElection(client valkey.Client, prefix string, config LeaderElectionConfig) *LeaderElection {
	if config.LockTTL == 0 {
		config.LockTTL = defaultLeaderLockTTL
	}
	if config.RenewPeriod == 0 {
		config.RenewPeriod = defaultLeaderRenewPeriod
	}
	if config.Identity == "" {
		hostname, _ := os.Hostname()
		config.Identity = fmt.Sprintf("%s-%s", hostname, uuid.New().String()[:8])
	}

	return &LeaderElection{
		client:           client,
		prefix:           prefix,
		identity:         config.Identity,
		lockTTL:          config.LockTTL,
		renewPeriod:      config.RenewPeriod,
		onStartedLeading: config.OnStartedLeading,
		onStoppedLeading: config.OnStoppedLeading,
		stopChan:         make(chan struct{}),
	}
}

// key returns the full Redis key with prefix.
func (le *LeaderElection) key() string {
	return le.prefix + leaderLockKey
}

// IsLeader returns whether this instance is currently the leader.
func (le *LeaderElection) IsLeader() bool {
	le.mu.RLock()
	defer le.mu.RUnlock()
	return le.isLeader
}

// GetIdentity returns the identity of this instance.
func (le *LeaderElection) GetIdentity() string {
	return le.identity
}

// GetCurrentLeader returns the identity of the current leader.
func (le *LeaderElection) GetCurrentLeader(ctx context.Context) (string, error) {
	res := le.client.Do(ctx, le.client.B().Get().Key(le.key()).Build())
	if res.Error() != nil {
		if valkey.IsValkeyNil(res.Error()) {
			return "", nil // No leader
		}
		return "", res.Error()
	}
	return res.ToString()
}

// tryAcquireLock attempts to acquire the leader lock.
func (le *LeaderElection) tryAcquireLock(ctx context.Context) (bool, error) {
	// Use SET NX EX for atomic acquire with TTL
	res := le.client.Do(ctx,
		le.client.B().Set().Key(le.key()).Value(le.identity).Nx().Ex(le.lockTTL).Build())

	if res.Error() != nil {
		if valkey.IsValkeyNil(res.Error()) {
			return false, nil // Lock already held by someone else
		}
		return false, res.Error()
	}

	// Check if we got the lock
	result, err := res.ToString()
	if err != nil {
		// SET NX returns nil if key already exists
		return false, nil
	}

	return result == "OK", nil
}

// renewLock renews the leader lock if we're still the leader.
func (le *LeaderElection) renewLock(ctx context.Context) (bool, error) {
	// Use Lua script for atomic check-and-renew
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("expire", KEYS[1], ARGV[2])
		else
			return 0
		end
	`

	ttlSecs := int64(le.lockTTL.Seconds())
	res := le.client.Do(ctx,
		le.client.B().Eval().Script(script).Numkeys(1).Key(le.key()).Arg(le.identity).Arg(fmt.Sprintf("%d", ttlSecs)).Build())

	if res.Error() != nil {
		return false, res.Error()
	}

	renewed, err := res.ToInt64()
	if err != nil {
		return false, err
	}

	return renewed == 1, nil
}

// releaseLock releases the leader lock if we hold it.
func (le *LeaderElection) releaseLock(ctx context.Context) error {
	// Use Lua script for atomic check-and-delete
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`

	res := le.client.Do(ctx,
		le.client.B().Eval().Script(script).Numkeys(1).Key(le.key()).Arg(le.identity).Build())

	return res.Error()
}

// Start begins the leader election process.
func (le *LeaderElection) Start(ctx context.Context) {
	go le.run(ctx)
}

// run is the main leader election loop.
func (le *LeaderElection) run(ctx context.Context) {
	ticker := time.NewTicker(le.renewPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-le.stopChan:
			le.handleLostLeadership(ctx)
			return
		case <-ctx.Done():
			le.handleLostLeadership(ctx)
			return
		case <-ticker.C:
			le.checkLeadership(ctx)
		}
	}
}

// checkLeadership checks and maintains leadership status.
func (le *LeaderElection) checkLeadership(ctx context.Context) {
	le.mu.Lock()
	wasLeader := le.isLeader
	le.mu.Unlock()

	if wasLeader {
		// Try to renew the lock
		renewed, err := le.renewLock(ctx)
		if err != nil {
			log.Printf("leader-election: failed to renew lock: %v", err)
			le.handleLostLeadership(ctx)
			return
		}

		if !renewed {
			// Lost leadership
			log.Printf("leader-election: lost leadership (identity=%s)", le.identity)
			le.handleLostLeadership(ctx)
		}
	} else {
		// Try to acquire the lock
		acquired, err := le.tryAcquireLock(ctx)
		if err != nil {
			log.Printf("leader-election: failed to acquire lock: %v", err)
			return
		}

		if acquired {
			// Became leader
			log.Printf("leader-election: became leader (identity=%s)", le.identity)
			le.handleBecameLeader(ctx)
		}
	}
}

// handleBecameLeader is called when this instance becomes the leader.
func (le *LeaderElection) handleBecameLeader(ctx context.Context) {
	le.mu.Lock()
	le.isLeader = true
	le.mu.Unlock()

	if le.onStartedLeading != nil {
		go le.onStartedLeading(ctx)
	}
}

// handleLostLeadership is called when this instance loses leadership.
func (le *LeaderElection) handleLostLeadership(ctx context.Context) {
	le.mu.Lock()
	wasLeader := le.isLeader
	le.isLeader = false
	le.mu.Unlock()

	if wasLeader {
		// Release lock
		_ = le.releaseLock(ctx)

		if le.onStoppedLeading != nil {
			le.onStoppedLeading()
		}
	}
}

// Stop stops the leader election process.
func (le *LeaderElection) Stop() {
	le.mu.Lock()
	if le.stopped {
		le.mu.Unlock()
		return
	}
	le.stopped = true
	le.mu.Unlock()

	close(le.stopChan)
}

// RunWithLeaderElection runs a function only if this instance is the leader.
// Returns true if the function was executed.
func (le *LeaderElection) RunWithLeaderElection(ctx context.Context, fn func(ctx context.Context) error) (bool, error) {
	if !le.IsLeader() {
		return false, nil
	}

	err := fn(ctx)
	return true, err
}
