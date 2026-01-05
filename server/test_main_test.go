package server

import (
	"testing"
)

// Deprecated: TestMain is intentionally disabled. Migrations will be run by the migrate CLI before tests.
func TestMain(m *testing.M) {
	// No-op: run tests directly
	m.Run()
}
