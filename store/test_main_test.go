package store

import "testing"

// Deprecated: TestMain is intentionally disabled. Migrations will be run by the migrate CLI before tests.
func TestMain(m *testing.M) {
	m.Run()
}
