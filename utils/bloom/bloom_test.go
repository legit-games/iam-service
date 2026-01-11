package bloom

import (
	"encoding/json"
	"testing"
)

func TestBloomFilter_PutAndTest(t *testing.T) {
	f := New()

	// Add items
	items := []string{"token1", "token2", "token3"}
	for _, item := range items {
		f.Put([]byte(item))
	}

	// Test that added items are found
	for _, item := range items {
		if !f.Test([]byte(item)) {
			t.Errorf("item %q should be in the filter", item)
		}
	}

	// Test that non-added items are likely not found
	// Note: Bloom filters may have false positives, but should not have false negatives
	notAdded := "token_not_added"
	// We can't assert this is false due to possible false positives
	// but we verify the function doesn't panic
	_ = f.Test([]byte(notAdded))
}

func TestBloomFilter_EmptyFilter(t *testing.T) {
	f := New()

	// Empty filter should return false for any item
	if f.Test([]byte("anything")) {
		t.Error("empty filter should return false for any item")
	}
}

func TestBloomFilter_JSON(t *testing.T) {
	f := New()
	f.Put([]byte("token1"))
	f.Put([]byte("token2"))

	// Marshal to JSON
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Unmarshal to new filter
	var f2 Filter
	if err := json.Unmarshal(data, &f2); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Verify same parameters
	if f.M() != f2.M() || f.K() != f2.K() {
		t.Error("parameters should match after JSON round-trip")
	}

	// Verify items still found
	if !f2.Test([]byte("token1")) || !f2.Test([]byte("token2")) {
		t.Error("items should still be found after JSON round-trip")
	}
}

func TestBloomFilter_Merge(t *testing.T) {
	f1 := NewWithParams(1000, 5)
	f1.Put([]byte("token1"))
	f1.Put([]byte("token2"))

	f2 := NewWithParams(1000, 5)
	f2.Put([]byte("token3"))
	f2.Put([]byte("token4"))

	merged, err := Merge(f1, f2)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}

	// All items should be in merged filter
	items := []string{"token1", "token2", "token3", "token4"}
	for _, item := range items {
		if !merged.Test([]byte(item)) {
			t.Errorf("item %q should be in merged filter", item)
		}
	}
}

func TestBloomFilter_MergeIncompatible(t *testing.T) {
	f1 := NewWithParams(1000, 5)
	f2 := NewWithParams(2000, 5) // Different m

	_, err := Merge(f1, f2)
	if err != ErrIncompatibleFilters {
		t.Error("should return ErrIncompatibleFilters for incompatible filters")
	}
}

func TestBloomFilter_OptimalParams(t *testing.T) {
	// 1000 items with 1% false positive rate
	m, k := OptimalParams(1000, 0.01)

	if m == 0 || k == 0 {
		t.Error("optimal params should return non-zero values")
	}

	// Verify filter works with optimal params
	f := NewWithParams(m, k)
	for i := 0; i < 1000; i++ {
		f.Put([]byte("item" + string(rune(i))))
	}
}

func TestFilterJSON(t *testing.T) {
	f := NewWithParams(100, 3)
	f.Put([]byte("test"))

	fj := f.ToJSON()
	if fj.M != 100 || fj.K != 3 {
		t.Error("ToJSON should preserve parameters")
	}

	f2 := NewFromJSON(fj)
	if !f2.Test([]byte("test")) {
		t.Error("NewFromJSON should create working filter")
	}
}

func TestMurmurHash3(t *testing.T) {
	// Test that hash function produces deterministic results
	data := []byte("test data")
	h1a, h2a := murmurHash3_128(data, 0)
	h1b, h2b := murmurHash3_128(data, 0)

	if h1a != h1b || h2a != h2b {
		t.Error("hash function should be deterministic")
	}

	// Different data should produce different hashes
	data2 := []byte("different data")
	h1c, h2c := murmurHash3_128(data2, 0)

	if h1a == h1c && h2a == h2c {
		t.Error("different data should produce different hashes")
	}
}

func BenchmarkBloomFilter_Put(b *testing.B) {
	f := New()
	data := []byte("benchmark_token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Put(data)
	}
}

func BenchmarkBloomFilter_Test(b *testing.B) {
	f := New()
	f.Put([]byte("benchmark_token"))
	data := []byte("benchmark_token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.Test(data)
	}
}
