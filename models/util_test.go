package models

import (
	"testing"
)

func TestSnowflakeUUID4RoundTrip(t *testing.T) {
	// Use a few sample snowflake IDs (including large values) to validate round-trip
	cases := []uint64{
		1,
		42,
		1234567890,
		0x7fffffffffffffff, // max int64
	}
	for _, id := range cases {
		u := SnowflakeToUUID4(id)
		back, err := UUID4ToSnowflake(u)
		if err != nil {
			t.Fatalf("decode failed for %d: %v", id, err)
		}
		if back != id {
			t.Fatalf("round-trip mismatch: in=%d out=%d uuid=%s", id, back, u)
		}
	}
}

func TestUUID4ToSnowflake_Invalid(t *testing.T) {
	// invalid length
	if _, err := UUID4ToSnowflake("1234"); err == nil {
		t.Fatalf("expected error for short uuid")
	}
	// invalid hex
	if _, err := UUID4ToSnowflake("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"); err == nil {
		t.Fatalf("expected error for invalid hex")
	}
}
