package models

import (
	"encoding/json"
	"testing"
)

// Strict RFC compliance: Token JSON should not include non-standard fields.
func TestTokenMarshalJSON_NoNonStandardFields(t *testing.T) {
	// Default zero-value token
	tok := &Token{}
	b, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if _, ok := out["access_exp_at"]; ok {
		t.Fatalf("unexpected access_exp_at in JSON: %v", out["access_exp_at"])
	}
	if _, ok := out["refresh_exp_at"]; ok {
		t.Fatalf("unexpected refresh_exp_at in JSON: %v", out["refresh_exp_at"])
	}
}
