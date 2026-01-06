package platforms

import (
	"testing"
)

func TestAccountGroup_NewAccountGroup(t *testing.T) {
	ag := NewAccountGroup()

	// Verify PSN group exists
	psnMembers := ag.GetGroupMembers("psn")
	if len(psnMembers) != 3 {
		t.Errorf("expected 3 PSN members, got %d", len(psnMembers))
	}

	// Verify Xbox Live group exists
	liveMembers := ag.GetGroupMembers("live")
	if len(liveMembers) != 2 {
		t.Errorf("expected 2 Xbox Live members, got %d", len(liveMembers))
	}
}

func TestAccountGroup_GetGroupMembers(t *testing.T) {
	ag := NewAccountGroup()

	tests := []struct {
		name     string
		expected []string
	}{
		{"psn", []string{"ps4", "ps5", "ps4web"}},
		{"live", []string{"xbl", "xblweb"}},
		{"unknown", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			members := ag.GetGroupMembers(tc.name)
			if tc.expected == nil {
				if members != nil {
					t.Errorf("expected nil for group %s, got %v", tc.name, members)
				}
				return
			}
			if len(members) != len(tc.expected) {
				t.Errorf("expected %d members for group %s, got %d", len(tc.expected), tc.name, len(members))
			}
		})
	}
}

func TestAccountGroup_GetSiblingMembers(t *testing.T) {
	ag := NewAccountGroup()

	tests := []struct {
		member   string
		expected []string
	}{
		{"ps4", []string{"ps4", "ps5", "ps4web"}},
		{"ps5", []string{"ps4", "ps5", "ps4web"}},
		{"ps4web", []string{"ps4", "ps5", "ps4web"}},
		{"xbl", []string{"xbl", "xblweb"}},
		{"xblweb", []string{"xbl", "xblweb"}},
		{"steam", nil},
		{"epicgames", nil},
	}

	for _, tc := range tests {
		t.Run(tc.member, func(t *testing.T) {
			siblings := ag.GetSiblingMembers(tc.member)
			if tc.expected == nil {
				if siblings != nil {
					t.Errorf("expected nil siblings for %s, got %v", tc.member, siblings)
				}
				return
			}
			if len(siblings) != len(tc.expected) {
				t.Errorf("expected %d siblings for %s, got %d", len(tc.expected), tc.member, len(siblings))
			}
		})
	}
}

func TestAccountGroup_GetGroupName(t *testing.T) {
	ag := NewAccountGroup()

	tests := []struct {
		member   string
		expected string
	}{
		{"ps4", "psn"},
		{"ps5", "psn"},
		{"ps4web", "psn"},
		{"xbl", "live"},
		{"xblweb", "live"},
		{"steam", ""},
		{"epicgames", ""},
	}

	for _, tc := range tests {
		t.Run(tc.member, func(t *testing.T) {
			groupName := ag.GetGroupName(tc.member)
			if groupName != tc.expected {
				t.Errorf("expected group name %q for %s, got %q", tc.expected, tc.member, groupName)
			}
		})
	}
}

func TestAccountGroup_GetPlatformName(t *testing.T) {
	ag := NewAccountGroup()

	tests := []struct {
		member   string
		expected string
	}{
		{"ps4", "psn"},
		{"ps5", "psn"},
		{"xbl", "live"},
		{"steam", "steam"},       // Non-member returns itself
		{"epicgames", "epicgames"}, // Non-member returns itself
	}

	for _, tc := range tests {
		t.Run(tc.member, func(t *testing.T) {
			platformName := ag.GetPlatformName(tc.member)
			if platformName != tc.expected {
				t.Errorf("expected platform name %q for %s, got %q", tc.expected, tc.member, platformName)
			}
		})
	}
}

func TestAccountGroup_CheckFamilyMember(t *testing.T) {
	ag := NewAccountGroup()

	tests := []struct {
		platform1 string
		platform2 string
		expected  bool
	}{
		{"ps4", "ps5", true},
		{"ps4", "ps4web", true},
		{"ps5", "ps4web", true},
		{"xbl", "xblweb", true},
		{"ps4", "xbl", false},
		{"ps4", "steam", false},
		{"steam", "epicgames", false},
	}

	for _, tc := range tests {
		t.Run(tc.platform1+"_"+tc.platform2, func(t *testing.T) {
			result := ag.CheckFamilyMember(tc.platform1, tc.platform2)
			if result != tc.expected {
				t.Errorf("expected CheckFamilyMember(%s, %s) = %v, got %v",
					tc.platform1, tc.platform2, tc.expected, result)
			}
		})
	}
}

func TestAccountGroup_IsGroupName(t *testing.T) {
	ag := NewAccountGroup()

	tests := []struct {
		name     string
		expected bool
	}{
		{"psn", true},
		{"live", true},
		{"ps4", false},
		{"steam", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ag.IsGroupName(tc.name)
			if result != tc.expected {
				t.Errorf("expected IsGroupName(%s) = %v, got %v", tc.name, tc.expected, result)
			}
		})
	}
}

func TestAccountGroup_IsMember(t *testing.T) {
	ag := NewAccountGroup()

	tests := []struct {
		name     string
		expected bool
	}{
		{"ps4", true},
		{"ps5", true},
		{"xbl", true},
		{"psn", false},  // Group name, not a member
		{"live", false}, // Group name, not a member
		{"steam", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ag.IsMember(tc.name)
			if result != tc.expected {
				t.Errorf("expected IsMember(%s) = %v, got %v", tc.name, tc.expected, result)
			}
		})
	}
}

func TestAccountGroup_AddGroup(t *testing.T) {
	ag := NewAccountGroup()

	// Add a custom group
	ag.AddGroup("nintendo", []string{"switch", "3ds"})

	// Verify the new group
	members := ag.GetGroupMembers("nintendo")
	if len(members) != 2 {
		t.Errorf("expected 2 Nintendo members, got %d", len(members))
	}

	// Verify sibling lookup works
	siblings := ag.GetSiblingMembers("switch")
	if len(siblings) != 2 {
		t.Errorf("expected 2 siblings for switch, got %d", len(siblings))
	}

	// Verify group name lookup
	groupName := ag.GetGroupName("3ds")
	if groupName != "nintendo" {
		t.Errorf("expected group name 'nintendo' for 3ds, got %q", groupName)
	}
}
