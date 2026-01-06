package platforms

// AccountGroup manages platform families where multiple platform IDs share the same account.
// For example, PS4, PS5, and PS4Web all use the same PSN account.
type AccountGroup struct {
	groups []group
}

type group struct {
	Name    string   // Group identifier (e.g., "psn")
	Members []string // Platform IDs in this group (e.g., ["ps4", "ps5", "ps4web"])
}

// NewAccountGroup creates a new AccountGroup with default platform groups.
func NewAccountGroup() *AccountGroup {
	ag := &AccountGroup{}
	// PlayStation Network group
	ag.AddGroup("psn", []string{"ps4", "ps5", "ps4web"})
	// Xbox Live group
	ag.AddGroup("live", []string{"xbl", "xblweb"})
	return ag
}

// AddGroup registers a new platform group.
func (ag *AccountGroup) AddGroup(name string, members []string) {
	ag.groups = append(ag.groups, group{Name: name, Members: members})
}

// GetPlatformName returns group name if member belongs to a group, otherwise returns the input itself.
func (ag *AccountGroup) GetPlatformName(member string) string {
	for _, g := range ag.groups {
		for _, m := range g.Members {
			if m == member {
				return g.Name
			}
		}
	}
	return member
}

// GetGroupName returns the group name for a platform member.
// Returns empty string if the member doesn't belong to any group.
func (ag *AccountGroup) GetGroupName(member string) string {
	for _, g := range ag.groups {
		for _, m := range g.Members {
			if m == member {
				return g.Name
			}
		}
	}
	return ""
}

// GetGroupMembers returns all members of a group by group name.
// Returns nil if no group with that name exists.
func (ag *AccountGroup) GetGroupMembers(name string) []string {
	for _, g := range ag.groups {
		if g.Name == name {
			return g.Members
		}
	}
	return nil
}

// GetSiblingMembers returns all siblings of a platform member (including itself).
// Returns nil if the member doesn't belong to any group.
func (ag *AccountGroup) GetSiblingMembers(member string) []string {
	for _, g := range ag.groups {
		for _, m := range g.Members {
			if m == member {
				return g.Members
			}
		}
	}
	return nil
}

// CheckFamilyMember checks if two platforms belong to the same group.
func (ag *AccountGroup) CheckFamilyMember(platform1, platform2 string) bool {
	group1 := ag.GetGroupName(platform1)
	group2 := ag.GetGroupName(platform2)
	if group1 == "" || group2 == "" {
		return false
	}
	return group1 == group2
}

// IsGroupName checks if the given name is a group name (not a member).
func (ag *AccountGroup) IsGroupName(name string) bool {
	for _, g := range ag.groups {
		if g.Name == name {
			return true
		}
	}
	return false
}

// IsMember checks if the given name is a member of any group.
func (ag *AccountGroup) IsMember(name string) bool {
	for _, g := range ag.groups {
		for _, m := range g.Members {
			if m == name {
				return true
			}
		}
	}
	return false
}
