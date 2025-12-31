package permission

import "strings"

// Action represents a permission action as a bitmask value.
// Matches Java PermissionAction values exactly.
// CREATE=1, READ=2, UPDATE=4, DELETE=8; combinations are bitwise ORs; ALL=15.
type Action int

const (
	CREATE Action = 1
	READ   Action = 2
	UPDATE Action = 4
	DELETE Action = 8

	// Combined
	CREATE_READ          Action = CREATE | READ                   // 3
	CREATE_UPDATE        Action = CREATE | UPDATE                 // 5
	READ_UPDATE          Action = READ | UPDATE                   // 6
	CREATE_READ_UPDATE   Action = CREATE | READ | UPDATE          // 7
	CREATE_DELETE        Action = CREATE | DELETE                 // 9
	READ_DELETE          Action = READ | DELETE                   // 10
	CREATE_READ_DELETE   Action = CREATE | READ | DELETE          // 11
	UPDATE_DELETE        Action = UPDATE | DELETE                 // 12
	CREATE_UPDATE_DELETE Action = CREATE | UPDATE | DELETE        // 13
	READ_UPDATE_DELETE   Action = READ | UPDATE | DELETE          // 14
	ALL                  Action = CREATE | READ | UPDATE | DELETE // 15
)

func (a Action) IsCreate() bool {
	// true if CREATE bit is set
	return a&CREATE == CREATE
}

func (a Action) IsRead() bool {
	// true if READ bit is set
	return a&READ == READ
}

func (a Action) IsUpdate() bool {
	// true if UPDATE bit is set
	return a&UPDATE == UPDATE
}

func (a Action) IsDelete() bool {
	// true if DELETE bit is set
	return a&DELETE == DELETE
}

func (a Action) IsAll() bool {
	// true if exactly ALL (CREATE|READ|UPDATE|DELETE)
	return a == ALL
}

// ParseAction converts a string to Action, case-insensitive.
// Returns ok=false if the string is not recognized.
func ParseAction(s string) (Action, bool) {
	sUpper := strings.ToUpper(strings.TrimSpace(s))
	switch sUpper {
	case "CREATE":
		return CREATE, true
	case "READ":
		return READ, true
	case "UPDATE":
		return UPDATE, true
	case "DELETE":
		return DELETE, true
	case "CREATE_READ":
		return CREATE_READ, true
	case "CREATE_UPDATE":
		return CREATE_UPDATE, true
	case "READ_UPDATE":
		return READ_UPDATE, true
	case "CREATE_READ_UPDATE":
		return CREATE_READ_UPDATE, true
	case "CREATE_DELETE":
		return CREATE_DELETE, true
	case "READ_DELETE":
		return READ_DELETE, true
	case "CREATE_READ_DELETE":
		return CREATE_READ_DELETE, true
	case "UPDATE_DELETE":
		return UPDATE_DELETE, true
	case "CREATE_UPDATE_DELETE":
		return CREATE_UPDATE_DELETE, true
	case "READ_UPDATE_DELETE":
		return READ_UPDATE_DELETE, true
	case "ALL":
		return ALL, true
	default:
		return 0, false
	}
}
