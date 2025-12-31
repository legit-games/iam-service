package permission

import (
	"fmt"
	"regexp"
	"strings"
)

// Constants mirroring Java Permission.java, now using uppercase prefixes
const (
	resourceRegex = `^(PUBLIC|ADMIN):[A-Za-z0-9:*{}]*$`
)

// Permission models a single permission of resource + action
// Example string: "ADMIN:NAMESPACE:ns:DOCUMENT_READ"
type Permission struct {
	Resource string
	Action   Action
}

func (p Permission) String() string { return fmt.Sprintf("%s_%s", p.Resource, p.ActionString()) }

func (p Permission) ActionString() string {
	switch p.Action {
	case CREATE:
		return "CREATE"
	case READ:
		return "READ"
	case UPDATE:
		return "UPDATE"
	case DELETE:
		return "DELETE"
	case CREATE_READ:
		return "CREATE_READ"
	case CREATE_UPDATE:
		return "CREATE_UPDATE"
	case READ_UPDATE:
		return "READ_UPDATE"
	case CREATE_READ_UPDATE:
		return "CREATE_READ_UPDATE"
	case CREATE_DELETE:
		return "CREATE_DELETE"
	case READ_DELETE:
		return "READ_DELETE"
	case CREATE_READ_DELETE:
		return "CREATE_READ_DELETE"
	case UPDATE_DELETE:
		return "UPDATE_DELETE"
	case CREATE_UPDATE_DELETE:
		return "CREATE_UPDATE_DELETE"
	case READ_UPDATE_DELETE:
		return "READ_UPDATE_DELETE"
	case ALL:
		return "ALL"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", p.Action)
	}
}

// ValueOf parses "resource_action" to a Permission
func ValueOf(s string) (Permission, error) {
	parts := strings.SplitN(s, "_", 2)
	if len(parts) != 2 {
		return Permission{}, fmt.Errorf("invalid permission string: %s", s)
	}
	a, ok := ParseAction(parts[1])
	if !ok {
		return Permission{}, fmt.Errorf("invalid action: %s", parts[1])
	}
	// enforce uppercase resource prefix for normalized format
	res := strings.TrimSpace(parts[0])
	res = strings.ToUpper(res)
	return Permission{Resource: res, Action: a}, nil
}

// IsValidFormat checks resource regex + valid action string
func (p Permission) IsValidFormat() bool {
	if p.Resource == "" {
		return false
	}
	re := regexp.MustCompile(resourceRegex)
	if !re.MatchString(p.Resource) {
		return false
	}
	// Action validity already guaranteed by construction
	return true
}

// HasValidPermissions returns true if any permission matches the resource and action via bitmask
func HasValidPermissions(perms []Permission, resource string, action Action) bool {
	// normalize check resource to uppercase as well
	resource = strings.ToUpper(resource)
	for _, perm := range perms {
		if resourceMatches(perm.Resource, resource) {
			if int(action)&int(perm.Action) == int(action) {
				return true
			}
		}
	}
	return false
}

// resourceMatches replicates Java logic: exact, or prefix when permission resource ends with '*'
func resourceMatches(permissionResource, resourceToCheck string) bool {
	// both expected uppercase; still use case-insensitive compare for safety
	if strings.EqualFold(permissionResource, resourceToCheck) {
		return true
	}
	if strings.HasSuffix(permissionResource, "*") {
		prefix := strings.TrimSuffix(permissionResource, "*")
		return strings.HasPrefix(resourceToCheck, prefix)
	}
	return strings.EqualFold(permissionResource, resourceToCheck)
}

// Helpers mirroring static methods
func AdminNamespace(ns string) string        { return "ADMIN:NAMESPACE:" + strings.ToUpper(ns) }
func AdminNamespaceRoles(ns string) string   { return AdminNamespace(ns) + ":ROLE" }
func AdminNamespaceUsers(ns string) string   { return AdminNamespace(ns) + ":USER" }
func AdminNamespaceClients(ns string) string { return AdminNamespace(ns) + ":CLIENT" }
