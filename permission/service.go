package permission

import (
	"strings"
)

// Claims represents user attributes typically attached by auth middleware.
// permissions: []string of "resource_action"
// accountId, namespace: optional for placeholder replacement
// Additional claims can be added as needed.
type Claims struct {
	Permissions []string
	AccountID   string
	Namespace   string
}

// Service mirrors Java PermissionService public helpers.
type Service struct{}

// replace placeholders in a slice of Permission by using claims
func replacePlaceholders(c Claims, list []Permission) {
	for i := range list {
		res := list[i].Resource
		// accountId
		if c.AccountID != "" {
			if strings.Contains(res, "{accountId}") {
				res = strings.ReplaceAll(res, "{accountId}", c.AccountID)
			}
			if strings.Contains(res, "{ACCOUNTID}") {
				res = strings.ReplaceAll(res, "{ACCOUNTID}", strings.ToUpper(c.AccountID))
			}
		}
		// namespace
		if c.Namespace != "" {
			if strings.Contains(res, "{namespace}") {
				res = strings.ReplaceAll(res, "{namespace}", c.Namespace)
			}
			if strings.Contains(res, "{NAMESPACE}") {
				res = strings.ReplaceAll(res, "{NAMESPACE}", strings.ToUpper(c.Namespace))
			}
		}
		list[i].Resource = res
	}
}

// HasPermission checks if claims.Permissions contain the required resource/action.
// Returns false on empty/malformed input; errors are not propagated to match Java behavior.
func (Service) HasPermission(c Claims, permissionString string) bool {
	parts := strings.SplitN(permissionString, "_", 2)
	if len(parts) != 2 {
		return false
	}
	a, ok := ParseAction(parts[1])
	if !ok {
		return false
	}

	// Parse all user permission strings
	var parsed []Permission
	for _, s := range c.Permissions {
		p, err := ValueOf(s)
		if err != nil {
			continue
		}
		parsed = append(parsed, p)
	}
	if len(parsed) == 0 {
		return false
	}

	replacePlaceholders(c, parsed)
	return HasValidPermissions(parsed, parts[0], a)
}

// Helper methods mirroring Java naming
func (s Service) HasAdminAccountPermission(c Claims, accountID string, action Action) bool {
	return s.HasPermission(c, "admin:account:"+accountID+":permission_"+actionString(action))
}
func (s Service) HasAdminAccount(c Claims, action Action) bool {
	return s.HasPermission(c, "admin:account_"+actionString(action))
}
func (s Service) HasAdminAccountWithID(c Claims, accountID string, action Action) bool {
	return s.HasPermission(c, "admin:account:"+accountID+"_"+actionString(action))
}
func (s Service) HasAdminNamespaceAccount(c Claims, namespace string, action Action) bool {
	return s.HasPermission(c, "admin:namespace:"+namespace+":account_"+actionString(action))
}
func (s Service) HasAdminNamespaceDocument(c Claims, namespace string, action Action) bool {
	return s.HasPermission(c, "admin:namespace:"+namespace+":document_"+actionString(action))
}
func (s Service) HasAdminNamespaceClient(c Claims, namespace string, action Action) bool {
	return s.HasPermission(c, "admin:namespace:"+namespace+":client_"+actionString(action))
}
func (s Service) HasAdminNamespacePermission(c Claims, namespace string, action Action) bool {
	return s.HasPermission(c, "admin:namespace:"+namespace+":permission_"+actionString(action))
}
func (s Service) HasAdminNamespaceProviderClient(c Claims, namespace string, action Action) bool {
	return s.HasPermission(c, "admin:namespace:"+namespace+":providerclient_"+actionString(action))
}
func (s Service) HasAdminNamespaceRole(c Claims, namespace string, action Action) bool {
	return s.HasPermission(c, "admin:namespace:"+namespace+":role_"+actionString(action))
}
func (s Service) HasAdminNamespace(c Claims, action Action) bool {
	return s.HasPermission(c, "admin:namespace_"+actionString(action))
}
func (s Service) HasAdminNamespaceWithID(c Claims, namespace string, action Action) bool {
	return s.HasPermission(c, "admin:namespace:"+namespace+"_"+actionString(action))
}
func (s Service) HasAdminRole(c Claims, action Action) bool {
	return s.HasPermission(c, "admin:role_"+actionString(action))
}

// actionString mirrors the names used in Java
func actionString(a Action) string {
	switch a {
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
		return "UNKNOWN"
	}
}
