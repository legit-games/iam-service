package permission

import "testing"

func TestParseAction(t *testing.T) {
	cases := []struct {
		in   string
		want Action
		ok   bool
	}{
		{"create", CREATE, true},
		{"READ", READ, true},
		{"Update", UPDATE, true},
		{"delete", DELETE, true},
		{"CREATE_READ", CREATE_READ, true},
		{"ALL", ALL, true},
		{"unknown", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseAction(c.in)
		if ok != c.ok || got != c.want {
			t.Fatalf("ParseAction(%q) = (%v,%v), want (%v,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestActionBitmaskHelpers(t *testing.T) {
	// CREATE_READ should include CREATE and READ, and exclude UPDATE/DELETE
	if !CREATE_READ.IsCreate() || !CREATE_READ.IsRead() {
		t.Fatal("CREATE_READ should include CREATE and READ")
	}
	if CREATE_READ.IsUpdate() || CREATE_READ.IsDelete() {
		t.Fatal("CREATE_READ should not include UPDATE or DELETE")
	}

	// CREATE_UPDATE should include CREATE and UPDATE
	if !CREATE_UPDATE.IsCreate() || !CREATE_UPDATE.IsUpdate() {
		t.Fatal("CREATE_UPDATE should include CREATE and UPDATE")
	}
	if CREATE_UPDATE.IsRead() || CREATE_UPDATE.IsDelete() {
		t.Fatal("CREATE_UPDATE should not include READ or DELETE")
	}

	// READ_UPDATE should include READ and UPDATE
	if !READ_UPDATE.IsRead() || !READ_UPDATE.IsUpdate() {
		t.Fatal("READ_UPDATE should include READ and UPDATE")
	}
	if READ_UPDATE.IsCreate() || READ_UPDATE.IsDelete() {
		t.Fatal("READ_UPDATE should not include CREATE or DELETE")
	}

	// CREATE_DELETE should include CREATE and DELETE
	if !CREATE_DELETE.IsCreate() || !CREATE_DELETE.IsDelete() {
		t.Fatal("CREATE_DELETE should include CREATE and DELETE")
	}
	if CREATE_DELETE.IsRead() || CREATE_DELETE.IsUpdate() {
		t.Fatal("CREATE_DELETE should not include READ or UPDATE")
	}

	// ALL should include all bits and IsAll should be true
	if !ALL.IsCreate() || !ALL.IsRead() || !ALL.IsUpdate() || !ALL.IsDelete() {
		t.Fatal("ALL should include CREATE, READ, UPDATE, DELETE")
	}
	if !ALL.IsAll() {
		t.Fatal("ALL.IsAll should be true")
	}

	// Single actions should identify only themselves
	if !(CREATE.IsCreate() && !CREATE.IsRead() && !CREATE.IsUpdate() && !CREATE.IsDelete()) {
		t.Fatal("CREATE should only have CREATE bit")
	}
	if !(READ.IsRead() && !READ.IsCreate() && !READ.IsUpdate() && !READ.IsDelete()) {
		t.Fatal("READ should only have READ bit")
	}
	if !(UPDATE.IsUpdate() && !UPDATE.IsCreate() && !UPDATE.IsRead() && !UPDATE.IsDelete()) {
		t.Fatal("UPDATE should only have UPDATE bit")
	}
	if !(DELETE.IsDelete() && !DELETE.IsCreate() && !DELETE.IsRead() && !DELETE.IsUpdate()) {
		t.Fatal("DELETE should only have DELETE bit")
	}
}

func TestPermissionStringAndValueOf(t *testing.T) {
	p := Permission{Resource: "ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT", Action: CREATE_READ}
	if p.String() != "ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT_CREATE_READ" {
		t.Fatalf("String() got %q", p.String())
	}
	parsed, err := ValueOf(p.String())
	if err != nil {
		t.Fatalf("ValueOf err: %v", err)
	}
	if parsed.Resource != p.Resource || parsed.Action != p.Action {
		t.Fatalf("ValueOf roundtrip mismatch: %+v vs %+v", parsed, p)
	}
	if _, err := ValueOf("noactionpart"); err == nil {
		t.Fatal("ValueOf should fail on invalid string")
	}
}

func TestPermissionFormatValidation(t *testing.T) {
	ok := Permission{Resource: "PUBLIC:THING:SUBTHING", Action: READ}.IsValidFormat()
	if !ok {
		t.Fatal("expected valid format")
	}
	bad := Permission{Resource: "INVALID-PREFIX:THING", Action: READ}.IsValidFormat()
	if bad {
		t.Fatal("expected invalid format for resource prefix")
	}
}

func TestHasValidPermissionsExactAndWildcard(t *testing.T) {
	perms := []Permission{
		{Resource: "ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT", Action: CREATE_READ},
		{Resource: "ADMIN:NAMESPACE:LEGIT-GAMES:*", Action: READ},
	}
	// exact + bitmask OK
	if !HasValidPermissions(perms, "ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT", READ) {
		t.Fatal("expected READ allowed for client via exact permission")
	}
	// exact + bitmask not sufficient
	if HasValidPermissions(perms, "ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT", UPDATE) {
		t.Fatal("expected UPDATE denied for client")
	}
	// wildcard resource match + action OK
	if !HasValidPermissions(perms, "ADMIN:NAMESPACE:LEGIT-GAMES:DOCUMENT", READ) {
		t.Fatal("expected READ allowed via wildcard resource")
	}
}

func TestServiceHasPermissionWithPlaceholders(t *testing.T) {
	s := Service{}
	claims := Claims{
		Permissions: []string{
			"PUBLIC:ACCOUNT:{accountId}_READ",
			"ADMIN:NAMESPACE:{namespace}:CLIENT_CREATE",
		},
		AccountID: "user-123",
		Namespace: "LEGIT-GAMES",
	}
	if !s.HasPermission(claims, "PUBLIC:ACCOUNT:USER-123_READ") {
		t.Fatal("expected placeholder {accountId} to be replaced and allowed")
	}
	if !s.HasPermission(claims, "ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT_CREATE") {
		t.Fatal("expected placeholder {namespace} to be replaced and allowed")
	}
	if s.HasPermission(claims, "ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT_UPDATE") {
		t.Fatal("expected UPDATE to be denied")
	}
}

func TestNamespaceHelpers(t *testing.T) {
	if AdminNamespace("ns") != "ADMIN:NAMESPACE:NS" {
		t.Fatal("AdminNamespace helper invalid")
	}
	if AdminNamespaceClients("ns") != "ADMIN:NAMESPACE:NS:CLIENT" {
		t.Fatal("AdminNamespaceClients helper invalid")
	}
}
