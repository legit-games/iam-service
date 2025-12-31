# Go Permission Service (Port of Java PermissionService)

This package ports the Java `PermissionService` and related classes to Go, designed for reuse in IAM components.

Features:
- Permission and Action bitmask model identical to Java values.
- Placeholder replacement for `{accountId}` and `{namespace}` (supports lowercase/uppercase tokens).
- Resource matching with exact and `*` prefix semantics.
- Small helper API via `Service`.

## Resource format (UPPERCASE)
- Resource prefixes are normalized to uppercase: `PUBLIC` or `ADMIN`.
- Examples:
  - `PUBLIC:ACCOUNT:{accountId}_READ`
  - `ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT_CREATE_READ`
  - `ADMIN:NAMESPACE:LEGIT-GAMES:*_READ`

## Usage
Create `Claims` from your auth middleware and check a required permission:

```go
claims := permission.Claims{
    Permissions: []string{
        "PUBLIC:ACCOUNT:{accountId}_READ",
        "ADMIN:NAMESPACE:{namespace}:CLIENT_CREATE",
        "ADMIN:NAMESPACE:LEGIT-GAMES:*_READ",
    },
    // AccountID is UUID4 hyphenless (32 hex chars), e.g., "018b28126a5f767500000009a4404002"
    AccountID: "018b28126a5f767500000009a4404002",
    Namespace: "LEGIT-GAMES",
}
svc := permission.Service{}
// Will succeed after placeholder replacement
allowed := svc.HasPermission(claims, "ADMIN:NAMESPACE:LEGIT-GAMES:CLIENT_CREATE")
// ...
```

## Helpers
- `Namespace(ns)`: returns `ADMIN:NAMESPACE:{NS}` (uppercase NS)
- `NamespaceClients(ns)`: returns `ADMIN:NAMESPACE:{NS}:CLIENT`

## Notes
- Invalid permission strings are ignored (not fatal), matching Java behavior.
- `ValueOf` normalizes the resource portion to uppercase; checks also normalize input.
- Extend `Claims` to include more user attributes if your system requires.
