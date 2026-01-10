# Account Linking Guide

## Overview

Account Linking is a feature that merges accounts created through different methods into one unified account. It is primarily used to link HEADLESS accounts (created via platform login like Google, Steam) to HEAD accounts (created with email/password).

## Account Types

| Type | Description | Characteristics |
|------|-------------|-----------------|
| **HEAD** | Account registered with email/password | Belongs to Publisher namespace, can login directly |
| **HEADLESS** | Account created via platform login | Belongs to Game namespace, can only login through platform |
| **FULL** | HEAD + HEADLESS linked account | Can login through both methods |
| **ORPHAN** | Empty account after linking | Former HEADLESS account becomes ORPHAN after linking |

## User Types

| Type | Description | Namespace |
|------|-------------|-----------|
| **HEAD** | Primary user of the account (email/password) | Empty (belongs to Publisher namespace) |
| **BODY** | Platform-linked user | Game namespace (e.g., TESTGAME) |

## Namespace Structure

```
Publisher Namespace (PUBLISHER)
├── HEAD Account (email/password)
│   └── HEAD User (user_type='HEAD', namespace='')
│
└── FULL Account (linked)
    ├── HEAD User (user_type='HEAD', namespace='')
    └── BODY User (user_type='BODY', namespace='TESTGAME')

Game Namespace (TESTGAME)
└── HEADLESS Account (platform only)
    └── BODY User (user_type='BODY', namespace='TESTGAME')
```

## Linking Process

### 1. Generate Link Code

Generate a Link Code from the HEADLESS account.

```
POST /api/{namespace}/accounts/{account_id}/link-code
```

- Generates an 8-character hexadecimal code
- Validity: 10 minutes
- Includes platform information (provider_type, provider_account_id)

### 2. Check Link Eligibility

When a HEAD account attempts to link using the Link Code, eligibility is verified.

```go
// CheckLinkEligibility verifies:
// 1. HEAD account is of type HEAD or FULL
// 2. No existing BODY user in that namespace (prevents duplicates)
// 3. HEADLESS account is valid
```

### 3. Execute Account Link

```
POST /api/{namespace}/link
Body: { "code": "a1b2c3d4" }
```

Operations performed during linking:
1. Move all BODY users from HEADLESS account to HEAD account
2. Move platform_users from HEADLESS account to HEAD account
3. Change HEAD account type to FULL
4. Change HEADLESS account type to ORPHAN
5. Mark Link Code as used

## Database Schema

### accounts
```sql
CREATE TABLE accounts (
    id VARCHAR(32) PRIMARY KEY,
    username VARCHAR(255),
    email VARCHAR(255),
    password_hash TEXT,
    account_type VARCHAR(20) DEFAULT 'HEAD',  -- HEAD, HEADLESS, FULL, ORPHAN
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### users
```sql
CREATE TABLE users (
    id VARCHAR(32) PRIMARY KEY,
    namespace VARCHAR(255),           -- '' for HEAD users, 'TESTGAME' for BODY users
    user_type VARCHAR(20),            -- HEAD or BODY
    display_name VARCHAR(255),
    provider_type VARCHAR(50),
    provider_account_id VARCHAR(255),
    orphaned BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### account_users (Bridge Table)
```sql
CREATE TABLE account_users (
    id VARCHAR(32) PRIMARY KEY,
    account_id VARCHAR(32) REFERENCES accounts(id),
    user_id VARCHAR(32) REFERENCES users(id),
    created_at TIMESTAMP
);
```

### link_codes
```sql
CREATE TABLE link_codes (
    id VARCHAR(32) PRIMARY KEY,
    code VARCHAR(8) UNIQUE,
    headless_account_id VARCHAR(32),
    namespace VARCHAR(255),
    provider_type VARCHAR(50),
    provider_account_id VARCHAR(255),
    expires_at TIMESTAMP,
    used BOOLEAN DEFAULT FALSE,
    used_by_account_id VARCHAR(32),
    used_at TIMESTAMP,
    created_at TIMESTAMP
);
```

## Linking Rules

### Eligibility Conditions
- Only HEAD accounts (account_type = 'HEAD' or 'FULL') can be the linking initiator
- Only HEADLESS accounts (account_type = 'HEADLESS') can be the linking target
- Cannot link if a BODY user already exists in the same namespace (1 account : 1 user per namespace)

### Linking Rules
```
Publisher Account (HEAD)     +    Game Account (HEADLESS)
        │                                  │
        │         Link Code               │
        │ <────────────────────────────── │
        │                                  │
        ▼                                  ▼
Publisher Account (FULL)          Game Account (ORPHAN)
├── HEAD User                     └── (empty)
└── BODY User (moved)
```

### 1:N Relationship
- One Publisher account (HEAD/FULL) can link with multiple HEADLESS accounts from different Game namespaces
- However, only one account can be linked per Game namespace

```
FULL Account
├── HEAD User (Publisher)
├── BODY User (TESTGAME namespace)
├── BODY User (GAME_A namespace)
└── BODY User (GAME_B namespace)
```

## API Endpoints

### Generate Link Code
```
POST /api/{namespace}/accounts/{account_id}/link-code
Response: {
    "code": "a1b2c3d4",
    "expires_at": "2024-01-01T12:10:00Z"
}
```

### Check Link Eligibility
```
GET /api/{namespace}/link/eligibility?code={link_code}
Response: {
    "eligible": true,
    "head_account_id": "...",
    "headless_account_id": "...",
    "namespace": "TESTGAME"
}
```

### Link Accounts
```
POST /api/{namespace}/link
Body: { "code": "a1b2c3d4" }
Response: {
    "success": true,
    "linked_account_id": "...",
    "namespace": "TESTGAME"
}
```

## Admin Console Queries

### When Publisher Namespace is Selected
- Only HEAD users are queried (user_type = 'HEAD')
- HEAD/FULL can be distinguished by account_type

### When Game Namespace is Selected
- Only BODY users are queried (user_type = 'BODY', namespace = 'TESTGAME')
- Displays the linked HEAD user's display_name

## Test Application

You can test the entire flow using the Account Linking Test application.

### Prerequisites

1. **Go 1.21+** installed
2. **PostgreSQL** database running
3. **Database migrations** applied

### Database Setup

Start PostgreSQL using Docker Compose:

```bash
# Start PostgreSQL
docker-compose up -d postgres

# Run migrations
make migrate-up
# or
goose -dir migrate/sql postgres "postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable" up
```

### Build

```bash
# Build the test application using make
make linktest-build

# Or build manually
go build -o bin/linktest ./cmd/linktest
```

### Run

#### Option 1: Quick start with make (Recommended)

```bash
# Start DB, run migrations, and launch linktest
make linktest-dev
```

#### Option 2: Run only (DB already running)

```bash
make linktest
```

#### Option 3: Run directly with Go

```bash
go run cmd/linktest/main.go
```

#### Option 4: Run the built binary

```bash
./bin/linktest
```

#### Option 5: Run with custom database URL

```bash
DATABASE_URL="postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable" go run cmd/linktest/main.go
```

#### Option 6: Run with custom port

```bash
# Using make
LINKTEST_PORT=9000 make linktest

# Or directly
PORT=9000 go run cmd/linktest/main.go
```

### Stop

```bash
# Kill linktest process
make linktest-kill
```

### Access

Open your browser and navigate to:

```
http://localhost:8088
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://oauth2:oauth2pass@localhost:5432/oauth2db?sslmode=disable` | PostgreSQL connection string |
| `PORT` | `8088` | HTTP server port |

### Application Features

| Feature | Description |
|---------|-------------|
| **Register** | Create a HEAD account in PUBLISHER namespace |
| **Login** | Login with existing HEAD account |
| **Create Headless Account** | Simulate platform login to create HEADLESS account |
| **Generate Link Code** | Generate 8-char code from HEADLESS account |
| **Link Account** | Link HEADLESS account to logged-in HEAD account |
| **View Accounts** | List all accounts with their types and namespaces |

### Test Scenario

1. **Register** to create a HEAD account in PUBLISHER namespace
2. **Create Headless Account** to create a HEADLESS account in TESTGAME namespace
3. Click **Generate Link Code** on the HEADLESS account
4. **Login** with HEAD account and enter the Link Code to link
5. Verify that the HEAD account has changed to **FULL** after linking
6. Check in **Admin Console** that the user appears in both PUBLISHER and TESTGAME namespaces

### Troubleshooting

#### Database connection failed
```
Error: password authentication failed for user "postgres"
```
Solution: Check that PostgreSQL is running and the DATABASE_URL is correct.

#### Port already in use
```
Error: listen tcp :8088: bind: address already in use
```
Solution: Kill the existing process or use a different port:
```bash
# Kill process on port 8088
lsof -ti:8088 | xargs kill -9

# Or use different port
PORT=9000 go run cmd/linktest/main.go
```

#### Link code generation failed
```
Error: No platform linked in this namespace
```
Solution: Make sure the HEADLESS account has a BODY user with platform information in the specified namespace.

