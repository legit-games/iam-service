# Link Test Application

A test application for testing account linking, unlinking, and merging functionality.

## How to Run

### 1. Start PostgreSQL

**Using Docker (Recommended):**
```bash
cd cmd/linktest
docker-compose up -d
```

**Using Homebrew (Mac):**
```bash
brew install postgresql@15
brew services start postgresql@15
createdb oauth2
```

### 2. Run Migrations

```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/oauth2?sslmode=disable"
go run ./migrate/cmd/main.go up
```

### 3. Run the Test App

**Using script:**
```bash
./cmd/linktest/run.sh
```

**Direct execution:**
```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/oauth2?sslmode=disable"
go run ./cmd/linktest/main.go
```

### 4. Access in Browser

http://localhost:8088

## Test Scenarios

### Linking a Headless Account to a Head Account

1. **Create HEAD Account (Register)**
   - Click the Register button
   - Enter Username, Email, Password to register
   - Automatically logged in after registration

2. **Create HEADLESS Account (Simulate Platform Login)**
   - Click button in "Create Headless Account" section
   - A HEADLESS account is created as if logged in via platform (Google, Steam, etc.)

3. **Generate Link Code**
   - In the All Accounts table, click "Generate Code" button on the HEADLESS account
   - An 8-character link code is generated (expires in 10 minutes)

4. **Link Accounts**
   - While logged in as HEAD account
   - Enter the link code in "Link with Code" section
   - Click "Link Account" button
   - HEAD account type changes to FULL
   - HEADLESS account type changes to ORPHAN

### Unlinking Accounts

1. **Unlink from FULL Account**
   - On a FULL account, click "Unlink {namespace}" button
   - The linked BODY user is moved back to original HEADLESS account
   - FULL account becomes HEAD
   - ORPHAN account is restored to HEADLESS

### Merging Accounts

1. **Check Merge Eligibility**
   - Two accounts with different platforms in the same namespace can be merged
   - Same platform type conflicts are NOT mergeable

2. **Merge with Conflict Resolution**
   - When both accounts have BODY users in the same namespace with different platforms
   - Select which platform's data to keep (SOURCE or TARGET)
   - The losing user's platform credentials are transferred to the winning user (AccelByte approach)
   - Both platforms can then login and access the same user data

## Account Types

| Type | Description |
|------|-------------|
| HEAD | Basic account created with email/password |
| HEADLESS | Account created via platform login only (Google, Steam, etc.) |
| FULL | Account with both HEAD user and BODY (platform) users |
| ORPHAN | Empty account remaining after link/merge |

## User Types

| Type | Description |
|------|-------------|
| HEAD | User without namespace, created with email/password |
| BODY | Namespace-scoped user with platform credentials |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| DATABASE_URL | postgres://postgres:postgres@localhost:5432/oauth2?sslmode=disable | PostgreSQL connection string |
| PORT | 8088 | Server port |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | / | Home page |
| GET/POST | /login | Login |
| GET/POST | /register | Register HEAD account |
| GET | /logout | Logout |
| POST | /create-headless | Create HEADLESS account |
| POST | /generate-link-code | Generate link code |
| POST | /link-with-code | Link account with code |
| POST | /unlink | Unlink namespace (reverse Link) |
| GET | /merge/check | Check merge eligibility |
| POST | /merge | Merge accounts |
| GET | /accounts | List all accounts (JSON) |

## Key Concepts

### Link vs Merge

| Aspect | Link | Merge |
|--------|------|-------|
| Scenario | Connect HEADLESS to HEAD | Combine two accounts with data |
| Source | HEADLESS only | HEAD, HEADLESS, or FULL |
| Target | HEAD only | HEAD or FULL |
| Conflict | Not possible (HEADLESS has single namespace) | Possible (same namespace with different platforms) |
| Reversible | Yes (Unlink) | Requires separate Unmerge |

### Platform Credential Transfer (AccelByte Approach)

When merging accounts with conflicts:
- The losing user's `platform_users.user_id` is updated to point to the winning user
- Both platforms can then login and return the same user ID
- The losing user is marked as orphaned
