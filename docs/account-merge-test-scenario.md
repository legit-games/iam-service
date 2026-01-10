# Account Merge Test Scenario

## Overview
This document describes a test scenario for the Account Merge feature, specifically focusing on conflict situations.

## Test Objectives
- Reproduce a conflict situation where two HEADLESS accounts created with different platforms in the same namespace
- Verify conflict detection and resolution UI functionality

---

## Test Scenario: Merging Different Platform Accounts in the Same Game

### Prerequisites
- linktest app running (`go run cmd/linktest/main.go`)
- TESTGAME namespace exists

### Step-by-Step Guide

#### Step 1: Create HEADLESS Account with XBOX
1. Navigate to "Platform Login (HEADLESS)" section on linktest main page
2. Enter the following information:
   - **Namespace**: `TESTGAME`
   - **Platform Type**: `xbox`
   - **Platform User ID**: `xbox_user_001`
3. Click "Platform Login" button
4. **Result**: HEADLESS Account A created
   - Account Type: `HEADLESS`
   - BODY user: namespace=TESTGAME, provider_type=xbox

#### Step 2: Create HEADLESS Account with PlayStation
1. Open a new browser session or logout first
2. In "Platform Login (HEADLESS)" section:
   - **Namespace**: `TESTGAME`
   - **Platform Type**: `playstation`
   - **Platform User ID**: `ps_user_001`
3. Click "Platform Login" button
4. **Result**: HEADLESS Account B created
   - Account Type: `HEADLESS`
   - BODY user: namespace=TESTGAME, provider_type=playstation

#### Step 3: Create HEAD Account
1. Open a new browser session or logout first
2. In "Register" section:
   - **Email**: `test@example.com`
   - **Password**: `password123`
3. Click "Register" button
4. **Result**: HEAD Account C created
   - Account Type: `HEAD`
   - Only HEAD user exists (namespace=nil)

#### Step 4: Link XBOX HEADLESS to HEAD (Create FULL Account)
1. While logged in as HEAD Account C
2. In "Link Account" section:
   - **Source Account ID**: Account A's ID (XBOX HEADLESS)
3. Click "Link" button
4. **Result**: Account C becomes FULL
   - Account Type: `FULL`
   - HEAD user + BODY user (TESTGAME/xbox)
   - Account A becomes ORPHAN

#### Step 5: Merge PS HEADLESS into FULL (Conflict Occurs)
1. While logged in as FULL Account C
2. In "Merge Account" section:
   - **Source Account ID**: Account B's ID (PS HEADLESS)
3. Click "Check Eligibility" button
4. **Expected Result**: Conflict detected
   ```json
   {
     "eligible": false,
     "reason": "conflict_detected",
     "conflicts": [
       {
         "namespace": "TESTGAME",
         "source_provider_type": "playstation",
         "source_provider_account": "ps_user_001",
         "target_provider_type": "xbox",
         "target_provider_account": "xbox_user_001"
       }
     ]
   }
   ```

#### Step 6: Resolve Conflict
1. With conflict information displayed, select resolution method:

   **Option A - Select SOURCE (Keep PlayStation)**:
   - Select "SOURCE" from the Keep dropdown for TESTGAME namespace
   - Click "Merge" button
   - **Result**:
     - Target's XBOX BODY user → ORPHAN
     - Source's PS BODY user → Moved to Target
     - Final: FULL account accesses TESTGAME via PlayStation

   **Option B - Select TARGET (Keep XBOX)**:
   - Select "TARGET" from the Keep dropdown for TESTGAME namespace
   - Click "Merge" button
   - **Result**:
     - Source's PS BODY user → ORPHAN
     - Target's XBOX BODY user retained
     - Final: FULL account accesses TESTGAME via XBOX

---

## Verification Checklist

### Conflict Detection
- [ ] Conflict is detected when different platform BODYs exist in the same namespace
- [ ] Conflict information accurately displays both platform details

### When SOURCE is Selected
- [ ] Source's BODY user is moved to Target account
- [ ] Target's existing BODY user is orphaned
- [ ] Source account status changes to ORPHAN
- [ ] MERGE record is created in account_transactions

### When TARGET is Selected
- [ ] Target's BODY user is retained as-is
- [ ] Source's BODY user is orphaned
- [ ] Source account status changes to ORPHAN
- [ ] MERGE record is created in account_transactions

---

## Data Flow Diagram

```
Initial State:
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Account A     │     │   Account B     │     │   Account C     │
│   (HEADLESS)    │     │   (HEADLESS)    │     │     (HEAD)      │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ BODY: TESTGAME  │     │ BODY: TESTGAME  │     │ HEAD user only  │
│ Platform: XBOX  │     │ Platform: PS    │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘

After Step 4 - Link:
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Account A     │     │   Account B     │     │   Account C     │
│    (ORPHAN)     │     │   (HEADLESS)    │     │     (FULL)      │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ (empty)         │     │ BODY: TESTGAME  │     │ HEAD user       │
│                 │     │ Platform: PS    │     │ BODY: TESTGAME  │
│                 │     │                 │     │ Platform: XBOX  │
└─────────────────┘     └─────────────────┘     └─────────────────┘

After Step 6 - Merge (SOURCE selected):
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Account A     │     │   Account B     │     │   Account C     │
│    (ORPHAN)     │     │    (ORPHAN)     │     │     (FULL)      │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ (empty)         │     │ (empty)         │     │ HEAD user       │
│                 │     │                 │     │ BODY: TESTGAME  │
│                 │     │                 │     │ Platform: PS    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                (XBOX is orphaned)
```

---

## Related APIs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/accounts/:id/merge/check?source_account_id=xxx` | Check merge eligibility and conflicts |
| POST | `/accounts/:id/merge` | Execute merge |

### Merge Request Example (with conflict resolution)
```json
POST /accounts/{target_account_id}/merge
{
  "source_account_id": "source-account-uuid",
  "conflict_resolutions": [
    {
      "namespace": "TESTGAME",
      "keep": "SOURCE"
    }
  ]
}
```
