# Link Test Application

Headless 계정을 Head 계정에 링크하는 기능을 테스트하기 위한 애플리케이션입니다.

## 실행 방법

### 1. PostgreSQL 실행

**Docker 사용 (권장):**
```bash
cd cmd/linktest
docker-compose up -d
```

**Homebrew 사용 (Mac):**
```bash
brew install postgresql@15
brew services start postgresql@15
createdb oauth2
```

### 2. 마이그레이션 실행

```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/oauth2?sslmode=disable"
go run ./migrate/cmd/main.go up
```

### 3. 테스트 앱 실행

**스크립트 사용:**
```bash
./cmd/linktest/run.sh
```

**직접 실행:**
```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/oauth2?sslmode=disable"
go run ./cmd/linktest/main.go
```

### 4. 브라우저에서 접속

http://localhost:8088

## 테스트 시나리오

### Headless 계정을 Head 계정에 링크하기

1. **HEAD 계정 생성 (Register)**
   - Register 버튼 클릭
   - Username, Email, Password 입력하여 등록
   - 등록 후 자동 로그인됨

2. **HEADLESS 계정 생성 (Simulate Platform Login)**
   - "Create Headless Account" 섹션에서 버튼 클릭
   - Google 등의 플랫폼으로 로그인한 것처럼 HEADLESS 계정이 생성됨

3. **Link Code 생성**
   - All Accounts 테이블에서 HEADLESS 계정의 "Generate Link Code" 버튼 클릭
   - 8자리 링크 코드가 생성됨 (10분 후 만료)

4. **계정 링크**
   - HEAD 계정으로 로그인된 상태에서
   - "Link Headless Account" 섹션에 링크 코드 입력
   - "Link Account" 버튼 클릭
   - HEAD 계정이 FULL 타입으로 변경됨
   - HEADLESS 계정은 ORPHAN 타입으로 변경됨

## 계정 타입 설명

| 타입 | 설명 |
|------|------|
| HEAD | 이메일/비밀번호로 생성된 기본 계정 |
| HEADLESS | 플랫폼(Google 등)으로만 로그인한 계정 |
| FULL | HEAD + BODY(플랫폼) 유저가 모두 있는 계정 |
| ORPHAN | 링크 후 남은 빈 계정 |

## 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| DATABASE_URL | postgres://postgres:postgres@localhost:5432/oauth2?sslmode=disable | PostgreSQL 연결 문자열 |
| PORT | 8088 | 서버 포트 |

## API 엔드포인트

| Method | Path | 설명 |
|--------|------|------|
| GET | / | 홈 페이지 |
| GET/POST | /login | 로그인 |
| GET/POST | /register | HEAD 계정 등록 |
| GET | /logout | 로그아웃 |
| POST | /create-headless | HEADLESS 계정 생성 |
| POST | /generate-link-code | 링크 코드 생성 |
| POST | /link-with-code | 코드로 계정 링크 |
| GET | /accounts | 모든 계정 목록 (JSON) |
