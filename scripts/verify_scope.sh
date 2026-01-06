#!/usr/bin/env bash
set -euo pipefail

# Requires: curl, jq, python3
# Env:
#   AUTH_BASE (e.g., https://auth.example.com)
#   TOKEN_ENDPOINT (defaults to $AUTH_BASE/oauth/token)
#   INTROSPECT_ENDPOINT (defaults to $AUTH_BASE/oauth/introspect)
#   CLIENT_ID, CLIENT_SECRET (required)
#   SCOPE (defaults to "read")
#   GRANT_TYPE (defaults to "client_credentials")
#   INTROSPECT_CLIENT_ID, INTROSPECT_CLIENT_SECRET (optional, for opaque tokens)

AUTH_BASE="${AUTH_BASE:-}"
TOKEN_ENDPOINT="${TOKEN_ENDPOINT:-${AUTH_BASE:+$AUTH_BASE/oauth/token}}"
INTROSPECT_ENDPOINT="${INTROSPECT_ENDPOINT:-${AUTH_BASE:+$AUTH_BASE/oauth/introspect}}"

if [[ -z "${TOKEN_ENDPOINT}" ]]; then
  echo "Set AUTH_BASE or TOKEN_ENDPOINT"
  exit 1
fi

CLIENT_ID="${CLIENT_ID:?set CLIENT_ID}"
CLIENT_SECRET="${CLIENT_SECRET:?set CLIENT_SECRET}"
SCOPE="${SCOPE:-read}"
GRANT_TYPE="${GRANT_TYPE:-client_credentials}"

INTROSPECT_CLIENT_ID="${INTROSPECT_CLIENT_ID:-}"
INTROSPECT_CLIENT_SECRET="${INTROSPECT_CLIENT_SECRET:-}"

echo "Requesting token (grant_type=${GRANT_TYPE}, scope='${SCOPE}') ..."
RESP="$(curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=${GRANT_TYPE}&scope=$(printf %s "$SCOPE" | sed 's/ /%20/g')" \
  "${TOKEN_ENDPOINT}" || true)"

if [[ -z "${RESP}" ]]; then
  echo "Empty token response"
  exit 1
fi

echo "Token response:"
echo "${RESP}" | jq .

ERROR_DESC="$(echo "${RESP}" | jq -r '.error // empty')"
if [[ -n "${ERROR_DESC}" ]]; then
  echo "Token error: ${ERROR_DESC}"
  if [[ "${ERROR_DESC}" == "invalid_scope" ]]; then
    echo "Client not allowed for requested scope(s)."
  fi
  exit 2
fi

ACCESS_TOKEN="$(echo "${RESP}" | jq -r '.access_token // empty')"
if [[ -z "${ACCESS_TOKEN}" ]]; then
  echo "No access_token in response"
  exit 3
fi

RESP_SCOPE="$(echo "${RESP}" | jq -r '.scope // empty')"
if [[ -n "${RESP_SCOPE}" ]]; then
  echo "Granted scope (from token response): ${RESP_SCOPE}"
fi

echo
echo "Validating scope in the issued token ..."

if [[ "${ACCESS_TOKEN}" == *.*.* ]]; then
  echo "Detected JWT access token. Decoding payload ..."
  PAYLOAD_JSON="$(python3 - "$ACCESS_TOKEN" <<'PY'
import sys, json, base64
tok = sys.argv[1]
parts = tok.split('.')
if len(parts) < 2:
    print("{}"); sys.exit(0)
p = parts[1] + "=" * (-len(parts[1]) % 4)
print(base64.urlsafe_b64decode(p.encode()).decode())
PY
)"
  echo "${PAYLOAD_JSON}" | jq .
  TOKEN_SCOPE="$(echo "${PAYLOAD_JSON}" | jq -r 'if has("scope") then .scope elif has("scp") then (.scp|join(" ")) else empty end')"
  if [[ -z "${TOKEN_SCOPE}" ]]; then
    echo "No 'scope'/'scp' claim found in JWT (RFC 9068 recommends 'scope')."
  else
    echo "scope in JWT: ${TOKEN_SCOPE}"
  fi
else
  echo "Detected opaque access token."
  if [[ -n "${INTROSPECT_CLIENT_ID}" && -n "${INTROSPECT_CLIENT_SECRET}" && -n "${INTROSPECT_ENDPOINT}" ]]; then
    echo "Calling introspection endpoint (RFC 7662) ..."
    INTROSPECT_RESP="$(curl -sS -u "${INTROSPECT_CLIENT_ID}:${INTROSPECT_CLIENT_SECRET}" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -d "token=${ACCESS_TOKEN}" \
      "${INTROSPECT_ENDPOINT}")"
    echo "${INTROSPECT_RESP}" | jq .
    ACTIVE="$(echo "${INTROSPECT_RESP}" | jq -r '.active // false')"
    if [[ "${ACTIVE}" != "true" ]]; then
      echo "Token not active"
      exit 4
    fi
    TOKEN_SCOPE="$(echo "${INTROSPECT_RESP}" | jq -r '.scope // empty')"
    if [[ -z "${TOKEN_SCOPE}" ]]; then
      echo "No 'scope' in introspection response."
    else
      echo "scope (introspection): ${TOKEN_SCOPE}"
    fi
  else
    echo "No introspection credentials or endpoint. Set INTROSPECT_CLIENT_ID/INTROSPECT_CLIENT_SECRET and INTROSPECT_ENDPOINT."
  fi
fi

echo
REQ_SCOPES="${SCOPE}"
GRANTED="${TOKEN_SCOPE:-${RESP_SCOPE:-}}"
if [[ -n "${GRANTED}" ]]; then
  missing=0
  for s in ${REQ_SCOPES}; do
    if ! grep -qw "$s" <<< "${GRANTED}"; then
      echo "Missing scope in token: $s"
      missing=1
    fi
  done
  if [[ $missing -eq 1 ]]; then
    echo "Requested scopes are not fully granted/embedded."
    exit 5
  fi
  echo "All requested scopes granted and discoverable."
else
  echo "Could not read granted scopes from token/JWT/introspection."
fi

