#!/usr/bin/env bash
# AstraNull generic Linux agent installer — checksum-verified artifact install with outbound-only service.
set -euo pipefail

DRY_RUN=0
TOKEN=""
API_URL="${ASTRANULL_API_URL:-http://localhost:3000}"
AGENT_SOURCE=""
AGENT_URL=""
SHA256=""
INSTALL_ROOT="/"
NO_START=0
AGENT_NAME=""
TENANT_ID=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD_UNIT_SRC="${SCRIPT_DIR}/systemd/astranull-agent.service"

usage() {
  cat <<'EOF'
Usage: install.sh --token <bootstrap_token> [options]

Required:
  --token <bootstrap_token>   One-time bootstrap token (never echoed)

Non-dry-run also requires:
  --sha256 <hex>              SHA-256 of agent artifact (required for install)
  --agent-source <path>       Local agent file, or
  --agent-url <https url>     Hosted agent download URL

Options:
  --dry-run                   Validate and summarize; do not write files
  --api <url>                 AstraNull API base URL
  --install-root <path>       Staged install root (default /)
  --no-start                  Install files without enabling/starting systemd
  --agent-name <name>         Friendly agent name (metadata)
  --tenant <tenant_id>        Optional tenant hint for developer validation only
  -h, --help                  Show this help

Package repositories (deb/rpm) and GPG signature verification are not part of this
generic install path; use --sha256 with a trusted artifact source until repos ship.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --api) API_URL="${2:-}"; shift 2 ;;
    --agent-source) AGENT_SOURCE="${2:-}"; shift 2 ;;
    --agent-url) AGENT_URL="${2:-}"; shift 2 ;;
    --sha256) SHA256="${2:-}"; shift 2 ;;
    --install-root) INSTALL_ROOT="${2:-}"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --agent-name) AGENT_NAME="${2:-}"; shift 2 ;;
    --tenant) TENANT_ID="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$TOKEN" ]]; then
  echo "error: --token required" >&2
  exit 1
fi

if [[ ! "$TOKEN" =~ ^ast_[A-Za-z0-9_-]{8,}$ ]]; then
  echo "error: token format invalid (expected ast_ prefix)" >&2
  exit 1
fi

INSTALL_ROOT="${INSTALL_ROOT%/}"
if [[ -z "$INSTALL_ROOT" ]]; then
  INSTALL_ROOT="/"
fi

AGENT_BIN="${INSTALL_ROOT}/usr/local/bin/astranull-agent.mjs"
AGENT_ENV="${INSTALL_ROOT}/etc/astranull/agent.env"
TOKEN_FILE="${INSTALL_ROOT}/var/lib/astranull/bootstrap-token"
IDENTITY_DIR="${INSTALL_ROOT}/var/lib/astranull"
SYSTEMD_UNIT="${INSTALL_ROOT}/etc/systemd/system/astranull-agent.service"

sha256_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
  else
    echo "error: sha256sum or shasum required for checksum verification" >&2
    exit 1
  fi
}

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "dry-run: would install outbound-only astranull-agent for API ${API_URL}"
  echo "dry-run: would install executable to ${AGENT_BIN}"
  echo "dry-run: would write config to ${AGENT_ENV} (no secrets in env file)"
  echo "dry-run: would write bootstrap token to ${TOKEN_FILE} (mode 0600, not echoed)"
  if [[ -f "$SYSTEMD_UNIT_SRC" ]]; then
    echo "dry-run: would install systemd unit to ${SYSTEMD_UNIT}"
  fi
  echo "dry-run: token validated format only — secret not echoed"
  if [[ "$DRY_RUN" -eq 1 && -z "$SHA256" ]]; then
    echo "dry-run: non-dry-run install would require --sha256 and --agent-source or --agent-url"
  fi
  exit 0
fi

if [[ -z "$SHA256" ]]; then
  echo "error: --sha256 required for install (artifact verification)" >&2
  exit 1
fi

SHA256="$(echo "$SHA256" | tr '[:upper:]' '[:lower:]')"
if [[ ! "$SHA256" =~ ^[a-f0-9]{64}$ ]]; then
  echo "error: --sha256 must be 64 hex characters" >&2
  exit 1
fi

if [[ -n "$AGENT_SOURCE" && -n "$AGENT_URL" ]]; then
  echo "error: specify only one of --agent-source or --agent-url" >&2
  exit 1
fi

if [[ -z "$AGENT_SOURCE" && -z "$AGENT_URL" ]]; then
  AGENT_SOURCE="${SCRIPT_DIR}/astranull-agent.mjs"
fi

WORKDIR=""
cleanup() {
  if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

if [[ -n "$AGENT_URL" ]]; then
  WORKDIR="$(mktemp -d)"
  DEST="${WORKDIR}/astranull-agent.mjs"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$AGENT_URL" -o "$DEST"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$DEST" "$AGENT_URL"
  else
    echo "error: curl or wget required to download --agent-url" >&2
    exit 1
  fi
  AGENT_SOURCE="$DEST"
fi

if [[ ! -f "$AGENT_SOURCE" ]]; then
  echo "error: agent artifact not found: $AGENT_SOURCE" >&2
  exit 1
fi

COMPUTED="$(sha256_file "$AGENT_SOURCE")"
if [[ "$COMPUTED" != "$SHA256" ]]; then
  echo "error: SHA-256 mismatch — refusing to install unverified artifact" >&2
  exit 1
fi

mkdir -p "$(dirname "$AGENT_BIN")" "$(dirname "$AGENT_ENV")" "$IDENTITY_DIR"
chmod 0750 "$IDENTITY_DIR" 2>/dev/null || chmod 0755 "$IDENTITY_DIR"

if [[ "$INSTALL_ROOT" == "/" && "$(id -u)" -eq 0 ]]; then
  if ! getent group astranull >/dev/null 2>&1; then
    groupadd --system astranull 2>/dev/null || true
  fi
  if ! id astranull >/dev/null 2>&1; then
    useradd --system --gid astranull --home-dir /var/lib/astranull --shell /usr/sbin/nologin astranull 2>/dev/null || true
  fi
  chown astranull:astranull "$IDENTITY_DIR" 2>/dev/null || true
fi

install -m 0755 "$AGENT_SOURCE" "$AGENT_BIN"

{
  echo "ASTRANULL_API_URL=${API_URL}"
  echo "ASTRANULL_AGENT_IDENTITY=${IDENTITY_DIR}/identity.json"
  echo "ASTRANULL_BOOTSTRAP_TOKEN_FILE=${TOKEN_FILE}"
  if [[ -n "$AGENT_NAME" ]]; then
    echo "ASTRANULL_AGENT_NAME=${AGENT_NAME}"
  fi
  if [[ -n "$TENANT_ID" ]]; then
    echo "ASTRANULL_TENANT_ID=${TENANT_ID}"
  fi
} >"$AGENT_ENV"
chmod 0644 "$AGENT_ENV"

umask 077
printf '%s' "$TOKEN" >"$TOKEN_FILE"
chmod 0600 "$TOKEN_FILE"
umask 022

if [[ -f "$SYSTEMD_UNIT_SRC" ]]; then
  mkdir -p "$(dirname "$SYSTEMD_UNIT")"
  cp "$SYSTEMD_UNIT_SRC" "$SYSTEMD_UNIT"
  chmod 0644 "$SYSTEMD_UNIT"
fi

echo "installed astranull-agent to ${AGENT_BIN}"
echo "wrote ${AGENT_ENV} (no bootstrap secret in env file)"
echo "bootstrap token stored in ${TOKEN_FILE} (not echoed)"

START_SERVICE=0
if [[ "$NO_START" -eq 0 && "$INSTALL_ROOT" == "/" ]] && command -v systemctl >/dev/null 2>&1; then
  START_SERVICE=1
fi

if [[ "$START_SERVICE" -eq 1 ]]; then
  systemctl daemon-reload
  systemctl enable astranull-agent.service
  systemctl start astranull-agent.service
  echo "enabled and started astranull-agent.service"
else
  echo "service not started (use systemctl after install, or omit --no-start on production root)"
fi

exit 0