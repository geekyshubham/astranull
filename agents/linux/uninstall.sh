#!/usr/bin/env bash
# AstraNull generic Linux agent uninstall — bounded removal of install artifacts; optional data purge.
set -euo pipefail

DRY_RUN=0
INSTALL_ROOT="/"
PURGE_DATA=0

usage() {
  cat <<'EOF'
Usage: uninstall.sh [options]

Options:
  --dry-run                   Summarize removals; do not delete files
  --install-root <path>       Staged uninstall root (default /)
  --purge-data                Remove /var/lib/astranull identity and bootstrap data
  -h, --help                  Show this help

Default behavior removes the systemd unit, agent binary, and /etc/astranull/agent.env
but preserves /var/lib/astranull unless --purge-data is set.

On production root (/) when systemctl is available, stops and disables astranull-agent.service.
Secrets are never read or echoed.

deb/rpm package-manager uninstall flows are not implemented in this script; use distro
tools when native packages ship.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --install-root) INSTALL_ROOT="${2:-}"; shift 2 ;;
    --purge-data) PURGE_DATA=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

INSTALL_ROOT="${INSTALL_ROOT%/}"
if [[ -z "$INSTALL_ROOT" ]]; then
  INSTALL_ROOT="/"
fi

if [[ "$INSTALL_ROOT" != /* ]]; then
  echo "error: --install-root must be an absolute path" >&2
  exit 1
fi

AGENT_BIN="${INSTALL_ROOT}/usr/local/bin/astranull-agent.mjs"
AGENT_ENV="${INSTALL_ROOT}/etc/astranull/agent.env"
AGENT_ENV_DIR="${INSTALL_ROOT}/etc/astranull"
IDENTITY_DIR="${INSTALL_ROOT}/var/lib/astranull"
SYSTEMD_UNIT="${INSTALL_ROOT}/etc/systemd/system/astranull-agent.service"

# Refuse ambiguous or dangerously short install roots for data purge.
if [[ "$PURGE_DATA" -eq 1 ]]; then
  if [[ "$IDENTITY_DIR" != *"/var/lib/astranull" ]]; then
    echo "error: identity data path is not a known AstraNull location" >&2
    exit 1
  fi
  if [[ "$INSTALL_ROOT" == "/" || "$INSTALL_ROOT" == "" ]]; then
    : # production purge allowed when operator passes --purge-data explicitly
  elif [[ ! "$IDENTITY_DIR" == "${INSTALL_ROOT}/var/lib/astranull" ]]; then
    echo "error: identity path must stay under --install-root" >&2
    exit 1
  fi
fi

remove_file() {
  local f="$1"
  if [[ -e "$f" || -L "$f" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "dry-run: would remove ${f}"
    else
      rm -f "$f"
      echo "removed ${f}"
    fi
  else
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "dry-run: ${f} already absent"
    fi
  fi
}

remove_dir_if_empty() {
  local d="$1"
  if [[ -d "$d" && -z "$(ls -A "$d" 2>/dev/null || true)" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "dry-run: would remove empty directory ${d}"
    else
      rmdir "$d" 2>/dev/null || true
    fi
  fi
}

purge_identity_data() {
  if [[ -d "$IDENTITY_DIR" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "dry-run: would remove identity data directory ${IDENTITY_DIR} (contents not listed)"
    else
      rm -rf "$IDENTITY_DIR"
      echo "removed identity data directory ${IDENTITY_DIR}"
    fi
  else
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "dry-run: identity data directory ${IDENTITY_DIR} already absent"
    fi
  fi
}

MANAGE_SYSTEMD=0
if [[ "$INSTALL_ROOT" == "/" ]] && command -v systemctl >/dev/null 2>&1; then
  MANAGE_SYSTEMD=1
fi

if [[ "$MANAGE_SYSTEMD" -eq 1 ]]; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would stop and disable astranull-agent.service"
    echo "dry-run: would run systemctl daemon-reload after unit removal"
  else
    systemctl stop astranull-agent.service 2>/dev/null || true
    systemctl disable astranull-agent.service 2>/dev/null || true
  fi
fi

remove_file "$SYSTEMD_UNIT"
remove_file "$AGENT_BIN"
remove_file "$AGENT_ENV"

if [[ "$PURGE_DATA" -eq 1 ]]; then
  purge_identity_data
else
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "dry-run: would preserve identity data under ${IDENTITY_DIR}"
  else
    echo "preserved identity data under ${IDENTITY_DIR}"
  fi
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
  remove_dir_if_empty "$AGENT_ENV_DIR"
  if [[ "$MANAGE_SYSTEMD" -eq 1 ]]; then
    systemctl daemon-reload 2>/dev/null || true
  fi
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "dry-run: complete (no secrets read or echoed)"
else
  echo "uninstall complete"
fi

exit 0