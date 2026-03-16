#!/usr/bin/env bash
set -euo pipefail

APP="firewall-api"
INSTALL_DIR="/opt/${APP}"
BIN_PATH="${INSTALL_DIR}/${APP}"
CONFIG_PATH="${INSTALL_DIR}/config.yaml"
SERVICE_FILE="/etc/systemd/system/${APP}.service"
STATE_DIR="/var/lib/${APP}"
DEFAULT_DB_PATH="${STATE_DIR}/state.db"
BACKUP_DIR="${STATE_DIR}/backups"
GO_VERSION="1.25.0"
GO_MIRROR_BASE="https://mirrors.aliyun.com/golang"
GO_PROXY_URL="https://mirrors.aliyun.com/goproxy/,direct"
GO_SUMDB_URL="sum.golang.google.cn"

WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
ACTION="${1:-install}"
TARGET_GOARCH=""
IS_FRESH_INSTALL="false"
PREINSTALL_DB_PATH=""
PREINSTALL_DB_EXISTED="false"
LAST_DB_BACKUP_PREFIX=""

usage() {
  printf '%s\n' \
    'Usage:' \
    '  bash deploy.sh install' \
    '  bash deploy.sh uninstall' \
    '' \
    'Actions:' \
    "  install   Install or update ${APP}" \
    '  uninstall Remove firewall-api and ask whether to delete the database file'
}

prompt_yes_no() {
  local prompt_text="${1}"
  local default_answer="${2:-N}"
  local answer=""

  read -r -p "${prompt_text}" answer
  if [[ -z "${answer}" ]]; then
    answer="${default_answer}"
  fi

  case "${answer}" in
    y|Y|yes|YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

log_header() {
  local action_name="${1:-run}"
  echo "===== ${APP} ${action_name} ====="
  echo "[INFO] Working directory: ${WORK_DIR}"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERROR] Please run as root"
    exit 1
  fi
}

ensure_install_files() {
  cd "${WORK_DIR}"

  if [[ ! -f main.go ]]; then
    echo "[ERROR] main.go not found"
    exit 1
  fi

  if [[ ! -f config.yaml ]]; then
    echo "[ERROR] config.yaml not found"
    exit 1
  fi

  if [[ ! -f go.mod || ! -f go.sum ]]; then
    echo "[ERROR] go.mod or go.sum not found; lock dependencies in the repository first"
    exit 1
  fi
}

detect_os() {
  if [[ -f /etc/redhat-release ]]; then
    OS_FAMILY="rhel"
  elif [[ -f /etc/debian_version ]]; then
    OS_FAMILY="debian"
  else
    echo "[ERROR] Unsupported OS; only Debian/Ubuntu or CentOS/RHEL are supported"
    exit 1
  fi
  echo "[INFO] Detected OS: ${OS_FAMILY}"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      TARGET_GOARCH="amd64"
      ;;
    aarch64|arm64)
      TARGET_GOARCH="arm64"
      ;;
    *)
      echo "[ERROR] Unsupported CPU architecture: $(uname -m)"
      exit 1
      ;;
  esac
  echo "[INFO] Target architecture: ${TARGET_GOARCH}"
}

install_system_deps() {
  echo "[INFO] Installing system dependencies..."
  if [[ "${OS_FAMILY}" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y \
      iptables \
      iptables-persistent \
      ca-certificates \
      curl \
      tar
  else
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y iptables iptables-services ca-certificates curl tar
    else
      yum install -y iptables iptables-services ca-certificates curl tar
    fi

    systemctl enable iptables || true
    systemctl start iptables || true

    if systemctl is-enabled firewalld >/dev/null 2>&1; then
      echo "[WARN] firewalld is enabled and may conflict with iptables rules"
      echo "[WARN] Disable it manually if needed: systemctl disable --now firewalld"
    fi
  fi
}

ensure_kernel_forwarding() {
  echo "[INFO] Enabling kernel IP forwarding..."

  if grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf 2>/dev/null; then
    echo "[INFO] net.ipv4.ip_forward already persisted"
  else
    printf '\nnet.ipv4.ip_forward=1\n' >> /etc/sysctl.conf
  fi

  if grep -q '^net.ipv6.conf.all.forwarding=1$' /etc/sysctl.conf 2>/dev/null; then
    echo "[INFO] net.ipv6.conf.all.forwarding already persisted"
  else
    printf 'net.ipv6.conf.all.forwarding=1\n' >> /etc/sysctl.conf
  fi

  sysctl -w net.ipv4.ip_forward=1
  sysctl -w net.ipv6.conf.all.forwarding=1
  sysctl -p >/dev/null || true

  echo "[INFO] Kernel forwarding status:"
  sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
}

install_go() {
  local go_bin="/usr/local/go/bin/go"
  local arch_name
  local go_tarball
  local download_url
  local temp_dir

  case "${TARGET_GOARCH}" in
    amd64)
      arch_name="amd64"
      ;;
    arm64)
      arch_name="arm64"
      ;;
    *)
      echo "[ERROR] Unsupported Go architecture: ${TARGET_GOARCH}"
      exit 1
      ;;
  esac

  if [[ -x "${go_bin}" ]]; then
    echo "[INFO] Go 已存在: $(${go_bin} version)"
  elif command -v go >/dev/null 2>&1; then
    echo "[INFO] Go 已存在: $(go version)"
  else
    echo "[INFO] Go not found; installing Go ${GO_VERSION} from Aliyun mirror..."
  fi

  if [[ ! -x "${go_bin}" ]] || ! "${go_bin}" version 2>/dev/null | grep -q "go${GO_VERSION}"; then
    temp_dir="$(mktemp -d)"
    go_tarball="go${GO_VERSION}.linux-${arch_name}.tar.gz"
    download_url="${GO_MIRROR_BASE}/${go_tarball}"

    echo "[INFO] Downloading ${download_url}"
    curl -fL --retry 3 --connect-timeout 15 -o "${temp_dir}/${go_tarball}" "${download_url}"

    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${temp_dir}/${go_tarball}"
    rm -rf "${temp_dir}"
  fi

  export PATH="/usr/local/go/bin:${PATH}"
  cat > /etc/profile.d/go-firewall-api.sh <<EOF
export PATH=/usr/local/go/bin:\$PATH
export GOPROXY=${GO_PROXY_URL}
export GOSUMDB=${GO_SUMDB_URL}
EOF
  chmod 644 /etc/profile.d/go-firewall-api.sh

  if ! command -v go >/dev/null 2>&1; then
    echo "[ERROR] Failed to install Go"
    exit 1
  fi

  echo "[INFO] Go 版本: $(go version)"
}

fix_go_env() {
  echo "[INFO] Preparing Go module environment..."
  unset GOPATH || true
  unset GOMODCACHE || true

  export GOPATH=/root/go
  export GOMODCACHE=/root/go/pkg/mod

  mkdir -p "${GOPATH}"
  mkdir -p "${GOMODCACHE}"

  export PATH="/usr/local/go/bin:${PATH}"
  export GOPROXY="${GO_PROXY_URL}"
  export GOSUMDB="${GO_SUMDB_URL}"

  go env -w GOPATH="${GOPATH}"
  go env -w GOMODCACHE="${GOMODCACHE}"
  go env -w GOPROXY="${GO_PROXY_URL}"
  go env -w GOSUMDB="${GO_SUMDB_URL}"

  echo "[INFO] GOPATH=${GOPATH}"
  echo "[INFO] GOMODCACHE=${GOMODCACHE}"
  echo "[INFO] GOPROXY=${GO_PROXY_URL}"
}

prepare_go_modules() {
  echo "[INFO] Downloading and verifying Go dependencies..."
  GOFLAGS="-mod=readonly" go mod download
  go mod verify
}

build_binary() {
  echo "[INFO] Building binary..."
  GOFLAGS="-mod=readonly" GOOS=linux GOARCH="${TARGET_GOARCH}" go build -o "${APP}" .
  chmod +x "${APP}"
}

prepare_dirs() {
  echo "[INFO] Creating installation directories..."
  mkdir -p "${INSTALL_DIR}"
  mkdir -p "${STATE_DIR}"
  mkdir -p "${BACKUP_DIR}"
}

backup_database_if_present() {
  local db_path="${1:-}"
  if [[ -z "${db_path}" || ! -f "${db_path}" ]]; then
    echo "[INFO] No existing database found to back up"
    return
  fi

  mkdir -p "${BACKUP_DIR}"
  LAST_DB_BACKUP_PREFIX="${BACKUP_DIR}/$(date +%Y%m%d-%H%M%S)-state"

  echo "[INFO] Backing up database: ${db_path}"
  cp -f "${db_path}" "${LAST_DB_BACKUP_PREFIX}.db"
  if [[ -f "${db_path}-wal" ]]; then
    cp -f "${db_path}-wal" "${LAST_DB_BACKUP_PREFIX}.db-wal"
  fi
  if [[ -f "${db_path}-shm" ]]; then
    cp -f "${db_path}-shm" "${LAST_DB_BACKUP_PREFIX}.db-shm"
  fi
  echo "[INFO] Database backup saved with prefix: ${LAST_DB_BACKUP_PREFIX}"
}

verify_database_after_start() {
  local db_path="${1:-}"
  if [[ -z "${db_path}" ]]; then
    echo "[WARN] Skip database verification because db_path is empty"
    return
  fi

  if [[ ! -f "${db_path}" ]]; then
    echo "[ERROR] Database file missing after install: ${db_path}"
    if [[ -n "${LAST_DB_BACKUP_PREFIX}" && -f "${LAST_DB_BACKUP_PREFIX}.db" ]]; then
      echo "[ERROR] Latest backup is available at ${LAST_DB_BACKUP_PREFIX}.db"
    fi
    exit 1
  fi

  echo "[INFO] Database file verified: ${db_path}"
  ls -l "${db_path}"
}

install_files() {
  echo "[INFO] Installing application files..."
  cp -f "${APP}" "${BIN_PATH}"

  if [[ -f "${CONFIG_PATH}" ]]; then
    echo "[INFO] Existing config preserved at ${CONFIG_PATH}"
  else
    cp -f config.yaml "${CONFIG_PATH}"
    chmod 600 "${CONFIG_PATH}"
    echo "[INFO] Default config installed to ${CONFIG_PATH}"
  fi

  chmod 755 "${BIN_PATH}"
}

write_service() {
  echo "[INFO] Writing systemd service..."
  cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Firewall API Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_PATH} ${CONFIG_PATH}
Restart=always
RestartSec=3
User=root
Group=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

start_service() {
  echo "[INFO] Reloading and starting service..."
  systemctl daemon-reload
  systemctl enable "${APP}"
  systemctl restart "${APP}"
  sleep 2
  systemctl --no-pager --full status "${APP}" || true
}

stop_service_forcefully() {
  echo "[INFO] Stopping ${APP} service and killing residual processes..."

  systemctl stop "${APP}" 2>/dev/null || true
  systemctl kill "${APP}" --kill-who=all 2>/dev/null || true
  systemctl disable "${APP}" 2>/dev/null || true
  systemctl reset-failed "${APP}" 2>/dev/null || true

  pkill -x "${APP}" 2>/dev/null || true
  if [[ -n "${BIN_PATH}" ]]; then
    pkill -f "${BIN_PATH}" 2>/dev/null || true
  fi

  sleep 1

  if pgrep -x "${APP}" >/dev/null 2>&1; then
    echo "[WARN] Found remaining ${APP} processes after normal stop; forcing SIGKILL"
    pkill -9 -x "${APP}" 2>/dev/null || true
  fi
  if [[ -n "${BIN_PATH}" ]] && pgrep -f "${BIN_PATH}" >/dev/null 2>&1; then
    pkill -9 -f "${BIN_PATH}" 2>/dev/null || true
  fi
}

show_result() {
  echo
  echo "========================================"
  echo "[OK] Install complete"
  echo "Binary: ${BIN_PATH}"
  echo "Config: ${CONFIG_PATH}"
  echo "State dir: /var/lib/${APP}"
  echo "Service: ${APP}"
  echo
  echo "Common commands:"
  echo "  systemctl status ${APP}"
  echo "  systemctl restart ${APP}"
  echo "  journalctl -u ${APP} -f"
  echo "========================================"
}

save_firewall_rules() {
  if [[ "${OS_FAMILY}" == "debian" ]]; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
  else
    mkdir -p /etc/sysconfig
    iptables-save > /etc/sysconfig/iptables
    ip6tables-save > /etc/sysconfig/ip6tables
    systemctl restart iptables || true
  fi
}

clear_firewall_rules_interactive() {
  if ! prompt_yes_no "[WARN] Clear all existing IPv4/IPv6 firewall rules now? [y/N]: " "N"; then
    echo "[INFO] Existing firewall rules preserved"
    return
  fi

  clear_firewall_rules
}

clear_firewall_rules() {
  echo "[WARN] Flushing current firewall rules..."

  iptables -F || true
  iptables -X || true
  iptables -t nat -F || true
  iptables -t nat -X || true
  iptables -t mangle -F || true
  iptables -t mangle -X || true
  iptables -P INPUT ACCEPT || true
  iptables -P FORWARD ACCEPT || true
  iptables -P OUTPUT ACCEPT || true

  ip6tables -F || true
  ip6tables -X || true
  ip6tables -t nat -F || true
  ip6tables -t nat -X || true
  ip6tables -t mangle -F || true
  ip6tables -t mangle -X || true
  ip6tables -P INPUT ACCEPT || true
  ip6tables -P FORWARD ACCEPT || true
  ip6tables -P OUTPUT ACCEPT || true

  save_firewall_rules
  echo "[INFO] Firewall rules cleared and saved"
}

detect_existing_installation() {
  if [[ -f "${BIN_PATH}" ]] || [[ -f "${CONFIG_PATH}" ]] || [[ -f "${SERVICE_FILE}" ]] || systemctl list-unit-files 2>/dev/null | grep -q "^${APP}\.service"; then
    IS_FRESH_INSTALL="false"
  else
    IS_FRESH_INSTALL="true"
  fi
  echo "[INFO] Fresh install: ${IS_FRESH_INSTALL}"
}

read_db_path() {
  local source_config="${CONFIG_PATH}"
  if [[ ! -f "${source_config}" ]]; then
    echo "${DEFAULT_DB_PATH}"
    return
  fi

  local db_path
  db_path="$(sed -n 's/^\s*db_path:\s*"\([^"]*\)"\s*$/\1/p' "${source_config}" | head -n 1)"
  if [[ -z "${db_path}" ]]; then
    echo "${DEFAULT_DB_PATH}"
    return
  fi

  echo "${db_path}"
}

uninstall_app() {
  local db_path
  detect_os
  db_path="$(read_db_path)"

  if ! prompt_yes_no "[WARN] Uninstall ${APP} from this server? [y/N]: " "N"; then
    echo "[INFO] Uninstall cancelled"
    exit 0
  fi

  echo "[INFO] Stopping and uninstalling service..."
  stop_service_forcefully
  clear_firewall_rules

  rm -f "${SERVICE_FILE}"
  systemctl daemon-reload
  systemctl reset-failed "${APP}" 2>/dev/null || true

  echo "[INFO] Removing installation directory..."
  rm -rf "${INSTALL_DIR}"

  if pgrep -x "${APP}" >/dev/null 2>&1 || pgrep -f "/opt/${APP}/${APP}" >/dev/null 2>&1; then
    echo "[ERROR] ${APP} process is still running after uninstall"
    ps -ef | grep "${APP}" | grep -v grep || true
    exit 1
  fi

  if [[ -f "${db_path}" ]]; then
    read -r -p "[WARN] Delete database file ${db_path} and its WAL/SHM files? [y/N]: " delete_db
    case "${delete_db}" in
      y|Y|yes|YES)
        rm -f "${db_path}" "${db_path}-wal" "${db_path}-shm"
        rmdir "$(dirname "${db_path}")" 2>/dev/null || true
        echo "[INFO] Database files deleted"
        ;;
      *)
        echo "[INFO] Database file preserved at ${db_path}"
        ;;
    esac
  else
    echo "[INFO] Database file not found at ${db_path}"
  fi

  echo "[OK] Uninstall complete"
}

install_app() {
  local db_path

  if ! prompt_yes_no "[INFO] Install or update ${APP} on this server? [Y/n]: " "Y"; then
    echo "[INFO] Install cancelled"
    exit 0
  fi

  ensure_install_files
  detect_os
  detect_arch
  detect_existing_installation
  db_path="$(read_db_path)"
  PREINSTALL_DB_PATH="${db_path}"
  if [[ -f "${db_path}" ]]; then
    PREINSTALL_DB_EXISTED="true"
  fi
  install_system_deps
  ensure_kernel_forwarding
  install_go
  fix_go_env
  prepare_go_modules
  build_binary
  prepare_dirs
  backup_database_if_present "${db_path}"
  install_files
  write_service
  start_service
  verify_database_after_start "${db_path}"
  if [[ "${IS_FRESH_INSTALL}" == "true" ]]; then
    clear_firewall_rules_interactive
  else
    echo "[INFO] Existing installation detected; skipping firewall clear prompt"
  fi
  show_result
}

case "${ACTION}" in
  install)
    require_root
    log_header "install/update"
    install_app
    ;;
  uninstall)
    require_root
    log_header "uninstall"
    uninstall_app
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "[ERROR] Unsupported action: ${ACTION}"
    usage
    exit 1
    ;;
esac