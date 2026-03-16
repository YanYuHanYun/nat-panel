#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/YanYuHanYun/nat-panel.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
CLONE_DIR="${CLONE_DIR:-/usr/local/src/nat-panel}"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERROR] Please run this script as root"
    exit 1
  fi
}

detect_os() {
  if [[ -f /etc/debian_version ]]; then
    OS_FAMILY="debian"
    return
  fi
  if [[ -f /etc/redhat-release ]]; then
    OS_FAMILY="rhel"
    return
  fi

  echo "[ERROR] Unsupported OS; only Debian/Ubuntu or CentOS/RHEL are supported"
  exit 1
}

install_git_if_needed() {
  if command -v git >/dev/null 2>&1; then
    echo "[INFO] Git already installed: $(git --version)"
    return
  fi

  echo "[INFO] Git not found; installing..."
  if [[ "${OS_FAMILY}" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y git
  else
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y git
    else
      yum install -y git
    fi
  fi

  echo "[INFO] Git installed: $(git --version)"
}

clone_or_update_repo() {
  local repo_dir_parent
  repo_dir_parent="$(dirname "${CLONE_DIR}")"
  mkdir -p "${repo_dir_parent}"

  if [[ -d "${CLONE_DIR}/.git" ]]; then
    echo "[INFO] Repository already exists at ${CLONE_DIR}; updating..."
    git -C "${CLONE_DIR}" remote set-url origin "${REPO_URL}"
    git -C "${CLONE_DIR}" fetch origin "${REPO_BRANCH}"
    if git -C "${CLONE_DIR}" show-ref --verify --quiet "refs/heads/${REPO_BRANCH}"; then
      git -C "${CLONE_DIR}" checkout "${REPO_BRANCH}"
    else
      git -C "${CLONE_DIR}" checkout -b "${REPO_BRANCH}" "origin/${REPO_BRANCH}"
    fi
    git -C "${CLONE_DIR}" pull --ff-only origin "${REPO_BRANCH}"
    return
  fi

  if [[ -e "${CLONE_DIR}" ]]; then
    echo "[ERROR] ${CLONE_DIR} already exists but is not a Git repository"
    exit 1
  fi

  echo "[INFO] Cloning ${REPO_URL} (${REPO_BRANCH}) to ${CLONE_DIR}"
  git clone --branch "${REPO_BRANCH}" --single-branch "${REPO_URL}" "${CLONE_DIR}"
}

run_deploy() {
  if [[ ! -f "${CLONE_DIR}/deploy.sh" ]]; then
    echo "[ERROR] deploy.sh not found in ${CLONE_DIR}"
    exit 1
  fi

  cd "${CLONE_DIR}"
  echo "[INFO] Running deploy.sh install"
  bash deploy.sh install
}

main() {
  require_root
  detect_os
  install_git_if_needed
  clone_or_update_repo
  run_deploy
}

main "$@"