#!/usr/bin/env bash
# lib.sh - shared test helpers for sdme integration tests
#
# Source this from verify-*.sh scripts. Provides:
#   - build_and_install: build sdme and install to PATH
#   - ensure_sdme: verify sdme is in PATH and matches the repo version
#   - ensure_root: check we're running as root
#   - ensure_base_fs: import a base rootfs if not already present
#   - cleanup_prefix: remove all containers and rootfs matching a prefix
#   - ok/fail/skipped: result tracking with summary
#   - stop_container/cleanup_container: container lifecycle helpers
#
# Convention: every test script uses a unique prefix for all artifacts
# (containers, rootfs, pods). The prefix is cleaned on startup so tests
# are idempotent and don't interfere with each other or user data.

SDME="${SDME:-sdme}"
VERBOSE="${VERBOSE:-}"
VFLAG=""
if [[ -n "$VERBOSE" ]]; then
    VFLAG="-v"
fi

# Resolve the repo root (two levels up from test/scripts/).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Result counters.
_pass=0
_fail=0
_skip=0

ok() {
    echo "  [PASS] $1"
    ((_pass++)) || true
}

fail() {
    echo "  [FAIL] $1"
    ((_fail++)) || true
}

skipped() {
    echo "  [SKIP] $1"
    ((_skip++)) || true
}

print_summary() {
    local total=$((_pass + _fail + _skip))
    echo ""
    echo "Results: $_pass passed, $_fail failed, $_skip skipped (total $total)"
    if [[ $_fail -gt 0 ]]; then
        return 1
    fi
    return 0
}

# -- Build and install ---------------------------------------------------------

build_and_install() {
    echo "==> Building sdme..."
    (cd "$REPO_ROOT" && cargo build --release --quiet) || {
        echo "error: cargo build failed" >&2
        exit 1
    }
    local bin="$REPO_ROOT/target/release/sdme"
    if [[ ! -x "$bin" ]]; then
        echo "error: $bin not found after build" >&2
        exit 1
    fi

    local dest
    dest=$(command -v sdme 2>/dev/null || echo "/usr/local/bin/sdme")

    # Only copy if binary differs.
    if ! cmp -s "$bin" "$dest" 2>/dev/null; then
        echo "==> Installing sdme to $dest"
        rm -f "$dest" 2>/dev/null || true
        cp "$bin" "$dest"
    fi

    echo "==> sdme $(sdme --version 2>&1 | awk '{print $2}')"
}

# -- Preflight checks ---------------------------------------------------------

ensure_sdme() {
    if ! command -v "$SDME" &>/dev/null; then
        echo "error: sdme not found in PATH; run build_and_install first" >&2
        exit 1
    fi
}

ensure_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "error: must run as root" >&2
        exit 1
    fi
}

# Import a base rootfs if it doesn't exist. Idempotent (OCI cache makes
# re-imports fast).
#   ensure_base_fs <name> <image>
ensure_base_fs() {
    local name="$1" image="$2"
    if sdme fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$name"; then
        return 0
    fi
    echo "==> Importing base rootfs '$name' from $image"
    if ! sdme fs import "$name" "$image" -v --install-packages=yes -f 2>&1; then
        echo "error: failed to import $name" >&2
        return 1
    fi
}

# -- Cleanup helpers -----------------------------------------------------------

# Stop and remove a single container.
stop_container() {
    timeout 30 "$SDME" stop "$1" 2>/dev/null || \
        timeout 30 "$SDME" stop --term "$1" 2>/dev/null || true
}

cleanup_container() {
    stop_container "$1"
    "$SDME" rm -f "$1" 2>/dev/null || true
}

# Remove all containers, rootfs, and pods matching a prefix.
#   cleanup_prefix <prefix>
cleanup_prefix() {
    local prefix="$1"
    local names

    # Stop and remove containers.
    names=$($SDME ps 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${prefix}" || true)
    for name in $names; do
        cleanup_container "$name"
    done

    # Remove rootfs (including kube- prefixed rootfs for kube containers).
    names=$($SDME fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -E "^(${prefix}|kube-${prefix})" || true)
    for name in $names; do
        $SDME fs rm -f "$name" 2>/dev/null || true
    done

    # Remove pods.
    names=$($SDME pod ls 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${prefix}" || true)
    for name in $names; do
        $SDME pod rm -f "$name" 2>/dev/null || true
    done

    # Remove kube secrets and configmaps.
    names=$($SDME kube secret ls 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${prefix}" || true)
    for name in $names; do
        $SDME kube secret rm "$name" 2>/dev/null || true
    done
    names=$($SDME kube configmap ls 2>/dev/null | awk 'NR>1 {print $1}' | grep "^${prefix}" || true)
    for name in $names; do
        $SDME kube configmap rm "$name" 2>/dev/null || true
    done
}

# Check if a rootfs exists.
fs_exists() {
    $SDME fs ls 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$1"
}

# Derive OCI service name from image reference.
# e.g. "docker.io/nginxinc/nginx-unprivileged" -> "sdme-oci-nginx-unprivileged.service"
oci_service_name() {
    local image="${1%%:*}"
    local last="${image##*/}"
    local name="${last//_/-}"
    echo "sdme-oci-${name}.service"
}
