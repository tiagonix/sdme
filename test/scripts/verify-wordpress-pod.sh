#!/usr/bin/env bash
set -uo pipefail

# verify-wordpress-pod.sh - end-to-end verification of WordPress + MySQL + Nginx
# Run as root. Requires a base-fs imported (e.g. ubuntu).
#
# Deploys a WordPress + MySQL + Nginx stack as a single kube pod and verifies:
#   - MySQL accepts connections
#   - WordPress installs and serves pages
#   - Nginx reverse-proxies to WordPress
#   - XML-RPC post creation and REST API read-back through Nginx

SDME="${SDME:-sdme}"
BASE_FS="${BASE_FS:-ubuntu}"
DATADIR="/var/lib/sdme"
KEEP=0
REPORT_DIR="."

POD_NAME="wp-pod"
YAML_FILE="test/kube/wordpress-stack.yaml"

# Timeouts (seconds)
TIMEOUT_CREATE=600
TIMEOUT_BOOT=120
TIMEOUT_MYSQL=90
TIMEOUT_WORDPRESS=60
TIMEOUT_NGINX=30

# Result tracking
declare -A RESULTS
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# State flags
POD_CREATED=0
POD_RUNNING=0

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

End-to-end verification of WordPress + MySQL + Nginx kube pod.
Must be run as root.

Options:
  --base-fs NAME   Base rootfs to use (default: ubuntu)
  --keep           Do not remove test artifacts on exit
  --report-dir DIR Write report to DIR (default: .)
  --help           Show help
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --base-fs)
                shift
                BASE_FS="$1"
                ;;
            --keep)
                KEEP=1
                ;;
            --report-dir)
                shift
                REPORT_DIR="$1"
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                echo "unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
        shift
    done
}

record() {
    local test_name="$1" result="$2" msg="${3:-}"
    RESULTS["$test_name"]="$result|$msg"
    case "$result" in
        PASS) ((PASS_COUNT++)); echo "  [PASS] $test_name${msg:+: $msg}" ;;
        FAIL) ((FAIL_COUNT++)); echo "  [FAIL] $test_name${msg:+: $msg}" ;;
        SKIP) ((SKIP_COUNT++)); echo "  [SKIP] $test_name${msg:+: $msg}" ;;
    esac
}

result_status() {
    local val="${RESULTS[$1]}"
    echo "${val%%|*}"
}

result_msg() {
    local val="${RESULTS[$1]}"
    echo "${val#*|}"
}

# --- Cleanup ------------------------------------------------------------------

cleanup() {
    if [[ $KEEP -eq 1 ]]; then
        echo "==> Keeping test artifacts (--keep)"
        return
    fi
    echo "==> Cleaning up..."
    "$SDME" kube delete "$POD_NAME" --force 2>/dev/null || true
}

trap cleanup EXIT INT TERM

# --- Phase 1: Create kube pod ------------------------------------------------

test_create_pod() {
    local test_name="create/kube"
    echo "--- $test_name: creating kube pod ---"

    if [[ ! -f "$YAML_FILE" ]]; then
        record "$test_name" FAIL "YAML file not found: $YAML_FILE"
        return
    fi

    local output
    if output=$(timeout "$TIMEOUT_CREATE" "$SDME" kube create -f "$YAML_FILE" --base-fs "$BASE_FS" -v 2>&1); then
        record "$test_name" PASS
        POD_CREATED=1
    else
        record "$test_name" FAIL "$output"
    fi
}

# --- Phase 2: Inject nginx reverse proxy config ------------------------------

test_setup_nginx_config() {
    local test_name="setup/nginx-config"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    echo "--- $test_name: writing nginx reverse proxy config ---"
    local conf_dir="$DATADIR/containers/$POD_NAME/upper/oci/apps/nginx-unprivileged/root/etc/nginx/conf.d"
    mkdir -p "$conf_dir"

    cat > "$conf_dir/default.conf" <<'NGINXEOF'
server {
    listen 8080;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINXEOF

    if [[ -f "$conf_dir/default.conf" ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "could not write nginx config"
    fi
}

# --- Phase 3: Write Python validation script ----------------------------------

test_setup_validate_script() {
    local test_name="setup/validate-script"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    echo "--- $test_name: writing validation script ---"
    local script_dir="$DATADIR/containers/$POD_NAME/upper/opt/sdme-test"
    mkdir -p "$script_dir"

    cat > "$script_dir/validate.py" <<'PYEOF'
#!/usr/bin/env python3
"""WordPress validation: install, create post via XML-RPC, read via REST API."""

import http.client
import json
import sys
import urllib.parse
import xml.etree.ElementTree as ET

TEST_MARKER = sys.argv[1] if len(sys.argv) > 1 else "sdme-test"

WP_HOST = "127.0.0.1"
WP_PORT = 80
NGINX_PORT = 8080
WP_USER = "admin"
WP_PASS = "adminpass123!"
WP_EMAIL = "admin@test.local"
WP_TITLE = "sdme test site"


def result(name, passed, msg=""):
    status = "PASS" if passed else "FAIL"
    print(f"RESULT {name} {status} {msg}")
    return passed


def wp_install():
    """Install WordPress via the web installer."""
    conn = http.client.HTTPConnection(WP_HOST, WP_PORT, timeout=30)
    params = urllib.parse.urlencode({
        "weblog_title": WP_TITLE,
        "user_name": WP_USER,
        "admin_password": WP_PASS,
        "admin_password2": WP_PASS,
        "admin_email": WP_EMAIL,
        "blog_public": "0",
        "Submit": "Install WordPress",
    })
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    conn.request("POST", "/wp-admin/install.php?step=2", body=params, headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="replace")
    conn.close()

    ok = resp.status == 200 and ("Success" in body or "Already" in body or "already installed" in body.lower())
    return result("validate/wp-install", ok, f"status={resp.status}")


def xmlrpc_create_post(marker):
    """Create a post via XML-RPC through Nginx."""
    import base64
    auth = base64.b64encode(f"{WP_USER}:{WP_PASS}".encode()).decode()

    post_title = f"Test Post {marker}"
    post_content = f"This is a test post created by sdme verification ({marker})."

    xml_body = f"""<?xml version="1.0"?>
<methodCall>
  <methodName>wp.newPost</methodName>
  <params>
    <param><value><int>1</int></value></param>
    <param><value><string>{WP_USER}</string></value></param>
    <param><value><string>{WP_PASS}</string></value></param>
    <param><value><struct>
      <member>
        <name>post_title</name>
        <value><string>{post_title}</string></value>
      </member>
      <member>
        <name>post_content</name>
        <value><string>{post_content}</string></value>
      </member>
      <member>
        <name>post_status</name>
        <value><string>publish</string></value>
      </member>
    </struct></value></param>
  </params>
</methodCall>"""

    conn = http.client.HTTPConnection(WP_HOST, NGINX_PORT, timeout=30)
    headers = {
        "Content-Type": "text/xml",
        "Authorization": f"Basic {auth}",
    }
    conn.request("POST", "/xmlrpc.php", body=xml_body, headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="replace")
    conn.close()

    try:
        root = ET.fromstring(body)
        value = root.find(".//value/string")
        if value is not None:
            post_id = value.text
            return result("validate/xmlrpc-create-post", True, f"post_id={post_id}"), post_id
        # Check for int response (some WP versions return int post ID)
        value = root.find(".//value/int")
        if value is not None:
            post_id = value.text
            return result("validate/xmlrpc-create-post", True, f"post_id={post_id}"), post_id
        # Check for fault
        fault = root.find(".//fault")
        if fault is not None:
            fault_str = ET.tostring(fault, encoding="unicode")
            return result("validate/xmlrpc-create-post", False, f"fault: {fault_str[:200]}"), None
    except ET.ParseError as e:
        return result("validate/xmlrpc-create-post", False, f"xml parse error: {e}"), None

    return result("validate/xmlrpc-create-post", False, f"unexpected response: {body[:200]}"), None


def rest_api_read(marker):
    """Read posts via REST API through Nginx."""
    conn = http.client.HTTPConnection(WP_HOST, NGINX_PORT, timeout=30)
    conn.request("GET", "/wp-json/wp/v2/posts")
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="replace")
    conn.close()

    if resp.status != 200:
        result("validate/rest-api-read-post", False, f"status={resp.status}")
        return result("validate/post-title-match", False, "skipped: REST API failed")

    try:
        posts = json.loads(body)
    except json.JSONDecodeError as e:
        result("validate/rest-api-read-post", False, f"json error: {e}")
        return result("validate/post-title-match", False, "skipped: JSON parse failed")

    if not isinstance(posts, list) or len(posts) == 0:
        result("validate/rest-api-read-post", False, "no posts returned")
        return result("validate/post-title-match", False, "skipped: no posts")

    result("validate/rest-api-read-post", True, f"found {len(posts)} post(s)")

    # Check if any post title contains the marker
    for post in posts:
        title = post.get("title", {}).get("rendered", "")
        if marker in title:
            return result("validate/post-title-match", True, f"title={title}")

    titles = [p.get("title", {}).get("rendered", "") for p in posts]
    return result("validate/post-title-match", False, f"marker '{marker}' not in titles: {titles}")


def main():
    if not wp_install():
        result("validate/xmlrpc-create-post", False, "skipped: install failed")
        result("validate/rest-api-read-post", False, "skipped: install failed")
        result("validate/post-title-match", False, "skipped: install failed")
        return 1

    ok, post_id = xmlrpc_create_post(TEST_MARKER)
    if not ok:
        result("validate/rest-api-read-post", False, "skipped: post creation failed")
        result("validate/post-title-match", False, "skipped: post creation failed")
        return 1

    rest_api_read(TEST_MARKER)
    return 0


if __name__ == "__main__":
    sys.exit(main())
PYEOF

    if [[ -f "$script_dir/validate.py" ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "could not write validation script"
    fi
}

# --- Phase 4: Start and check services ---------------------------------------

test_start_pod() {
    local test_name="start/pod"
    if [[ $POD_CREATED -eq 0 ]]; then
        record "$test_name" SKIP "pod not created"
        return
    fi

    echo "--- $test_name: starting pod ---"
    local output
    if output=$(timeout "$TIMEOUT_BOOT" "$SDME" start "$POD_NAME" -t 120 -v 2>&1); then
        record "$test_name" PASS
        POD_RUNNING=1
        echo "    waiting 10s for services to settle..."
        sleep 10
    else
        record "$test_name" FAIL "$output"
    fi
}

test_service_active() {
    local service_name="$1" test_name="$2"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    echo "--- $test_name: checking service ---"
    local output
    if output=$("$SDME" exec "$POD_NAME" -- /usr/bin/systemctl is-active "sdme-oci-${service_name}.service" 2>&1) && \
       [[ "$output" == *"active"* ]]; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "$output"
    fi
}

test_ready_mysql() {
    local test_name="ready/mysql"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    echo "--- $test_name: waiting for MySQL (up to ${TIMEOUT_MYSQL}s) ---"
    if "$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket,sys,time
end=time.time()+${TIMEOUT_MYSQL}
while time.time()<end:
 try: s=socket.create_connection(('127.0.0.1',3306),2); s.close(); sys.exit(0)
 except: time.sleep(3)
sys.exit(1)" 2>/dev/null; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "port 3306 not listening after ${TIMEOUT_MYSQL}s"
    fi
}

test_ready_wordpress() {
    local test_name="ready/wordpress"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi
    if [[ "$(result_status "ready/mysql")" != "PASS" ]]; then
        record "$test_name" SKIP "mysql not ready"
        return
    fi

    echo "--- $test_name: waiting for WordPress (up to ${TIMEOUT_WORDPRESS}s) ---"
    if "$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket,sys,time
end=time.time()+${TIMEOUT_WORDPRESS}
while time.time()<end:
 try: s=socket.create_connection(('127.0.0.1',80),2); s.close(); sys.exit(0)
 except: time.sleep(3)
sys.exit(1)" 2>/dev/null; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "port 80 not listening after ${TIMEOUT_WORDPRESS}s"
    fi
}

test_ready_nginx() {
    local test_name="ready/nginx"
    if [[ $POD_RUNNING -eq 0 ]]; then
        record "$test_name" SKIP "pod not running"
        return
    fi

    echo "--- $test_name: waiting for Nginx (up to ${TIMEOUT_NGINX}s) ---"
    if "$SDME" exec "$POD_NAME" -- /usr/bin/python3 -c "
import socket,sys,time
end=time.time()+${TIMEOUT_NGINX}
while time.time()<end:
 try: s=socket.create_connection(('127.0.0.1',8080),2); s.close(); sys.exit(0)
 except: time.sleep(3)
sys.exit(1)" 2>/dev/null; then
        record "$test_name" PASS
    else
        record "$test_name" FAIL "port 8080 not listening after ${TIMEOUT_NGINX}s"
    fi
}

# --- Phase 5: Validate WordPress through Nginx --------------------------------

test_validate_wordpress() {
    if [[ $POD_RUNNING -eq 0 ]]; then
        for t in validate/wp-install validate/xmlrpc-create-post validate/rest-api-read-post validate/post-title-match; do
            record "$t" SKIP "pod not running"
        done
        return
    fi
    if [[ "$(result_status "ready/wordpress")" != "PASS" || "$(result_status "ready/nginx")" != "PASS" ]]; then
        for t in validate/wp-install validate/xmlrpc-create-post validate/rest-api-read-post validate/post-title-match; do
            record "$t" SKIP "services not ready"
        done
        return
    fi

    local test_marker="sdme-$(date +%s)"
    echo "--- validate: running WordPress validation (marker=$test_marker) ---"

    local output
    output=$("$SDME" exec "$POD_NAME" -- /usr/bin/python3 /opt/sdme-test/validate.py "$test_marker" 2>&1)
    local rc=$?

    echo "$output"

    # Parse RESULT lines from the Python script output
    local found_results=0
    while IFS= read -r line; do
        if [[ "$line" == RESULT\ * ]]; then
            found_results=1
            local name status msg
            name=$(echo "$line" | awk '{print $2}')
            status=$(echo "$line" | awk '{print $3}')
            msg=$(echo "$line" | cut -d' ' -f4-)
            record "$name" "$status" "$msg"
        fi
    done <<< "$output"

    if [[ $found_results -eq 0 ]]; then
        echo "    no RESULT lines found in output"
        for t in validate/wp-install validate/xmlrpc-create-post validate/rest-api-read-post validate/post-title-match; do
            if [[ -z "${RESULTS[$t]+x}" ]]; then
                record "$t" FAIL "no output from validation script (rc=$rc)"
            fi
        done
    fi
}

# --- Report -------------------------------------------------------------------

generate_report() {
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local report="$REPORT_DIR/verify-wordpress-pod-$ts.md"

    mkdir -p "$REPORT_DIR"

    {
        echo "# sdme WordPress Pod Verification Report"
        echo ""
        echo "## System Info"
        echo ""
        echo "| Field | Value |"
        echo "|-------|-------|"
        echo "| Date | $(date -Iseconds) |"
        echo "| Hostname | $(hostname) |"
        echo "| Kernel | $(uname -r) |"
        echo "| systemd | $(systemctl --version | head -1) |"
        local sdme_ver
        sdme_ver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml 2>/dev/null || echo unknown)
        echo "| sdme | $sdme_ver |"
        echo "| Base FS | $BASE_FS |"
        echo ""

        echo "## Summary"
        echo ""
        local total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
        echo "| Result | Count |"
        echo "|--------|-------|"
        echo "| PASS | $PASS_COUNT |"
        echo "| FAIL | $FAIL_COUNT |"
        echo "| SKIP | $SKIP_COUNT |"
        echo "| Total | $total |"
        echo ""

        echo "## Results"
        echo ""
        echo "| Test | Result |"
        echo "|------|--------|"
        for test_name in \
            create/kube setup/nginx-config setup/validate-script \
            start/pod service/mysql service/wordpress service/nginx \
            ready/mysql ready/wordpress ready/nginx \
            validate/wp-install validate/xmlrpc-create-post \
            validate/rest-api-read-post validate/post-title-match; do
            if [[ -n "${RESULTS[$test_name]+x}" ]]; then
                echo "| $test_name | $(result_status "$test_name") |"
            fi
        done
        echo ""

        # Detailed failures
        local has_failures=0
        for key in "${!RESULTS[@]}"; do
            if [[ "$(result_status "$key")" == "FAIL" ]]; then
                has_failures=1
                break
            fi
        done

        if [[ $has_failures -eq 1 ]]; then
            echo "## Failures"
            echo ""
            for key in $(echo "${!RESULTS[@]}" | tr ' ' '\n' | sort); do
                if [[ "$(result_status "$key")" == "FAIL" ]]; then
                    local msg
                    msg=$(result_msg "$key")
                    echo "### $key"
                    echo ""
                    echo '```'
                    echo "$msg"
                    echo '```'
                    echo ""
                fi
            done
        fi
    } > "$report"

    echo "Report: $report"
}

# --- Main ---------------------------------------------------------------------

main() {
    parse_args "$@"

    if [[ $EUID -ne 0 ]]; then
        echo "error: must be run as root" >&2
        exit 1
    fi

    if [[ ! -d "$DATADIR/fs/$BASE_FS" ]]; then
        echo "error: base rootfs '$BASE_FS' not found; import it first:" >&2
        echo "  sdme fs import docker.io/$BASE_FS:latest -n $BASE_FS" >&2
        exit 1
    fi

    echo "=== sdme WordPress pod verification ==="
    echo "base-fs: $BASE_FS"
    echo "pod:     $POD_NAME"
    echo ""

    # Phase 1: Create
    test_create_pod

    # Phase 2: Inject nginx config
    test_setup_nginx_config

    # Phase 3: Write validation script
    test_setup_validate_script

    # Phase 4: Start and check services
    test_start_pod
    test_service_active "mysql" "service/mysql"
    test_service_active "wordpress" "service/wordpress"
    test_service_active "nginx-unprivileged" "service/nginx"

    # Readiness checks
    test_ready_mysql
    test_ready_wordpress
    test_ready_nginx

    # Phase 5: Validate WordPress
    test_validate_wordpress

    echo ""
    echo "=== Results ==="
    echo "Total: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped"

    # Phase 6: Report
    generate_report

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
