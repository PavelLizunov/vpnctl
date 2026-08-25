#!/usr/bin/env bash
# scripts/tests/test_vpnctl_backup.sh — regression test suite for vpnctl-backup.sh and vpnctl-backup.service
# Tests AUD-022 deploy key resolution, env loading, dotted paths, archiving, and offsite SSH key usage.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_PATH="${REPO_ROOT}/scripts/vpnctl-backup.sh"
SERVICE_PATH="${REPO_ROOT}/scripts/vpnctl-backup.service"

PASSED=0
FAILED=0

assert_eq() {
    local expected="$1"
    local actual="$2"
    local desc="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  [PASS] $desc"
        PASSED=$((PASSED + 1))
    else
        echo "  [FAIL] $desc (expected '$expected', got '$actual')"
        FAILED=$((FAILED + 1))
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local desc="$3"
    if echo "$haystack" | grep -Fq -- "$needle"; then
        echo "  [PASS] $desc"
        PASSED=$((PASSED + 1))
    else
        echo "  [FAIL] $desc (pattern '$needle' not found)"
        FAILED=$((FAILED + 1))
    fi
}

echo "=== Running vpnctl-backup regression tests ==="

# 1. Test systemd service EnvironmentFile loading
echo "Test 1: Service loads optional /etc/vpnctl/vpnctld.env"
service_content="$(cat "$SERVICE_PATH")"
assert_contains "$service_content" "EnvironmentFile=-/etc/vpnctl/vpnctld.env" "vpnctl-backup.service has EnvironmentFile=-/etc/vpnctl/vpnctld.env"

# Helper to extract and evaluate only the tunables & config resolution from vpnctl-backup.sh
eval_tunables() {
    local env_prefix="$1"
    env -i bash -c "
        ${env_prefix}
        eval \"\$(sed -n '/^## ── tunables/,/^## ── derived/p' '$SCRIPT_PATH' | grep -v '^##')\"
        echo \"DEPLOY_KEY=\$DEPLOY_KEY|DEPLOY_KEY_PUB=\$DEPLOY_KEY_PUB|OFFSITE_KEY=\$OFFSITE_KEY\"
    "
}

# 2. Test default resolution (canonical fallback)
echo "Test 2: Default resolution fallback"
vals=$(eval_tunables "")
assert_contains "$vals" "DEPLOY_KEY=/var/lib/vpnctl/.ssh/id_ed25519" "DEPLOY_KEY defaults to canonical fallback"
assert_contains "$vals" "DEPLOY_KEY_PUB=/var/lib/vpnctl/.ssh/id_ed25519.pub" "DEPLOY_KEY_PUB derived with .pub"
assert_contains "$vals" "OFFSITE_KEY=/var/lib/vpnctl/.ssh/id_ed25519" "OFFSITE_KEY defaults to resolved deploy key"

# 3. Test resolution from VPNCTLD_DEPLOY_KEY
echo "Test 3: Resolution from VPNCTLD_DEPLOY_KEY"
vals=$(eval_tunables "VPNCTLD_DEPLOY_KEY='/custom/deploy/key'")
assert_contains "$vals" "DEPLOY_KEY=/custom/deploy/key" "DEPLOY_KEY resolved from VPNCTLD_DEPLOY_KEY"
assert_contains "$vals" "DEPLOY_KEY_PUB=/custom/deploy/key.pub" "DEPLOY_KEY_PUB derived from VPNCTLD_DEPLOY_KEY"
assert_contains "$vals" "OFFSITE_KEY=/custom/deploy/key" "OFFSITE_KEY defaults to VPNCTLD_DEPLOY_KEY"

# 4. Test dotted custom key path
echo "Test 4: Dotted custom path resolution"
vals=$(eval_tunables "VPNCTLD_DEPLOY_KEY='/var/lib/vpnctl/.ssh/id.custom.ed25519'")
assert_contains "$vals" "DEPLOY_KEY=/var/lib/vpnctl/.ssh/id.custom.ed25519" "DEPLOY_KEY handles dotted custom path"
assert_contains "$vals" "DEPLOY_KEY_PUB=/var/lib/vpnctl/.ssh/id.custom.ed25519.pub" "DEPLOY_KEY_PUB appends .pub to dotted custom path"
assert_contains "$vals" "OFFSITE_KEY=/var/lib/vpnctl/.ssh/id.custom.ed25519" "OFFSITE_KEY inherits dotted custom path"

# 5. Test override precedence
echo "Test 5: Override precedence"
vals=$(eval_tunables "VPNCTLD_DEPLOY_KEY='/base/key' DEPLOY_KEY='/override/key' OFFSITE_KEY='/custom/offsite' DEPLOY_KEY_PUB='/override/pub'")
assert_contains "$vals" "DEPLOY_KEY=/override/key" "DEPLOY_KEY overrides VPNCTLD_DEPLOY_KEY"
assert_contains "$vals" "DEPLOY_KEY_PUB=/override/pub" "DEPLOY_KEY_PUB explicit override preserved"
assert_contains "$vals" "OFFSITE_KEY=/custom/offsite" "OFFSITE_KEY explicit override preserved"

# 6. End-to-end dry run test for archive paths and offsite SSH command key
echo "Test 6: Archive creation with dotted key pair & offsite command execution"
TMP_TEST_DIR=$(mktemp -d /tmp/vpnctl-backup-test.XXXXXX)
trap 'rm -rf "$TMP_TEST_DIR"' EXIT

MOCK_BIN="$TMP_TEST_DIR/bin"
mkdir -p "$MOCK_BIN"

# Mock sqlite3
cat <<'EOF' > "$MOCK_BIN/sqlite3"
#!/usr/bin/env bash
for arg in "$@"; do
    if [[ "$arg" =~ ^\.backup ]]; then
        dest=$(echo "$arg" | sed -E "s/^\.backup '([^']+)'/\1/")
        echo "MOCK SQLITE DB" > "$dest"
        exit 0
    fi
done
exit 0
EOF
chmod +x "$MOCK_BIN/sqlite3"

# Mock age
cat <<'EOF' > "$MOCK_BIN/age"
#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [ -n "$out" ]; then
    echo "ENCRYPTED_MOCK_DATA" > "$out"
    exit 0
fi
exit 1
EOF
chmod +x "$MOCK_BIN/age"

# Mock scp & ssh to record invocations
SCP_LOG="$TMP_TEST_DIR/scp.log"
cat <<EOF > "$MOCK_BIN/scp"
#!/usr/bin/env bash
echo "scp \$@" >> "$SCP_LOG"
exit 0
EOF
chmod +x "$MOCK_BIN/scp"

SSH_LOG="$TMP_TEST_DIR/ssh.log"
cat <<EOF > "$MOCK_BIN/ssh"
#!/usr/bin/env bash
echo "ssh \$@" >> "$SSH_LOG"
exit 0
EOF
chmod +x "$MOCK_BIN/ssh"

# Create fixture files
DB_FILE="$TMP_TEST_DIR/inv.db"
touch "$DB_FILE"
ENV_FILE="$TMP_TEST_DIR/vpnctld.env"
echo "SECRET_ENV_VAR=super_secret_value" > "$ENV_FILE"
ASSETS_DIR="$TMP_TEST_DIR/assets"
mkdir -p "$ASSETS_DIR"
echo "body { color: red; }" > "$ASSETS_DIR/admin.css"
RECIPIENT_FILE="$TMP_TEST_DIR/recipient.txt"
echo "Public key: age1mockrecipientkeyxyz" > "$RECIPIENT_FILE"

# Create dotted custom deploy key pair
KEY_DIR="$TMP_TEST_DIR/keys"
mkdir -p "$KEY_DIR"
DEPLOY_KEY_FILE="$KEY_DIR/id.custom.ed25519"
DEPLOY_KEY_PUB_FILE="$KEY_DIR/id.custom.ed25519.pub"
echo "PRIVATE KEY CONTENT" > "$DEPLOY_KEY_FILE"
echo "PUBLIC KEY CONTENT" > "$DEPLOY_KEY_PUB_FILE"

BACKUP_DEST="$TMP_TEST_DIR/backups"

# Run backup script with custom env
OUTPUT=$(PATH="$MOCK_BIN:$PATH" \
    DB_PATH="$DB_FILE" \
    ENV_FILE="$ENV_FILE" \
    ASSETS_DIR="$ASSETS_DIR" \
    RECIPIENT_FILE="$RECIPIENT_FILE" \
    BACKUP_DIR="$BACKUP_DEST" \
    VPNCTLD_DEPLOY_KEY="$DEPLOY_KEY_FILE" \
    TARGET_HOST="user@remote.primary" \
    OFFSITE_HOST="root@remote.offsite" \
    TMPDIR="$TMP_TEST_DIR/tmp" \
    bash "$SCRIPT_PATH" 2>&1)

assert_contains "$OUTPUT" "ok " "Script completed successfully"

# Verify no secret values were logged
if echo "$OUTPUT" | grep -Fq "super_secret_value"; then
    echo "  [FAIL] Secret leaked in log output!"
    FAILED=$((FAILED + 1))
elif echo "$OUTPUT" | grep -Fq "PRIVATE KEY CONTENT"; then
    echo "  [FAIL] Private key leaked in log output!"
    FAILED=$((FAILED + 1))
else
    echo "  [PASS] No secret logging detected"
    PASSED=$((PASSED + 1))
fi

# Check scp invocation used offsite deploy key
SCP_CALLS=$(cat "$SCP_LOG")
assert_contains "$SCP_CALLS" "scp -O " "Primary LAN scp forces legacy protocol for VM 118"
assert_contains "$SCP_CALLS" "-i $DEPLOY_KEY_FILE" "Offsite scp command used resolved deploy key (-i $DEPLOY_KEY_FILE)"

# Check ssh invocation used offsite deploy key
SSH_CALLS=$(cat "$SSH_LOG")
assert_contains "$SSH_CALLS" "-i $DEPLOY_KEY_FILE" "Offsite ssh command used resolved deploy key (-i $DEPLOY_KEY_FILE)"

# 7. Test explicit OFFSITE_KEY override in commands
echo "Test 7: Explicit OFFSITE_KEY override command execution"
> "$SCP_LOG"
> "$SSH_LOG"
OFFSITE_OVERRIDE_KEY="$KEY_DIR/offsite_special.key"
touch "$OFFSITE_OVERRIDE_KEY"

OUTPUT=$(PATH="$MOCK_BIN:$PATH" \
    DB_PATH="$DB_FILE" \
    ENV_FILE="$ENV_FILE" \
    ASSETS_DIR="$ASSETS_DIR" \
    RECIPIENT_FILE="$RECIPIENT_FILE" \
    BACKUP_DIR="$BACKUP_DEST" \
    VPNCTLD_DEPLOY_KEY="$DEPLOY_KEY_FILE" \
    OFFSITE_KEY="$OFFSITE_OVERRIDE_KEY" \
    TARGET_HOST="user@remote.primary" \
    OFFSITE_HOST="root@remote.offsite" \
    TMPDIR="$TMP_TEST_DIR/tmp" \
    bash "$SCRIPT_PATH" 2>&1)

SCP_CALLS=$(cat "$SCP_LOG")
assert_contains "$SCP_CALLS" "-i $OFFSITE_OVERRIDE_KEY" "Offsite scp command used explicit OFFSITE_KEY override"

SSH_CALLS=$(cat "$SSH_LOG")
assert_contains "$SSH_CALLS" "-i $OFFSITE_OVERRIDE_KEY" "Offsite ssh command used explicit OFFSITE_KEY override"

# 8. Verify tar archive paths include the dotted key pair
echo "Test 8: Verify tar archive contains actual key pair"
TAR_ENTRIES_LOG="$TMP_TEST_DIR/tar_entries.log"
cat <<EOF > "$MOCK_BIN/tar"
#!/usr/bin/env bash
for arg in "\$@"; do
    echo "\$arg" >> "$TAR_ENTRIES_LOG"
done
/usr/bin/tar "\$@"
EOF
chmod +x "$MOCK_BIN/tar"

rm -rf "$BACKUP_DEST"/*
OUTPUT=$(PATH="$MOCK_BIN:$PATH" \
    DB_PATH="$DB_FILE" \
    ENV_FILE="$ENV_FILE" \
    ASSETS_DIR="$ASSETS_DIR" \
    RECIPIENT_FILE="$RECIPIENT_FILE" \
    BACKUP_DIR="$BACKUP_DEST" \
    VPNCTLD_DEPLOY_KEY="$DEPLOY_KEY_FILE" \
    TARGET_HOST="user@remote.primary" \
    OFFSITE_HOST="root@remote.offsite" \
    TMPDIR="$TMP_TEST_DIR/tmp" \
    bash "$SCRIPT_PATH" 2>&1)

TAR_LOG_CONTENT=$(cat "$TAR_ENTRIES_LOG")
assert_contains "$TAR_LOG_CONTENT" "$DEPLOY_KEY_FILE" "Tar archive input contains resolved deploy key"
assert_contains "$TAR_LOG_CONTENT" "$DEPLOY_KEY_PUB_FILE" "Tar archive input contains derived public deploy key"

echo ""
echo "=== Test Summary: $PASSED passed, $FAILED failed ==="
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
