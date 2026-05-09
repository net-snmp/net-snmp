#!/bin/sh

# Install the ENTITY-MIB AgentX subagent on a remote system over SSH.
# Usage: local/install-entity-subagent-remote.sh user@host

set -eu

usage()
{
    printf 'usage: %s user@host\n' "$0" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage

REMOTE=$1
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR" && pwd)

BINARY=$ROOT_DIR/entity_subagent
SERVICE=$ROOT_DIR/entity_subagent.service
REMOTE_TMP=/tmp/entity-subagent-install.$$
REMOTE_BIN=/usr/local/lib/snmpd/entity_subagent
REMOTE_SERVICE=/etc/systemd/system/entity_subagent.service
SERVICE_NAME=entity_subagent.service

[ -f "$BINARY" ] || { printf 'missing binary: %s\n' "$BINARY" >&2; exit 1; }
[ -f "$SERVICE" ] || { printf 'missing service: %s\n' "$SERVICE" >&2; exit 1; }

if ssh "$REMOTE" "test -f '$REMOTE_SERVICE' || systemctl list-unit-files '$SERVICE_NAME' >/dev/null 2>&1"; then
    printf 'existing service found on %s; stopping before upgrade\n' "$REMOTE"
    ssh "$REMOTE" "sudo systemctl stop '$SERVICE_NAME' || true"
    INSTALL_MODE=upgrade
else
    printf 'service not installed on %s; doing first install\n' "$REMOTE"
    INSTALL_MODE=install
fi

printf 'copying files to %s\n' "$REMOTE"
ssh "$REMOTE" "mkdir -p '$REMOTE_TMP'"
scp "$BINARY" "$SERVICE" "$REMOTE:$REMOTE_TMP/"

printf '%s service on %s\n' "$INSTALL_MODE" "$REMOTE"
ssh "$REMOTE" "sudo sh -eu -c '
    install -d -m 0755 /usr/local/lib/snmpd
    install -m 0755 "$REMOTE_TMP/entity_subagent" "$REMOTE_BIN"
    install -m 0644 "$REMOTE_TMP/entity_subagent.service" "$REMOTE_SERVICE"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    systemctl --no-pager --full status "$SERVICE_NAME"
    rm -rf "$REMOTE_TMP"
'"

printf 'installed entity_subagent on %s\n' "$REMOTE"
