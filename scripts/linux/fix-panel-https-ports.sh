#!/usr/bin/env bash
set -euo pipefail

readonly ENV_FILE="/etc/nodepanel/panel.env"
readonly SERVICE_NAME="nodepanel-panel.service"
readonly TARGET_URLS="http://0.0.0.0:80;https://0.0.0.0:443"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Please run this script as root." >&2
    exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing environment file: $ENV_FILE" >&2
    exit 1
fi

backup_file="${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$ENV_FILE" "$backup_file"

temp_file="$(mktemp)"
trap 'rm -f "$temp_file"' EXIT

awk -v target_urls="$TARGET_URLS" '
    BEGIN { updated = 0 }
    /^ASPNETCORE_URLS=/ {
        print "ASPNETCORE_URLS=\"" target_urls "\""
        updated = 1
        next
    }
    /^Panel__AutoRestartOnHttpsChange=/ {
        next
    }
    { print }
    END {
        if (!updated) {
            print "ASPNETCORE_URLS=\"" target_urls "\""
        }
    }
' "$ENV_FILE" > "$temp_file"

cat "$temp_file" > "$ENV_FILE"

systemctl restart "$SERVICE_NAME"

echo "Updated $ENV_FILE"
echo "Backup: $backup_file"
echo "Current listener:"
grep '^ASPNETCORE_URLS=' "$ENV_FILE" || true
echo
systemctl --no-pager --full status "$SERVICE_NAME" || true
