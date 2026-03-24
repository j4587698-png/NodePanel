#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMMON_CANDIDATES=(
    "$SCRIPT_DIR/lib/nodepanel-common.sh"
    "$SCRIPT_DIR/nodepanel-common.sh"
    "/usr/local/lib/nodepanel/nodepanel-common.sh"
)

for candidate in "${COMMON_CANDIDATES[@]}"; do
    if [[ -f "$candidate" ]]; then
        # shellcheck source=/dev/null
        source "$candidate"
        break
    fi
done

if [[ "${NODEPANEL_COMMON_LOADED:-0}" != "1" ]]; then
    printf 'Failed to load nodepanel-common.sh\n' >&2
    exit 1
fi

readonly DISPLAY_NAME="NodePanel Service"
readonly SYSTEMD_NAME="nodepanel-service"
readonly INSTALL_ROOT="/usr/local/nodepanel-service"
readonly APP_DIR="${INSTALL_ROOT}/app"
readonly DATA_DIR="${INSTALL_ROOT}/data"
readonly CERT_DIR="${DATA_DIR}/certificates"
readonly BIN_PATH="/usr/local/bin/nodepanel-service"
readonly COMMON_INSTALL_DIR="/usr/local/lib/nodepanel"
readonly ENV_DIR="/etc/nodepanel"
readonly ENV_FILE="${ENV_DIR}/service.env"
readonly UNIT_FILE="/etc/systemd/system/${SYSTEMD_NAME}.service"
readonly SYSTEM_USER="nodepanel-service"
readonly SYSTEM_GROUP="nodepanel-service"
readonly EXECUTABLE_NAME="NodePanel.Service"
readonly DLL_NAME="NodePanel.Service.dll"
readonly LAUNCHER_PATH="${INSTALL_ROOT}/run.sh"
readonly SELF_SCRIPT_SOURCE="$(np_abs_path "${BASH_SOURCE[0]}")"
readonly COMMON_SCRIPT_SOURCE="$(np_abs_path "${NODEPANEL_COMMON_SOURCE}")"
readonly PACKAGE_PREFIX="nodepanel-service"
readonly DEFAULT_GITHUB_REPO="${NODEPANEL_DEFAULT_GITHUB_REPO:-}"
readonly COLOR_RED=$'\033[0;31m'
readonly COLOR_GREEN=$'\033[0;32m'
readonly COLOR_YELLOW=$'\033[0;33m'
readonly COLOR_CYAN=$'\033[0;36m'
readonly COLOR_PLAIN=$'\033[0m'

SERVICE_PANEL_URL=""
SERVICE_NODE_ID=""
SERVICE_ACCESS_TOKEN=""
SERVICE_ASPNETCORE_URLS=""
SERVICE_SOURCE_ARG=""
SERVICE_GITHUB_REPO=""
SERVICE_GITHUB_TAG=""
SERVICE_PACKAGE_RID=""
SAVED_PACKAGE_GITHUB_REPO=""
SAVED_PACKAGE_RID=""

usage() {
    cat <<'EOF'
Usage:
  nodepanel-service.sh                         (interactive menu)
  nodepanel-service.sh install [package_dir|package.tar.gz|package_url|owner/repo|owner/repo@tag] [options]
  nodepanel-service.sh update [package_dir|package.tar.gz|package_url|owner/repo|owner/repo@tag] [options]
  nodepanel-service.sh configure [options]
  nodepanel-service.sh start
  nodepanel-service.sh stop
  nodepanel-service.sh restart
  nodepanel-service.sh status
  nodepanel-service.sh log [-f] [lines]
  nodepanel-service.sh enable
  nodepanel-service.sh disable
  nodepanel-service.sh uninstall [--purge]

Options:
  --panel URL
  --panel-base-url URL
  --panel-url URL
  --control-plane-url URL
  --node-id ID
  --access-token TOKEN
  --control-plane-access-token TOKEN
  --aspnetcore-urls URLS
  --service-urls URLS
  --github-repo OWNER/REPO
  --version TAG
  --tag TAG
  --rid RID

Examples:
  bash install.sh install
  bash install.sh install --panel https://panel.example.com --node-id node-001
  bash install.sh install owner/repo --panel https://panel.example.com --node-id node-001
  bash install.sh install v1.2.3 --github-repo owner/repo --panel https://panel.example.com --node-id node-001
  bash install.sh install https://downloads.example.com/nodepanel-service-linux-x64.tar.gz --panel http://127.0.0.1 --node-id node-001
  nodepanel-service update /tmp/nodepanel-service-linux-x64.tar.gz --panel http://127.0.0.1
  nodepanel-service update owner/repo@v1.2.3
  nodepanel-service update
  nodepanel-service configure --access-token your-token
  nodepanel-service log -f 200
EOF
}

require_option_value() {
    local option_name="$1"
    local option_value="${2:-}"
    if [[ -z "$option_value" ]]; then
        np_die "Missing value for ${option_name}"
    fi
}

trim_value() {
    local value="${1:-}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s\n' "$value"
}

is_interactive_session() {
    [[ -t 0 && -t 1 ]]
}

normalize_panel_url() {
    local raw_value
    raw_value="$(trim_value "${1:-}")"
    if [[ -z "$raw_value" ]]; then
        printf '\n'
        return 0
    fi

    if [[ ! "$raw_value" =~ ^[A-Za-z][A-Za-z0-9+.-]*:// ]]; then
        case "$raw_value" in
            localhost|localhost:*|127.*|[[]::1[]]*|::1|::1:*)
                raw_value="http://${raw_value}"
                ;;
            *)
                raw_value="https://${raw_value}"
                ;;
        esac
    fi

    local scheme
    local authority
    local path
    local query

    if [[ "$raw_value" =~ ^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]+)([^?#]*)?(\?[^#]*)?$ ]]; then
        scheme="${BASH_REMATCH[1],,}"
        authority="${BASH_REMATCH[2]}"
        path="${BASH_REMATCH[3]}"
        query="${BASH_REMATCH[4]}"
    else
        np_die "Invalid panel URL: ${raw_value}"
    fi

    case "$scheme" in
        http)
            scheme="ws"
            ;;
        https)
            scheme="wss"
            ;;
        ws|wss)
            ;;
        *)
            np_die "Unsupported panel URL scheme: ${scheme}. Use http, https, ws or wss."
            ;;
    esac

    path="${path:-}"
    query="${query:-}"

    case "$path" in
        ""|"/"|"/control"|"/control/"|"/control/ws/")
            path="/control/ws"
            ;;
    esac

    printf '%s://%s%s%s\n' "$scheme" "$authority" "$path" "$query"
}

display_panel_url_default() {
    local raw_value
    raw_value="$(trim_value "${1:-}")"
    if [[ -z "$raw_value" ]]; then
        printf '\n'
        return 0
    fi

    local scheme
    local authority
    local path
    local query

    if [[ "$raw_value" =~ ^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]+)([^?#]*)?(\?[^#]*)?$ ]]; then
        scheme="${BASH_REMATCH[1],,}"
        authority="${BASH_REMATCH[2]}"
        path="${BASH_REMATCH[3]}"
        query="${BASH_REMATCH[4]}"
    else
        printf '%s\n' "$raw_value"
        return 0
    fi

    case "$scheme" in
        ws)
            scheme="http"
            ;;
        wss)
            scheme="https"
            ;;
    esac

    path="${path:-}"
    query="${query:-}"

    case "$path" in
        "/control/ws"|"/control/ws/"|"/control"|"/control/")
            path=""
            query=""
            ;;
    esac

    printf '%s://%s%s%s\n' "$scheme" "$authority" "$path" "$query"
}

prompt_value() {
    local label="$1"
    local default_value="${2:-}"
    local input_value

    while true; do
        if [[ -n "$default_value" ]]; then
            printf '%s [%s]: ' "$label" "$default_value" >&2
        else
            printf '%s: ' "$label" >&2
        fi

        if ! IFS= read -r input_value; then
            printf '\n' >&2
            np_die "Interactive input was interrupted."
        fi

        input_value="$(trim_value "$input_value")"
        if [[ -n "$input_value" ]]; then
            printf '%s\n' "$input_value"
            return 0
        fi

        if [[ -n "$default_value" ]]; then
            printf '%s\n' "$default_value"
            return 0
        fi
    done
}

prompt_secret_value() {
    local label="$1"
    local default_value="${2:-}"
    local input_value

    while true; do
        if [[ -n "$default_value" ]]; then
            printf '%s [press Enter to keep current]: ' "$label" >&2
        else
            printf '%s: ' "$label" >&2
        fi

        if ! IFS= read -r -s input_value; then
            printf '\n' >&2
            np_die "Interactive input was interrupted."
        fi
        printf '\n' >&2

        input_value="$(trim_value "$input_value")"
        if [[ -n "$input_value" ]]; then
            printf '%s\n' "$input_value"
            return 0
        fi

        if [[ -n "$default_value" ]]; then
            printf '%s\n' "$default_value"
            return 0
        fi
    done
}

prompt_optional_value() {
    local label="$1"
    local default_value="${2:-}"
    local input_value

    if [[ -n "$default_value" ]]; then
        printf '%s [%s]: ' "$label" "$default_value" >&2
    else
        printf '%s: ' "$label" >&2
    fi

    if ! IFS= read -r input_value; then
        printf '\n' >&2
        np_die "Interactive input was interrupted."
    fi

    input_value="$(trim_value "$input_value")"
    if [[ -n "$input_value" ]]; then
        printf '%s\n' "$input_value"
        return 0
    fi

    printf '%s\n' "$default_value"
}

ensure_install_configuration() {
    local operation_name="$1"

    if [[ -n "$SERVICE_PANEL_URL" ]]; then
        SERVICE_PANEL_URL="$(normalize_panel_url "$SERVICE_PANEL_URL")"
    fi
    SERVICE_NODE_ID="$(trim_value "$SERVICE_NODE_ID")"
    SERVICE_ACCESS_TOKEN="$(trim_value "$SERVICE_ACCESS_TOKEN")"

    if [[ "$operation_name" != "install" ]]; then
        return 0
    fi

    local saved_panel_url
    local saved_node_id
    local saved_access_token
    saved_panel_url="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NodePanel__PanelUrl")")"
    saved_node_id="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NodePanel__Identity__NodeId")")"
    saved_access_token="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NodePanel__ControlPlane__AccessToken")")"

    if [[ -z "$SERVICE_PANEL_URL" ]]; then
        SERVICE_PANEL_URL="$saved_panel_url"
    fi
    if [[ -z "$SERVICE_NODE_ID" ]]; then
        SERVICE_NODE_ID="$saved_node_id"
    fi
    if [[ -z "$SERVICE_ACCESS_TOKEN" ]]; then
        SERVICE_ACCESS_TOKEN="$saved_access_token"
    fi

    if [[ -n "$SERVICE_PANEL_URL" && -n "$SERVICE_NODE_ID" && -n "$SERVICE_ACCESS_TOKEN" ]]; then
        if [[ "$SERVICE_PANEL_URL" != ws://* && "$SERVICE_PANEL_URL" != wss://* ]]; then
            SERVICE_PANEL_URL="$(normalize_panel_url "$SERVICE_PANEL_URL")"
        fi
        return 0
    fi

    if ! is_interactive_session; then
        np_die "Missing required service configuration. Provide --panel/--panel-url, --node-id and --access-token, or rerun this install command in an interactive shell."
    fi

    np_log "Interactive setup for ${DISPLAY_NAME}"
    np_log "Enter the panel URL only. The script will convert it to the correct ws/wss control-plane address automatically."

    local panel_input
    panel_input="$(prompt_value "Panel URL" "$(display_panel_url_default "$SERVICE_PANEL_URL")")"
    SERVICE_PANEL_URL="$(normalize_panel_url "$panel_input")"
    SERVICE_NODE_ID="$(prompt_value "Node ID" "$SERVICE_NODE_ID")"
    SERVICE_ACCESS_TOKEN="$(prompt_secret_value "Access Token" "$SERVICE_ACCESS_TOKEN")"
}

parse_config_arguments() {
    local command_name="$1"
    shift || true

    SERVICE_PANEL_URL=""
    SERVICE_NODE_ID=""
    SERVICE_ACCESS_TOKEN=""
    SERVICE_ASPNETCORE_URLS=""
    SERVICE_SOURCE_ARG=""
    SERVICE_GITHUB_REPO=""
    SERVICE_GITHUB_TAG=""
    SERVICE_PACKAGE_RID=""

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --panel|--panel-base-url|--panel-url|--control-plane-url)
                require_option_value "$1" "${2:-}"
                SERVICE_PANEL_URL="$2"
                shift 2
                ;;
            --node-id)
                require_option_value "$1" "${2:-}"
                SERVICE_NODE_ID="$2"
                shift 2
                ;;
            --access-token|--control-plane-access-token)
                require_option_value "$1" "${2:-}"
                SERVICE_ACCESS_TOKEN="$2"
                shift 2
                ;;
            --aspnetcore-urls|--service-urls)
                require_option_value "$1" "${2:-}"
                SERVICE_ASPNETCORE_URLS="$2"
                shift 2
                ;;
            --github-repo)
                require_option_value "$1" "${2:-}"
                SERVICE_GITHUB_REPO="$2"
                shift 2
                ;;
            --version|--tag)
                require_option_value "$1" "${2:-}"
                SERVICE_GITHUB_TAG="$2"
                shift 2
                ;;
            --rid)
                require_option_value "$1" "${2:-}"
                SERVICE_PACKAGE_RID="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            --*)
                np_die "Unknown option for ${command_name}: $1"
                ;;
            *)
                if [[ -n "$SERVICE_SOURCE_ARG" ]]; then
                    np_die "Only one package source may be provided for ${command_name}."
                fi

                SERVICE_SOURCE_ARG="$1"
                shift
                ;;
        esac
    done
}

load_saved_package_defaults() {
    SAVED_PACKAGE_GITHUB_REPO="$(np_first_non_empty \
        "$SERVICE_GITHUB_REPO" \
        "$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_GITHUB_REPO")" \
        "${NODEPANEL_GITHUB_REPO:-}" \
        "$DEFAULT_GITHUB_REPO")"
    SAVED_PACKAGE_RID="$(np_first_non_empty \
        "$SERVICE_PACKAGE_RID" \
        "$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_PACKAGE_RID")")"
}

load_package_info_defaults() {
    local source_root="$1"
    local package_info_path="${source_root}/PACKAGE_INFO"

    local package_info_repo
    local package_info_rid
    package_info_repo="$(np_read_key_value_file_value "$package_info_path" "github_repo")"
    package_info_rid="$(np_read_key_value_file_value "$package_info_path" "rid")"

    SERVICE_GITHUB_REPO="$(np_first_non_empty \
        "$SERVICE_GITHUB_REPO" \
        "$NODEPANEL_RESOLVED_GITHUB_REPO" \
        "$package_info_repo" \
        "$SAVED_PACKAGE_GITHUB_REPO")"
    SERVICE_PACKAGE_RID="$(np_first_non_empty \
        "$SERVICE_PACKAGE_RID" \
        "$NODEPANEL_RESOLVED_PACKAGE_RID" \
        "$package_info_rid" \
        "$SAVED_PACKAGE_RID")"
}

persist_package_defaults() {
    if [[ -n "$SERVICE_GITHUB_REPO" ]]; then
        np_upsert_env_value "$ENV_FILE" "NODEPANEL_GITHUB_REPO" "$SERVICE_GITHUB_REPO"
    fi

    if [[ -n "$SERVICE_PACKAGE_RID" ]]; then
        np_upsert_env_value "$ENV_FILE" "NODEPANEL_PACKAGE_RID" "$SERVICE_PACKAGE_RID"
    fi
}

fix_env_file_owner() {
    if id -u "$SYSTEM_USER" >/dev/null 2>&1; then
        chown "${SYSTEM_USER}:${SYSTEM_GROUP}" "$ENV_FILE"
    fi
}

apply_env_overrides() {
    if [[ ! -f "$ENV_FILE" ]]; then
        write_default_env_file
    fi

    if [[ -n "$SERVICE_ASPNETCORE_URLS" ]]; then
        np_upsert_env_value "$ENV_FILE" "ASPNETCORE_URLS" "$SERVICE_ASPNETCORE_URLS"
    fi

    if [[ -n "$SERVICE_PANEL_URL" ]]; then
        np_upsert_env_value "$ENV_FILE" "NodePanel__PanelUrl" "$SERVICE_PANEL_URL"
    fi

    if [[ -n "$SERVICE_NODE_ID" ]]; then
        np_upsert_env_value "$ENV_FILE" "NodePanel__Identity__NodeId" "$SERVICE_NODE_ID"
    fi

    if [[ -n "$SERVICE_ACCESS_TOKEN" ]]; then
        np_upsert_env_value "$ENV_FILE" "NodePanel__ControlPlane__AccessToken" "$SERVICE_ACCESS_TOKEN"
    fi

    chmod 640 "$ENV_FILE"
    fix_env_file_owner
}

has_env_overrides() {
    [[ -n "$SERVICE_PANEL_URL" || -n "$SERVICE_NODE_ID" || -n "$SERVICE_ACCESS_TOKEN" || -n "$SERVICE_ASPNETCORE_URLS" ]]
}

has_package_overrides() {
    [[ -n "$SERVICE_GITHUB_REPO" || -n "$SERVICE_PACKAGE_RID" ]]
}

write_launcher_file() {
    cat >"$1" <<EOF
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR}"

if [[ -x "\${APP_DIR}/${EXECUTABLE_NAME}" ]]; then
    exec "\${APP_DIR}/${EXECUTABLE_NAME}"
fi

if command -v dotnet >/dev/null 2>&1 && [[ -f "\${APP_DIR}/${DLL_NAME}" ]]; then
    exec dotnet "\${APP_DIR}/${DLL_NAME}"
fi

echo "Unable to locate ${EXECUTABLE_NAME} or ${DLL_NAME} in \${APP_DIR}" >&2
exit 1
EOF
}

write_unit_file() {
    cat >"$UNIT_FILE" <<EOF
[Unit]
Description=${DISPLAY_NAME}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SYSTEM_USER}
Group=${SYSTEM_GROUP}
WorkingDirectory=${APP_DIR}
EnvironmentFile=-${ENV_FILE}
ExecStart=${LAUNCHER_PATH}
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

write_default_env_file() {
    mkdir -p "$ENV_DIR"

    cat >"$ENV_FILE" <<EOF
DOTNET_ENVIRONMENT=Production
ASPNETCORE_URLS=http://127.0.0.1:6610
NodePanel__CachedConfigPath=${DATA_DIR}/node-runtime-config.json

# Required before the node can connect to the panel:
# Same host / local direct-run example:
# NodePanel__PanelUrl=ws://127.0.0.1/control/ws
# Public panel HTTPS / WSS example:
# NodePanel__PanelUrl=wss://panel.example.com/control/ws
# NodePanel__Identity__NodeId=node-001
# NodePanel__ControlPlane__AccessToken=
EOF

    chmod 640 "$ENV_FILE"
}

preserve_existing_files() {
    local old_app_dir="$1"
    local new_app_dir="$2"

    if [[ -f "${old_app_dir}/appsettings.json" ]]; then
        cp -a "${old_app_dir}/appsettings.json" "${new_app_dir}/appsettings.json"
    fi

    if [[ -e "${old_app_dir}/node-runtime-config.json" && ! -L "${old_app_dir}/node-runtime-config.json" && ! -f "${DATA_DIR}/node-runtime-config.json" ]]; then
        mv "${old_app_dir}/node-runtime-config.json" "${DATA_DIR}/node-runtime-config.json"
    fi

    if [[ -d "${old_app_dir}/certificates" && ! -L "${old_app_dir}/certificates" ]]; then
        mkdir -p "$CERT_DIR"
        cp -a "${old_app_dir}/certificates/." "$CERT_DIR/"
    fi

    mkdir -p "$CERT_DIR"
    np_remove_path_if_exists "${new_app_dir}/node-runtime-config.json"
    np_remove_path_if_exists "${new_app_dir}/certificates"
    ln -sfn "../data/node-runtime-config.json" "${new_app_dir}/node-runtime-config.json"
    ln -sfn "../data/certificates" "${new_app_dir}/certificates"
}

install_or_update() {
    local operation_name="$1"
    shift || true
    parse_config_arguments "$operation_name" "$@"

    np_require_linux
    np_require_root
    np_require_cmd tar
    np_require_cmd systemctl

    load_saved_package_defaults

    local temp_root
    temp_root="$(mktemp -d)"
    trap 'rm -rf "$temp_root"' EXIT

    local source_root
    source_root="$(np_prepare_source_dir "$SCRIPT_DIR" "$SERVICE_SOURCE_ARG" "$temp_root" "$PACKAGE_PREFIX" "$SAVED_PACKAGE_GITHUB_REPO" "$SERVICE_GITHUB_TAG" "$SAVED_PACKAGE_RID")"
    load_package_info_defaults "$source_root"
    local source_app_dir="${source_root}/app"
    local staged_app_dir="${temp_root}/staged-app"
    local staged_launcher="${temp_root}/run.sh"

    if [[ ! -d "$source_app_dir" ]]; then
        np_die "Package source does not contain an app/ directory."
    fi

    np_ensure_service_account "$SYSTEM_GROUP" "$SYSTEM_USER" "$INSTALL_ROOT"
    mkdir -p "$INSTALL_ROOT" "$DATA_DIR" "$CERT_DIR" "$ENV_DIR"

    np_copy_dir_contents "$source_app_dir" "$staged_app_dir"
    preserve_existing_files "$APP_DIR" "$staged_app_dir"
    write_launcher_file "$staged_launcher"

    np_install_runtime_scripts "$SELF_SCRIPT_SOURCE" "$COMMON_SCRIPT_SOURCE" "$BIN_PATH" "$COMMON_INSTALL_DIR"

    if [[ ! -f "$ENV_FILE" ]]; then
        write_default_env_file
    fi

    ensure_install_configuration "$operation_name"
    apply_env_overrides
    persist_package_defaults

    if [[ -f "$UNIT_FILE" ]]; then
        systemctl stop "${SYSTEMD_NAME}.service" || true
    fi

    np_remove_path_if_exists "$APP_DIR"
    mv "$staged_app_dir" "$APP_DIR"
    mv "$staged_launcher" "$LAUNCHER_PATH"

    chmod 755 "$LAUNCHER_PATH"
    if [[ -f "${APP_DIR}/${EXECUTABLE_NAME}" ]]; then
        chmod 755 "${APP_DIR}/${EXECUTABLE_NAME}"
    fi

    chown -R "${SYSTEM_USER}:${SYSTEM_GROUP}" "$INSTALL_ROOT"
    fix_env_file_owner

    write_unit_file
    systemctl daemon-reload
    systemctl enable "${SYSTEMD_NAME}.service" >/dev/null
    systemctl restart "${SYSTEMD_NAME}.service"

    np_log "${DISPLAY_NAME} has been installed to ${INSTALL_ROOT}"
    np_log "Environment file: ${ENV_FILE}"
    systemctl --no-pager --full status "${SYSTEMD_NAME}.service" || true
}

configure_component() {
    parse_config_arguments configure "$@"

    np_require_linux
    np_require_root

    if [[ -n "$SERVICE_SOURCE_ARG" ]]; then
        np_die "The configure command does not accept a package source."
    fi

    if [[ -n "$SERVICE_GITHUB_TAG" ]]; then
        np_die "The configure command does not accept --version or --tag."
    fi

    if ! has_env_overrides && ! has_package_overrides; then
        np_die "No configuration options were provided."
    fi

    load_saved_package_defaults
    ensure_install_configuration configure
    apply_env_overrides
    persist_package_defaults
    np_log "Updated ${ENV_FILE}"

    if [[ -f "$UNIT_FILE" ]]; then
        systemctl restart "${SYSTEMD_NAME}.service"
        systemctl --no-pager --full status "${SYSTEMD_NAME}.service" || true
        return 0
    fi

    np_warn "${DISPLAY_NAME} is not installed yet. Configuration was written only."
}

uninstall_component() {
    local purge="${1:-0}"

    np_require_linux
    np_require_root
    np_require_cmd systemctl

    if [[ -f "$UNIT_FILE" ]]; then
        systemctl disable --now "${SYSTEMD_NAME}.service" || true
        rm -f "$UNIT_FILE"
        systemctl daemon-reload
    fi

    rm -f "$BIN_PATH"
    rm -f "$LAUNCHER_PATH"
    rm -rf "$APP_DIR"

    if [[ "$purge" == "1" ]]; then
        rm -rf "$INSTALL_ROOT"
        rm -f "$ENV_FILE"
        np_log "${DISPLAY_NAME} has been fully removed."
        return 0
    fi

    np_log "${DISPLAY_NAME} executable files have been removed."
    np_warn "Data and configuration were kept:"
    np_warn "  ${DATA_DIR}"
    np_warn "  ${ENV_FILE}"
}

run_systemctl() {
    local action="$1"
    np_require_linux
    np_require_cmd systemctl
    systemctl "$action" "${SYSTEMD_NAME}.service"
}

show_logs() {
    local follow="0"
    local lines="200"

    if [[ "${1:-}" == "-f" ]]; then
        follow="1"
        shift || true
    fi

    if [[ -n "${1:-}" ]]; then
        lines="$1"
    fi

    np_require_linux
    np_require_cmd journalctl

    if [[ "$follow" == "1" ]]; then
        journalctl -u "${SYSTEMD_NAME}.service" -n "$lines" -f || true
        return 0
    fi

    journalctl -u "${SYSTEMD_NAME}.service" -n "$lines" --no-pager || true
}

service_is_installed() {
    [[ -f "$UNIT_FILE" || -x "$BIN_PATH" || -d "$INSTALL_ROOT" ]]
}

service_active_state() {
    if ! service_is_installed; then
        printf 'not-installed\n'
        return 0
    fi

    systemctl is-active "${SYSTEMD_NAME}.service" 2>/dev/null || true
}

service_enabled_state() {
    if ! service_is_installed; then
        printf 'not-installed\n'
        return 0
    fi

    systemctl is-enabled "${SYSTEMD_NAME}.service" 2>/dev/null || true
}

render_state_label() {
    local state="${1:-unknown}"
    case "$state" in
        active)
            printf '%sactive%s\n' "$COLOR_GREEN" "$COLOR_PLAIN"
            ;;
        activating|reloading)
            printf '%s%s%s\n' "$COLOR_YELLOW" "$state" "$COLOR_PLAIN"
            ;;
        inactive|failed|deactivating)
            printf '%s%s%s\n' "$COLOR_RED" "$state" "$COLOR_PLAIN"
            ;;
        enabled)
            printf '%senabled%s\n' "$COLOR_GREEN" "$COLOR_PLAIN"
            ;;
        disabled)
            printf '%sdisabled%s\n' "$COLOR_RED" "$COLOR_PLAIN"
            ;;
        not-installed)
            printf '%snot installed%s\n' "$COLOR_RED" "$COLOR_PLAIN"
            ;;
        *)
            printf '%s\n' "$state"
            ;;
    esac
}

mask_secret() {
    local value="${1:-}"
    if [[ -z "$value" ]]; then
        printf '(not set)\n'
        return 0
    fi

    local length="${#value}"
    if [[ "$length" -le 6 ]]; then
        printf '******\n'
        return 0
    fi

    printf '%s***%s\n' "${value:0:3}" "${value:length-2:2}"
}

show_current_configuration() {
    local current_panel_url
    local current_node_id
    local current_access_token
    local current_service_urls
    local current_repo
    local current_rid

    current_panel_url="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NodePanel__PanelUrl")")"
    current_node_id="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NodePanel__Identity__NodeId")")"
    current_access_token="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NodePanel__ControlPlane__AccessToken")")"
    current_service_urls="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "ASPNETCORE_URLS")")"
    current_repo="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_GITHUB_REPO")")"
    current_rid="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NODEPANEL_PACKAGE_RID")")"

    printf 'Env file        : %s\n' "$ENV_FILE"
    printf 'Panel URL       : %s\n' "$(display_panel_url_default "$current_panel_url")"
    printf 'Control URL     : %s\n' "${current_panel_url:-"(not set)"}"
    printf 'Node ID         : %s\n' "${current_node_id:-"(not set)"}"
    printf 'Access Token    : %s\n' "$(mask_secret "$current_access_token")"
    printf 'Service URLs    : %s\n' "${current_service_urls:-"(default)"}"
    printf 'GitHub Repo     : %s\n' "${current_repo:-"${DEFAULT_GITHUB_REPO:-"(not set)"}"}"
    printf 'Package RID     : %s\n' "${current_rid:-"(auto)"}"
}

show_service_overview() {
    local installed_text='no'
    local active_state
    local enabled_state

    if service_is_installed; then
        installed_text="${COLOR_GREEN}yes${COLOR_PLAIN}"
    else
        installed_text="${COLOR_RED}no${COLOR_PLAIN}"
    fi

    active_state="$(service_active_state)"
    enabled_state="$(service_enabled_state)"

    printf 'Installed       : %b\n' "$installed_text"
    printf 'Runtime State   : %b' "$(render_state_label "$active_state")"
    printf 'Auto Start      : %b' "$(render_state_label "$enabled_state")"
    show_current_configuration
}

pause_for_menu() {
    printf '\nPress Enter to return to the menu: ' >&2
    read -r _ || true
}

confirm_choice() {
    local prompt_text="$1"
    local default_value="${2:-n}"
    local input_value
    local hint='y/N'

    if [[ "$default_value" == "y" ]]; then
        hint='Y/n'
    fi

    printf '%s [%s]: ' "$prompt_text" "$hint" >&2
    if ! IFS= read -r input_value; then
        printf '\n' >&2
        return 1
    fi

    input_value="$(trim_value "$input_value")"
    if [[ -z "$input_value" ]]; then
        input_value="$default_value"
    fi

    [[ "$input_value" == "y" || "$input_value" == "Y" ]]
}

menu_require_installed() {
    if service_is_installed; then
        return 0
    fi

    np_warn "${DISPLAY_NAME} is not installed yet."
    return 1
}

prompt_package_source() {
    printf '%s\n' "Supported package source:" >&2
    printf '%s\n' "  - leave blank to use the saved/latest GitHub release" >&2
    printf '%s\n' "  - owner/repo or owner/repo@tag" >&2
    printf '%s\n' "  - local package directory / archive path / package URL" >&2
    prompt_optional_value "Package source" ""
}

interactive_configure_component() {
    np_require_linux
    np_require_root

    load_saved_package_defaults

    SERVICE_PANEL_URL="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NodePanel__PanelUrl")")"
    SERVICE_NODE_ID="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NodePanel__Identity__NodeId")")"
    SERVICE_ACCESS_TOKEN="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "NodePanel__ControlPlane__AccessToken")")"
    SERVICE_ASPNETCORE_URLS="$(trim_value "$(np_read_key_value_file_value "$ENV_FILE" "ASPNETCORE_URLS")")"

    np_log "Interactive configuration for ${DISPLAY_NAME}"
    np_log "Enter the panel URL only. The script will convert it to ws:// or wss:// automatically."

    local panel_input
    panel_input="$(prompt_value "Panel URL" "$(display_panel_url_default "$SERVICE_PANEL_URL")")"
    SERVICE_PANEL_URL="$(normalize_panel_url "$panel_input")"
    SERVICE_NODE_ID="$(prompt_value "Node ID" "$SERVICE_NODE_ID")"
    SERVICE_ACCESS_TOKEN="$(prompt_secret_value "Access Token" "$SERVICE_ACCESS_TOKEN")"
    SERVICE_ASPNETCORE_URLS="$(prompt_optional_value "Service listen URL" "${SERVICE_ASPNETCORE_URLS:-http://127.0.0.1:6610}")"

    apply_env_overrides
    persist_package_defaults
    np_log "Updated ${ENV_FILE}"

    if [[ -f "$UNIT_FILE" ]]; then
        systemctl restart "${SYSTEMD_NAME}.service" || true
        systemctl --no-pager --full status "${SYSTEMD_NAME}.service" || true
        return 0
    fi

    np_warn "${DISPLAY_NAME} is not installed yet. Configuration was written only."
}

show_status_command() {
    if ! service_is_installed; then
        np_warn "${DISPLAY_NAME} is not installed yet."
        return 0
    fi

    systemctl status "${SYSTEMD_NAME}.service" --no-pager --full || true
}

menu_install_component() {
    local source_arg
    if service_is_installed && ! confirm_choice "Reinstall ${DISPLAY_NAME}?" "n"; then
        return 0
    fi

    source_arg="$(prompt_package_source)"
    if [[ -n "$source_arg" ]]; then
        install_or_update install "$source_arg"
        return 0
    fi

    install_or_update install
}

menu_update_component() {
    local source_arg
    if ! menu_require_installed; then
        return 0
    fi

    source_arg="$(prompt_package_source)"
    if [[ -n "$source_arg" ]]; then
        install_or_update update "$source_arg"
        return 0
    fi

    install_or_update update
}

menu_uninstall_component() {
    local purge_flag="0"

    if ! menu_require_installed; then
        return 0
    fi

    if ! confirm_choice "Uninstall ${DISPLAY_NAME}?" "n"; then
        return 0
    fi

    if confirm_choice "Delete data and environment files as well?" "n"; then
        purge_flag="1"
    fi

    uninstall_component "$purge_flag"
}

menu_run_systemctl_action() {
    local action="$1"
    if ! menu_require_installed; then
        return 0
    fi

    np_require_root
    systemctl "$action" "${SYSTEMD_NAME}.service" || true
    systemctl --no-pager --full status "${SYSTEMD_NAME}.service" || true
}

show_menu() {
    while true; do
        clear 2>/dev/null || true
        printf '\n%sNodePanel Service Manager%s\n' "$COLOR_CYAN" "$COLOR_PLAIN"
        printf '%s\n' '----------------------------------------'
        show_service_overview
        printf '%s\n' '----------------------------------------'
        cat <<'EOF'
  1. Install / Reinstall Service
  2. Update Service
  3. Configure Panel Access
  4. Start Service
  5. Stop Service
  6. Restart Service
  7. Show Service Status
  8. Follow Service Logs
  9. Enable Auto Start
 10. Disable Auto Start
 11. Show Current Config
 12. Uninstall Service
  0. Exit
EOF

        printf 'Choose [0-12]: ' >&2
        local choice
        if ! IFS= read -r choice; then
            printf '\n' >&2
            return 0
        fi

        case "$(trim_value "$choice")" in
            1)
                menu_install_component
                pause_for_menu
                ;;
            2)
                menu_update_component
                pause_for_menu
                ;;
            3)
                interactive_configure_component
                pause_for_menu
                ;;
            4)
                menu_run_systemctl_action start
                pause_for_menu
                ;;
            5)
                menu_run_systemctl_action stop
                pause_for_menu
                ;;
            6)
                menu_run_systemctl_action restart
                pause_for_menu
                ;;
            7)
                show_status_command
                pause_for_menu
                ;;
            8)
                if menu_require_installed; then
                    local lines
                    lines="$(prompt_optional_value "Log lines" "200")"
                    printf 'Press Ctrl+C to stop following logs.\n' >&2
                    show_logs -f "${lines:-200}"
                fi
                ;;
            9)
                if menu_require_installed; then
                    np_require_root
                    systemctl enable "${SYSTEMD_NAME}.service" || true
                    systemctl status "${SYSTEMD_NAME}.service" --no-pager --full || true
                fi
                pause_for_menu
                ;;
            10)
                if menu_require_installed; then
                    np_require_root
                    systemctl disable "${SYSTEMD_NAME}.service" || true
                    systemctl status "${SYSTEMD_NAME}.service" --no-pager --full || true
                fi
                pause_for_menu
                ;;
            11)
                show_current_configuration
                pause_for_menu
                ;;
            12)
                menu_uninstall_component
                pause_for_menu
                ;;
            0|q|quit|exit)
                return 0
                ;;
            *)
                np_warn "Please enter a valid number between 0 and 12."
                sleep 1
                ;;
        esac
    done
}

main() {
    local command="${1:-}"
    shift || true

    case "$command" in
        install)
            install_or_update install "$@"
            ;;
        update)
            install_or_update update "$@"
            ;;
        configure)
            if [[ "$#" -eq 0 && is_interactive_session ]]; then
                interactive_configure_component
            else
                configure_component "$@"
            fi
            ;;
        start)
            np_require_root
            run_systemctl start
            ;;
        stop)
            np_require_root
            run_systemctl stop
            ;;
        restart)
            np_require_root
            run_systemctl restart
            ;;
        status)
            show_status_command
            ;;
        log|logs)
            show_logs "$@"
            ;;
        enable)
            np_require_root
            run_systemctl enable
            ;;
        disable)
            np_require_root
            run_systemctl disable
            ;;
        uninstall)
            if [[ "${1:-}" == "--purge" ]]; then
                uninstall_component 1
            else
                uninstall_component 0
            fi
            ;;
        "")
            if is_interactive_session; then
                show_menu
            else
                usage
            fi
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            usage
            np_die "Unknown command: ${command}"
            ;;
    esac
}

main "$@"
