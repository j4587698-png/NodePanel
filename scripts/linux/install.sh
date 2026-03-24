#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_GITHUB_REPO="${NODEPANEL_DEFAULT_GITHUB_REPO:-j4587698-png/NodePanel}"

BOOTSTRAP_COMPONENT=""
BOOTSTRAP_COMMAND=""
BOOTSTRAP_SOURCE_ARG=""
BOOTSTRAP_HELPER_REPO=""
BOOTSTRAP_HELPER_TAG=""
BOOTSTRAP_FORWARD_ARGS=()
BOOTSTRAP_TEMP_ROOT=""

usage() {
    cat <<'EOF'
Usage:
  install.sh panel [install|update|start|stop|restart|status|log|enable|disable|uninstall] [source] [options]
  install.sh service [install|update|configure|start|stop|restart|status|log|enable|disable|uninstall] [source] [options]

Source:
  package_dir
  package.tar.gz
  package_url
  owner/repo
  owner/repo@tag
  tag (requires --github-repo)

Bootstrap options:
  --github-repo OWNER/REPO
  --version TAG
  --tag TAG
  --panel URL
  --panel-base-url URL
  --panel-url URL

Examples:
  bash install.sh panel
  bash install.sh panel install owner/repo
  bash install.sh panel install owner/repo@v0.1.0
  bash install.sh service
  bash install.sh service install --github-repo owner/repo --version v0.1.0 --panel https://panel.example.com --node-id node-001 --access-token your-token
  bash install.sh service update
EOF
}

np_bootstrap_log() {
    printf '[nodepanel-bootstrap] %s\n' "$*"
}

np_bootstrap_die() {
    printf '[nodepanel-bootstrap] ERROR: %s\n' "$*" >&2
    exit 1
}

np_bootstrap_require_option_value() {
    local option_name="$1"
    local option_value="${2:-}"
    if [[ -z "$option_value" ]]; then
        np_bootstrap_die "Missing value for ${option_name}"
    fi
}

np_bootstrap_require_cmd() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        np_bootstrap_die "Missing required command: ${command_name}"
    fi
}

np_bootstrap_is_url() {
    local value="${1:-}"
    [[ "$value" =~ ^https?:// ]]
}

np_bootstrap_is_github_repo() {
    local value="${1:-}"
    [[ "$value" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]
}

np_bootstrap_is_known_command() {
    local value="${1:-}"
    case "$value" in
        install|update|configure|start|stop|restart|status|log|logs|enable|disable|uninstall)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

np_bootstrap_parse_args() {
    if [[ "$#" -eq 0 ]]; then
        usage
        exit 1
    fi

    case "${1:-}" in
        panel|service)
            BOOTSTRAP_COMPONENT="$1"
            shift
            ;;
        -h|--help|help)
            usage
            exit 0
            ;;
        *)
            usage
            np_bootstrap_die "The first argument must be panel or service."
            ;;
    esac

    if [[ "$#" -gt 0 ]] && np_bootstrap_is_known_command "${1:-}"; then
        BOOTSTRAP_COMMAND="$1"
        shift
    fi

    BOOTSTRAP_FORWARD_ARGS=()
    BOOTSTRAP_SOURCE_ARG=""
    BOOTSTRAP_HELPER_REPO=""
    BOOTSTRAP_HELPER_TAG=""

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --github-repo)
                np_bootstrap_require_option_value "$1" "${2:-}"
                BOOTSTRAP_HELPER_REPO="$2"
                BOOTSTRAP_FORWARD_ARGS+=("$1" "$2")
                shift 2
                ;;
            --version|--tag)
                np_bootstrap_require_option_value "$1" "${2:-}"
                BOOTSTRAP_HELPER_TAG="$2"
                BOOTSTRAP_FORWARD_ARGS+=("$1" "$2")
                shift 2
                ;;
            --rid|--panel|--panel-base-url|--panel-url|--control-plane-url|--node-id|--access-token|--control-plane-access-token|--aspnetcore-urls|--service-urls)
                np_bootstrap_require_option_value "$1" "${2:-}"
                BOOTSTRAP_FORWARD_ARGS+=("$1" "$2")
                shift 2
                ;;
            -h|--help|help)
                BOOTSTRAP_FORWARD_ARGS+=("$1")
                shift
                ;;
            *)
                if [[ -z "$BOOTSTRAP_SOURCE_ARG" && "$1" != -* ]]; then
                    BOOTSTRAP_SOURCE_ARG="$1"
                fi
                BOOTSTRAP_FORWARD_ARGS+=("$1")
                shift
                ;;
        esac
    done

    if [[ -n "$BOOTSTRAP_SOURCE_ARG" ]]; then
        if [[ "$BOOTSTRAP_SOURCE_ARG" == *"@"* ]]; then
            local repo_candidate="${BOOTSTRAP_SOURCE_ARG%@*}"
            local tag_candidate="${BOOTSTRAP_SOURCE_ARG#*@}"
            if np_bootstrap_is_github_repo "$repo_candidate" && [[ -n "$tag_candidate" ]]; then
                if [[ -z "$BOOTSTRAP_HELPER_REPO" ]]; then
                    BOOTSTRAP_HELPER_REPO="$repo_candidate"
                fi
                if [[ -z "$BOOTSTRAP_HELPER_TAG" ]]; then
                    BOOTSTRAP_HELPER_TAG="$tag_candidate"
                fi
            fi
        elif np_bootstrap_is_github_repo "$BOOTSTRAP_SOURCE_ARG"; then
            if [[ -z "$BOOTSTRAP_HELPER_REPO" ]]; then
                BOOTSTRAP_HELPER_REPO="$BOOTSTRAP_SOURCE_ARG"
            fi
        elif [[ -n "$BOOTSTRAP_HELPER_REPO" && ! -e "$BOOTSTRAP_SOURCE_ARG" ]] && ! np_bootstrap_is_url "$BOOTSTRAP_SOURCE_ARG"; then
            if [[ -z "$BOOTSTRAP_HELPER_TAG" ]]; then
                BOOTSTRAP_HELPER_TAG="$BOOTSTRAP_SOURCE_ARG"
            fi
        fi
    fi

    if [[ -z "$BOOTSTRAP_HELPER_REPO" ]]; then
        BOOTSTRAP_HELPER_REPO="$DEFAULT_GITHUB_REPO"
    fi

    if [[ -z "$BOOTSTRAP_COMMAND" ]]; then
        if [[ "$BOOTSTRAP_COMPONENT" == "panel" ]]; then
            BOOTSTRAP_COMMAND="install"
        elif [[ -n "$BOOTSTRAP_SOURCE_ARG" || "${#BOOTSTRAP_FORWARD_ARGS[@]}" -gt 0 ]]; then
            BOOTSTRAP_COMMAND="install"
        fi
    fi
}

np_bootstrap_download_file() {
    local url="$1"
    local output_path="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --connect-timeout 15 -o "$output_path" "$url"
        return 0
    fi

    if command -v wget >/dev/null 2>&1; then
        wget -O "$output_path" "$url"
        return 0
    fi

    np_bootstrap_die "Neither curl nor wget is available for downloading helper scripts."
}

np_bootstrap_build_asset_url() {
    local github_repo="$1"
    local asset_name="$2"
    local github_tag="${3:-}"

    if [[ -z "$github_tag" || "$github_tag" == "latest" ]]; then
        printf 'https://github.com/%s/releases/latest/download/%s\n' "$github_repo" "$asset_name"
        return 0
    fi

    printf 'https://github.com/%s/releases/download/%s/%s\n' "$github_repo" "$github_tag" "$asset_name"
}

np_bootstrap_download_helpers() {
    BOOTSTRAP_TEMP_ROOT="$(mktemp -d)"
    trap 'rm -rf "$BOOTSTRAP_TEMP_ROOT"' EXIT

    local component_asset
    component_asset="nodepanel-${BOOTSTRAP_COMPONENT}.sh"
    local common_asset="nodepanel-common.sh"
    local component_url
    local common_url

    component_url="$(np_bootstrap_build_asset_url "$BOOTSTRAP_HELPER_REPO" "$component_asset" "$BOOTSTRAP_HELPER_TAG")"
    common_url="$(np_bootstrap_build_asset_url "$BOOTSTRAP_HELPER_REPO" "$common_asset" "$BOOTSTRAP_HELPER_TAG")"

    np_bootstrap_log "Downloading ${component_asset} from ${BOOTSTRAP_HELPER_REPO}${BOOTSTRAP_HELPER_TAG:+ (${BOOTSTRAP_HELPER_TAG})}"
    np_bootstrap_download_file "$component_url" "${BOOTSTRAP_TEMP_ROOT}/${component_asset}"
    np_bootstrap_download_file "$common_url" "${BOOTSTRAP_TEMP_ROOT}/${common_asset}"
    chmod 755 "${BOOTSTRAP_TEMP_ROOT}/${component_asset}"
}

main() {
    np_bootstrap_parse_args "$@"
    np_bootstrap_download_helpers

    if [[ -n "$BOOTSTRAP_COMMAND" ]]; then
        NODEPANEL_DEFAULT_GITHUB_REPO="$BOOTSTRAP_HELPER_REPO" \
            "${BOOTSTRAP_TEMP_ROOT}/nodepanel-${BOOTSTRAP_COMPONENT}.sh" \
            "$BOOTSTRAP_COMMAND" \
            "${BOOTSTRAP_FORWARD_ARGS[@]}"
        return 0
    fi

    NODEPANEL_DEFAULT_GITHUB_REPO="$BOOTSTRAP_HELPER_REPO" \
        "${BOOTSTRAP_TEMP_ROOT}/nodepanel-${BOOTSTRAP_COMPONENT}.sh" \
        "${BOOTSTRAP_FORWARD_ARGS[@]}"
}

main "$@"
