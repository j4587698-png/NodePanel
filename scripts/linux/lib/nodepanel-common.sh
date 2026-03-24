#!/usr/bin/env bash
set -euo pipefail

NODEPANEL_COMMON_LOADED=1
NODEPANEL_COMMON_SOURCE="${BASH_SOURCE[0]}"
NODEPANEL_SOURCE_MODE=""
NODEPANEL_RESOLVED_GITHUB_REPO=""
NODEPANEL_RESOLVED_GITHUB_TAG=""
NODEPANEL_RESOLVED_PACKAGE_RID=""

np_log() {
    printf '[nodepanel] %s\n' "$*" >&2
}

np_warn() {
    printf '[nodepanel] WARN: %s\n' "$*" >&2
}

np_die() {
    printf '[nodepanel] ERROR: %s\n' "$*" >&2
    exit 1
}

np_require_linux() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        np_die "This script only supports Linux."
    fi
}

np_require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        np_die "Please run this command as root."
    fi
}

np_require_cmd() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        np_die "Missing required command: ${command_name}"
    fi
}

np_first_non_empty() {
    local value
    for value in "$@"; do
        if [[ -n "${value:-}" ]]; then
            printf '%s\n' "$value"
            return 0
        fi
    done

    printf '\n'
}

np_is_url() {
    local value="${1:-}"
    [[ "$value" =~ ^https?:// ]]
}

np_is_github_repo() {
    local value="${1:-}"
    [[ "$value" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]
}

np_archive_name_from_url() {
    local url="$1"
    local sanitized_url="${url%%\#*}"
    sanitized_url="${sanitized_url%%\?*}"

    local file_name="${sanitized_url##*/}"
    case "$file_name" in
        *.tar.gz|*.tgz|*.tar|*.zip)
            printf '%s\n' "$file_name"
            return 0
            ;;
        *)
            np_die "Cannot determine archive type from URL: ${url}. Use a URL ending with .tar.gz, .tgz, .tar or .zip."
            ;;
    esac
}

np_abs_path() {
    local value="${1:-}"
    if [[ -z "$value" ]]; then
        printf '\n'
        return 0
    fi

    if [[ "$value" == /* ]]; then
        printf '%s\n' "$value"
        return 0
    fi

    printf '%s\n' "$(pwd)/${value}"
}

np_strip_wrapping_quotes() {
    local value="${1-}"
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
        value="${value:1:${#value}-2}"
    fi

    value="${value//\\\"/\"}"
    value="${value//\\\\/\\}"
    value="${value//\\\$/\$}"
    value="${value//\\\`/\`}"
    printf '%s\n' "$value"
}

np_read_key_value_file_value() {
    local file_path="$1"
    local key="$2"

    if [[ ! -f "$file_path" ]]; then
        printf '\n'
        return 0
    fi

    local raw_value
    raw_value="$(awk -v key="$key" '
        index($0, key "=") == 1 {
            print substr($0, length(key) + 2)
            exit
        }
    ' "$file_path")"

    np_strip_wrapping_quotes "$raw_value"
}

np_resolve_package_version() {
    local package_info_path="$1"
    local resolved_github_tag="${2:-}"
    local package_info_version

    package_info_version="$(np_read_key_value_file_value "$package_info_path" "version")"
    printf '%s\n' "$(np_first_non_empty "$package_info_version" "${resolved_github_tag#v}")"
}

np_resolve_nologin_shell() {
    local candidate
    for candidate in /usr/sbin/nologin /sbin/nologin /usr/bin/false /bin/false; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    printf '/usr/sbin/nologin\n'
}

np_ensure_service_account() {
    local account_group="$1"
    local account_user="$2"
    local home_dir="$3"

    if ! getent group "$account_group" >/dev/null 2>&1; then
        groupadd --system "$account_group"
    fi

    if ! id -u "$account_user" >/dev/null 2>&1; then
        useradd \
            --system \
            --gid "$account_group" \
            --home-dir "$home_dir" \
            --create-home \
            --shell "$(np_resolve_nologin_shell)" \
            "$account_user"
    fi
}

np_download_file() {
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

    np_die "Neither curl nor wget is available for downloading package sources."
}

np_detect_linux_rid() {
    local machine_arch
    machine_arch="$(uname -m)"

    case "$machine_arch" in
        x86_64|amd64|x64)
            printf 'linux-x64\n'
            ;;
        aarch64|arm64)
            printf 'linux-arm64\n'
            ;;
        armv7l|armv7|armhf|armv6l|armv6)
            printf 'linux-arm\n'
            ;;
        *)
            np_die "Unsupported Linux architecture: ${machine_arch}. Use --rid to specify the package runtime explicitly."
            ;;
    esac
}

np_build_package_asset_name() {
    local package_prefix="$1"
    local package_rid="$2"
    printf '%s-%s.tar.gz\n' "$package_prefix" "$package_rid"
}

np_build_github_release_url() {
    local github_repo="$1"
    local asset_name="$2"
    local github_tag="${3:-}"

    if [[ -z "$github_tag" || "$github_tag" == "latest" ]]; then
        printf 'https://github.com/%s/releases/latest/download/%s\n' "$github_repo" "$asset_name"
        return 0
    fi

    printf 'https://github.com/%s/releases/download/%s/%s\n' "$github_repo" "$github_tag" "$asset_name"
}

np_extract_archive() {
    local archive_path="$1"
    local destination_dir="$2"

    mkdir -p "$destination_dir"

    case "$archive_path" in
        *.tar.gz|*.tgz)
            tar -xzf "$archive_path" -C "$destination_dir"
            ;;
        *.tar)
            tar -xf "$archive_path" -C "$destination_dir"
            ;;
        *.zip)
            np_require_cmd unzip
            unzip -q "$archive_path" -d "$destination_dir"
            ;;
        *)
            np_die "Unsupported package format: ${archive_path}"
            ;;
    esac
}

np_locate_package_root() {
    local extracted_root="$1"

    if [[ -d "$extracted_root/app" ]]; then
        printf '%s\n' "$extracted_root"
        return 0
    fi

    local entries=()
    while IFS= read -r -d '' item; do
        entries+=("$item")
    done < <(find "$extracted_root" -mindepth 1 -maxdepth 1 -type d -print0)

    if [[ "${#entries[@]}" -eq 1 && -d "${entries[0]}/app" ]]; then
        printf '%s\n' "${entries[0]}"
        return 0
    fi

    np_die "Cannot locate package root that contains an app/ directory."
}

np_prepare_github_release_source() {
    local github_repo="$1"
    local github_tag="${2:-}"
    local package_prefix="$3"
    local package_rid="${4:-}"
    local temp_root="$5"

    if ! np_is_github_repo "$github_repo"; then
        np_die "Invalid GitHub repository reference: ${github_repo}. Use owner/repo."
    fi

    if [[ -z "$package_prefix" ]]; then
        np_die "Missing package prefix for GitHub package lookup."
    fi

    if [[ -z "$package_rid" ]]; then
        package_rid="$(np_detect_linux_rid)"
    fi

    local asset_name
    asset_name="$(np_build_package_asset_name "$package_prefix" "$package_rid")"

    local downloaded_archive="${temp_root}/${asset_name}"
    local extracted_dir="${temp_root}/package-extract"
    local release_url
    release_url="$(np_build_github_release_url "$github_repo" "$asset_name" "$github_tag")"

    if [[ -n "$github_tag" && "$github_tag" != "latest" ]]; then
        np_log "Downloading ${asset_name} from GitHub repo ${github_repo} (${github_tag})"
    else
        np_log "Downloading ${asset_name} from GitHub repo ${github_repo} (latest)"
    fi

    np_download_file "$release_url" "$downloaded_archive"

    NODEPANEL_SOURCE_MODE="github"
    NODEPANEL_RESOLVED_GITHUB_REPO="$github_repo"
    NODEPANEL_RESOLVED_GITHUB_TAG="$github_tag"
    NODEPANEL_RESOLVED_PACKAGE_RID="$package_rid"

    np_extract_archive "$downloaded_archive" "$extracted_dir"
    np_locate_package_root "$extracted_dir"
}

np_prepare_source_dir() {
    local script_dir="$1"
    local source_arg="${2:-}"
    local temp_root="$3"
    local package_prefix="${4:-}"
    local github_repo="${5:-}"
    local github_tag="${6:-}"
    local package_rid="${7:-}"

    NODEPANEL_SOURCE_MODE=""
    NODEPANEL_RESOLVED_GITHUB_REPO=""
    NODEPANEL_RESOLVED_GITHUB_TAG=""
    NODEPANEL_RESOLVED_PACKAGE_RID=""

    if [[ -z "$source_arg" ]]; then
        if [[ -d "$script_dir/app" ]]; then
            NODEPANEL_SOURCE_MODE="script-dir"
            printf '%s\n' "$script_dir"
            return 0
        fi

        if [[ -n "$github_repo" ]]; then
            np_prepare_github_release_source "$github_repo" "$github_tag" "$package_prefix" "$package_rid" "$temp_root"
            return 0
        fi

        np_die "No package source was provided, and the current directory does not contain an app/ folder. Pass a package directory, archive path, package URL or GitHub repo."
    fi

    if np_is_url "$source_arg"; then
        local archive_name
        archive_name="$(np_archive_name_from_url "$source_arg")"

        local downloaded_archive="$temp_root/${archive_name}"
        local extracted_dir="$temp_root/package-extract"
        np_log "Downloading package from ${source_arg}"
        np_download_file "$source_arg" "$downloaded_archive"
        NODEPANEL_SOURCE_MODE="url"
        np_extract_archive "$downloaded_archive" "$extracted_dir"
        np_locate_package_root "$extracted_dir"
        return 0
    fi

    local absolute_source
    absolute_source="$(np_abs_path "$source_arg")"

    if [[ -d "$absolute_source" ]]; then
        if [[ -d "$absolute_source/app" ]]; then
            NODEPANEL_SOURCE_MODE="directory"
            printf '%s\n' "$absolute_source"
            return 0
        fi

        np_die "Source directory must contain an app/ folder: ${absolute_source}"
    fi

    if [[ -f "$absolute_source" ]]; then
        local extracted_dir="$temp_root/package-extract"
        NODEPANEL_SOURCE_MODE="archive"
        np_extract_archive "$absolute_source" "$extracted_dir"
        np_locate_package_root "$extracted_dir"
        return 0
    fi

    if [[ "$source_arg" == *"@"* ]]; then
        local repo_candidate="${source_arg%@*}"
        local tag_candidate="${source_arg#*@}"
        if np_is_github_repo "$repo_candidate" && [[ -n "$tag_candidate" ]]; then
            np_prepare_github_release_source "$repo_candidate" "$tag_candidate" "$package_prefix" "$package_rid" "$temp_root"
            return 0
        fi
    fi

    if np_is_github_repo "$source_arg"; then
        np_prepare_github_release_source "$source_arg" "$github_tag" "$package_prefix" "$package_rid" "$temp_root"
        return 0
    fi

    if [[ -n "$github_repo" ]]; then
        np_prepare_github_release_source "$github_repo" "$source_arg" "$package_prefix" "$package_rid" "$temp_root"
        return 0
    fi

    np_die "Package source not found: ${source_arg}"
}

np_install_runtime_scripts() {
    local component_script_source="$1"
    local common_script_source="$2"
    local installed_script_path="$3"
    local installed_common_dir="$4"
    local installed_common_path="${installed_common_dir}/nodepanel-common.sh"

    mkdir -p "$installed_common_dir"

    if [[ ! -e "$installed_common_path" || ! "$common_script_source" -ef "$installed_common_path" ]]; then
        install -m 644 "$common_script_source" "$installed_common_path"
    fi

    if [[ ! -e "$installed_script_path" || ! "$component_script_source" -ef "$installed_script_path" ]]; then
        install -m 755 "$component_script_source" "$installed_script_path"
    fi
}

np_copy_dir_contents() {
    local source_dir="$1"
    local destination_dir="$2"

    mkdir -p "$destination_dir"
    cp -a "$source_dir/." "$destination_dir/"
}

np_remove_path_if_exists() {
    local target_path="$1"
    if [[ -e "$target_path" || -L "$target_path" ]]; then
        rm -rf "$target_path"
    fi
}

np_chown_if_exists() {
    local owner="$1"
    local target_path="$2"
    if [[ -e "$target_path" || -L "$target_path" ]]; then
        chown -R "$owner" "$target_path"
    fi
}

np_quote_env_value() {
    local value="${1-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//\$/\\$}"
    value="${value//\`/\\\`}"
    printf '"%s"\n' "$value"
}

np_upsert_env_value() {
    local env_file="$1"
    local env_key="$2"
    local env_value="$3"
    local quoted_value
    local temp_file

    mkdir -p "$(dirname "$env_file")"
    touch "$env_file"

    quoted_value="$(np_quote_env_value "$env_value")"
    temp_file="$(mktemp)"

    awk -v key="$env_key" -v value="$quoted_value" '
        BEGIN { updated = 0 }
        index($0, key "=") == 1 {
            print key "=" value
            updated = 1
            next
        }
        { print }
        END {
            if (!updated) {
                print key "=" value
            }
        }
    ' "$env_file" > "$temp_file"

    cat "$temp_file" > "$env_file"
    rm -f "$temp_file"
}
