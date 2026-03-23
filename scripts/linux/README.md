# Linux Deployment Scripts

This directory contains Linux deployment helpers for both components:

- `install.sh`
  1-click bootstrap script. Download just this file first, then let it fetch the matching component installer from GitHub Releases.
- `publish-linux.sh`
  Builds Linux publish directories and `.tar.gz` packages for `panel` and `service`.
- `nodepanel-panel.sh`
  Installs, updates and manages the panel with `systemd`.
- `nodepanel-service.sh`
  Installs, updates and manages the service with `systemd`.

## Build Packages

Run from `Xray-dotnet`:

```bash
./scripts/linux/publish-linux.sh
```

Default outputs:

- `artifacts/linux/nodepanel-panel-linux-x64.tar.gz`
- `artifacts/linux/nodepanel-service-linux-x64.tar.gz`

Custom runtime example:

```bash
./scripts/linux/publish-linux.sh --rid linux-arm64
```

If you plan to distribute through GitHub Releases and want later `update` commands to remember the repo automatically, build packages with:

```bash
./scripts/linux/publish-linux.sh --github-repo owner/repo
```

## GitHub Release

The repository release flow is version-driven from:

- `Directory.Build.props` -> `NodePanelVersionPrefix`

Release steps:

1. Update `NodePanelVersionPrefix`
2. Commit and push `main`
3. GitHub Actions creates `vX.Y.Z`, builds Linux packages and publishes the release

If the same release tag already exists, pushes to `main` skip the publish step automatically.

You can still trigger the workflow manually from GitHub Actions:

- leave `version` empty: publish using `Directory.Build.props`
- fill `version`: publish that explicit version without editing the file first

## 1-Click Install

Download one bootstrap script first:

```bash
curl -fL -o install.sh https://github.com/owner/repo/releases/latest/download/install.sh
chmod +x install.sh
```

Install panel from the latest release:

```bash
sudo bash install.sh panel
```

Install service from the latest release:

```bash
sudo bash install.sh service \
  --panel-url wss://panel.example.com/control/ws \
  --node-id node-001 \
  --access-token your-token
```

Install a specific release:

```bash
sudo bash install.sh panel install owner/repo@v0.1.0
sudo bash install.sh service install owner/repo@v0.1.0 \
  --panel-url wss://panel.example.com/control/ws \
  --node-id node-001 \
  --access-token your-token
```

## Install Panel

```bash
tar -xzf nodepanel-panel-linux-x64.tar.gz
cd nodepanel-panel-linux-x64
sudo bash install.sh install
```

Direct package URL install:

```bash
sudo bash install.sh install https://downloads.example.com/nodepanel-panel-linux-x64.tar.gz
```

GitHub repo install:

```bash
sudo bash install.sh install owner/repo
```

GitHub specific version install:

```bash
sudo bash install.sh install owner/repo@v1.2.3
sudo bash install.sh install v1.2.3 --github-repo owner/repo
```

Default paths:

- install root: `/usr/local/nodepanel-panel`
- command: `/usr/local/bin/nodepanel-panel`
- env file: `/etc/nodepanel/panel.env`
- systemd unit: `nodepanel-panel`

Fresh installs should then open:

```text
http://<server-ip>/install
```

The panel runs directly on Kestrel. No `nginx` reverse proxy is required.

- HTTP entrypoint: `80`
- HTTPS entrypoint: configured in `/admin/certificates`, then the panel listens directly on `443`
- ACME `http-01`: keep `80` open so the panel can answer `/.well-known/acme-challenge/*`

When installed with these scripts, the default `/etc/nodepanel/panel.env` enables automatic process restart after the Panel HTTPS listener address/port changes, so first-time `443` enablement can be applied directly under `systemd`.

## Install Service

```bash
tar -xzf nodepanel-service-linux-x64.tar.gz
cd nodepanel-service-linux-x64
sudo bash install.sh install \
  --panel-url wss://panel.example.com/control/ws \
  --node-id node-001 \
  --access-token your-token
```

Direct package URL install:

```bash
sudo bash install.sh install \
  https://downloads.example.com/nodepanel-service-linux-x64.tar.gz \
  --panel-url wss://panel.example.com/control/ws \
  --node-id node-001 \
  --access-token your-token
```

GitHub repo install:

```bash
sudo bash install.sh install owner/repo \
  --panel-url wss://panel.example.com/control/ws \
  --node-id node-001 \
  --access-token your-token
```

GitHub specific version install:

```bash
sudo bash install.sh install owner/repo@v1.2.3 \
  --panel-url wss://panel.example.com/control/ws \
  --node-id node-001 \
  --access-token your-token
```

Default paths:

- install root: `/usr/local/nodepanel-service`
- command: `/usr/local/bin/nodepanel-service`
- env file: `/etc/nodepanel/service.env`
- systemd unit: `nodepanel-service`

The install and update commands can write the runtime config directly into:

```text
/etc/nodepanel/service.env
```

Supported configuration options:

- `--panel-url` / `--control-plane-url`
- `--node-id`
- `--access-token` / `--control-plane-access-token`
- `--aspnetcore-urls` / `--service-urls`

Examples:

- same host / local direct-run panel: `ws://127.0.0.1/control/ws`
- public HTTPS panel: `wss://panel.example.com/control/ws`

When the package came from GitHub Releases, the scripts keep `NODEPANEL_GITHUB_REPO` and `NODEPANEL_PACKAGE_RID` in the component env file, so later `update` can pull the matching release asset automatically.

If the service has already been installed, update the config later with:

```bash
sudo nodepanel-service configure \
  --panel-url wss://panel.example.com/control/ws \
  --node-id node-001 \
  --access-token your-token
```

The configure command updates `service.env` and restarts the service automatically.

Manual restart is still available:

```bash
sudo nodepanel-service restart
```

## Update

Panel:

```bash
sudo nodepanel-panel update /path/to/nodepanel-panel-linux-x64.tar.gz
sudo nodepanel-panel update https://downloads.example.com/nodepanel-panel-linux-x64.tar.gz
sudo nodepanel-panel update owner/repo
sudo nodepanel-panel update owner/repo@v1.2.3
sudo nodepanel-panel update
```

Service:

```bash
sudo nodepanel-service update /path/to/nodepanel-service-linux-x64.tar.gz
sudo nodepanel-service update https://downloads.example.com/nodepanel-service-linux-x64.tar.gz
sudo nodepanel-service update owner/repo
sudo nodepanel-service update owner/repo@v1.2.3
sudo nodepanel-service update
```

The scripts preserve mutable files on update:

- panel: `appsettings.json`, `server.db`, `panel-state.json`
- service: `appsettings.json`, `node-runtime-config.json`, `certificates/`

## Common Commands

```bash
sudo nodepanel-panel status
sudo nodepanel-panel log -f 200
sudo nodepanel-panel restart

sudo nodepanel-service status
sudo nodepanel-service log -f 200
sudo nodepanel-service restart
```

## Uninstall

Keep data:

```bash
sudo nodepanel-panel uninstall
sudo nodepanel-service uninstall
```

Remove everything:

```bash
sudo nodepanel-panel uninstall --purge
sudo nodepanel-service uninstall --purge
```
