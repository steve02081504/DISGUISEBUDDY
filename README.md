# DISGUISEBUDDY

A companion tool for managing and configuring **disguise (d3) media servers**. Provides two interfaces for server setup, network configuration, and fleet deployment.

## Features

- **Server Profiles** — Save and apply named configurations (hostname, network adapters, roles)
- **Network Configuration** — Configure IP addresses, subnets, and DHCP for up to 6 adapters per server
- **SMB File Shares** — Manage d3 Projects shares for media distribution
- **Telemetry Monitoring** — Real-time d3 server health and performance data
- **BMC / IPMI Management** — Out-of-band server management
- **Network Discovery & Deployment** — Scan subnets for d3 servers and push profiles remotely

## Interfaces

### PowerShell WinForms (DisguiseBuddy.ps1)

Native Windows GUI built with `System.Windows.Forms`. No external dependencies.

```powershell
# Run as Administrator (required for network/hostname changes)
.\DisguiseBuddy.ps1
```

### React / Electron Web UI (disguise-buddy-ui/)

Modern web-based desktop app with an Express API backend.

```bash
cd disguise-buddy-ui
npm install
npm run start          # API server + Vite dev server
npm run electron:dev   # Full Electron app
```

## Prerequisites

- **Windows 10/11** (or Windows Server)
- **PowerShell 5.1+** (for PowerShell interface)
- **Node.js 18+** (for Electron/React interface)
- **Administrator privileges** (for system configuration changes)

## Build

### React / Electron installer

```bash
cd disguise-buddy-ui
npm run electron:build
```

Output: `disguise-buddy-ui/dist-installer/`

### Standalone PowerShell executable

```powershell
# Requires PowerShell 5.1+; installs ps12exe automatically if missing
.\Build-Executable.ps1
```

`ps12exe` compiles `DisguiseBuddy.ps1` — inlining the `modules\` it dot-sources — into `dist\`:

- `DisguiseBuddy.exe` — GUI launcher (requests UAC elevation)
- `DisguiseBuddy-console.exe` — the same app with a visible console, for troubleshooting

Distribute the whole `dist\` folder: the executable reads and writes `profiles\` next to it at runtime.
