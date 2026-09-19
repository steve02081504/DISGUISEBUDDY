# Build-Executable.ps1
# DISGUISE BUDDY - Executable Build Script
#
# Run this on Windows with PowerShell 5.1+.
# ps12exe compiles DisguiseBuddy.ps1 straight into a standalone .exe. The
# dot-sourced modules under modules/ are inlined automatically at build time
# (ps12exe rewrites the "$PSScriptRoot/modules/*.ps1" includes), so there is no
# merge step and no path patching to keep in sync.
#
# Usage:
#   .\Build-Executable.ps1
#   .\Build-Executable.ps1 -OutputDir "C:\MyBuilds"
#   .\Build-Executable.ps1 -SkipInstallCheck
#
# Output:
#   dist\
#     DisguiseBuddy.exe          <- double-click launcher (UAC elevation, GUI)
#     DisguiseBuddy-console.exe  <- same app with a visible console, for troubleshooting
#     profiles\                  <- shipped alongside exe (read/write at runtime)
#       Actor-01.json
#       ... (all profiles)
#
# Prerequisites (installed automatically if missing):
#   ps12exe  (Install-Module ps12exe -Scope CurrentUser)

#Requires -Version 5.1

[CmdletBinding()]
param(
    # Where to write the finished build. Defaults to .\dist next to this script.
    [string]$OutputDir = (Join-Path $PSScriptRoot 'dist'),

    # Skip ps12exe availability check (useful if it is installed but not on PATH).
    [switch]$SkipInstallCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# CONFIGURATION
# ============================================================================

$AppName        = 'DisguiseBuddy'
$AppVersion     = '1.0.0.0'
$AppDescription = 'DISGUISE BUDDY - Server Configuration Manager'
$AppCompany     = 'disguise'
$AppCopyright   = "Copyright $((Get-Date).Year) disguise"
$IconPath       = Join-Path $PSScriptRoot 'icon.ico'   # optional - skipped if absent
$EntryScript    = Join-Path $PSScriptRoot 'DisguiseBuddy.ps1'
$ExeOutput      = Join-Path $OutputDir "$AppName.exe"
$ConsoleExe     = Join-Path $OutputDir "$AppName-console.exe"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Step {
    param([string]$Message)
    Write-Host "`n  >> $Message" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Message)
    Write-Host "     OK  $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "     FAIL  $Message" -ForegroundColor Red
}

# ============================================================================
# STEP 1 - Verify ps12exe is available
# ============================================================================

Write-Step 'Checking for ps12exe'

if (-not $SkipInstallCheck) {
    if (-not (Get-Module -ListAvailable -Name ps12exe)) {
        Write-Host '     ps12exe not found. Installing from PSGallery...' -ForegroundColor Yellow

        # Ensure NuGet provider is available (required on fresh systems)
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget -or $nuget.Version -lt [Version]'2.8.5.201') {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }

        Install-Module -Name ps12exe -Scope CurrentUser -Force -AllowClobber
        Write-OK 'ps12exe installed'
    } else {
        Write-OK 'ps12exe already available'
    }
}

Import-Module ps12exe -ErrorAction Stop

# ============================================================================
# STEP 2 - Validate source files
# ============================================================================

Write-Step 'Validating source files'

if (-not (Test-Path -Path $EntryScript -PathType Leaf)) {
    Write-Fail "Missing entry script: $EntryScript"
    exit 1
}

# ps12exe inlines every "$PSScriptRoot/modules/*.ps1" dot-source it finds in the
# entry script. Parse those references and fail early if a module is missing.
$entryText = Get-Content -Path $EntryScript -Raw -Encoding UTF8
$moduleRefs = @(
    [regex]::Matches($entryText, '\$PSScriptRoot[/\\]modules[/\\](?<name>[\w.-]+\.ps1)') |
        ForEach-Object { $_.Groups['name'].Value } | Select-Object -Unique
)

if ($moduleRefs.Count -eq 0) {
    Write-Fail "No `$PSScriptRoot/modules/*.ps1 dot-sources found in $EntryScript - ps12exe has nothing to inline."
    exit 1
}

$missing = @($moduleRefs | Where-Object { -not (Test-Path (Join-Path $PSScriptRoot "modules/$_") -PathType Leaf) })
if ($missing.Count -gt 0) {
    Write-Fail "Missing module(s): $($missing -join ', ')"
    exit 1
}
Write-OK "All $($moduleRefs.Count) module(s) present"

$profilesDir = Join-Path $PSScriptRoot 'profiles'
$profiles = @(Get-ChildItem $profilesDir -Filter '*.json' -ErrorAction SilentlyContinue)
if ($profiles.Count -eq 0) {
    Write-Fail "No .json profiles found in $profilesDir"
    exit 1
}
Write-OK "$($profiles.Count) profile(s) found"

# ============================================================================
# STEP 3 - Prepare output directory
# ============================================================================

Write-Step 'Preparing output directory'

if (Test-Path $OutputDir) {
    # Safety check: only remove the output directory if it is within the project tree
    $resolvedOutput = [System.IO.Path]::GetFullPath($OutputDir)
    $resolvedProject = [System.IO.Path]::GetFullPath($PSScriptRoot)
    if (-not $resolvedOutput.StartsWith($resolvedProject + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -and
        $resolvedOutput -ne $resolvedProject) {
        Write-Fail "Safety check failed: OutputDir '$resolvedOutput' is outside the project directory '$resolvedProject'. Aborting."
        exit 1
    }
    Remove-Item $OutputDir -Recurse -Force
}
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

# Copy profiles directory (must ship alongside exe — writable at runtime)
$destProfiles = Join-Path $OutputDir 'profiles'
Copy-Item -Path $profilesDir -Destination $destProfiles -Recurse -Force
Write-OK "Copied profiles/ ($($profiles.Count) files)"

# Copy icon if present (also used as the compiled exe icon below)
if (Test-Path $IconPath) {
    Copy-Item -Path $IconPath -Destination (Join-Path $OutputDir 'icon.ico') -Force
    Write-OK 'Copied icon.ico'
}

# ============================================================================
# STEP 4 - Compile with ps12exe
#
# ps12exe resolves the script's "$PSScriptRoot/modules/*.ps1" dot-sources,
# inlines them, and embeds the merged script as a resource in the .exe.
# At runtime $PSScriptRoot points at the .exe directory, where we ship
# profiles/ (Get-AppRootPath in Theme.ps1 accounts for both layouts).
#
# Two executables are produced from the same source:
#   - DisguiseBuddy.exe:         windowed GUI (normal use)
#   - DisguiseBuddy-console.exe: visible console (troubleshooting; replaces the
#     old hand-written .bat fallback launcher)
# ============================================================================

Write-Step 'Compiling with ps12exe'

function Invoke-Ps12ExeBuild {
    param(
        [hashtable]$Overrides,
        [string]$Label
    )

    $resources = @{
        Title       = $AppName
        Description = $AppDescription
        Version     = $AppVersion
        Company     = $AppCompany
        Product     = $AppName
        Copyright   = $AppCopyright
    }
    if (Test-Path $IconPath) {
        $resources['Icon'] = $IconPath
    }

    $compileParams = @{
        inputFile  = $EntryScript
        Os         = @{
            Admin = $true        # Embeds UAC manifest: requestedExecutionLevel = requireAdministrator
        }
        Build      = @{
            # x64 is correct for disguise servers; change to x86 only if targeting 32-bit systems
            Platform = 'x64'
        }
        Resources  = $resources
        # Skip the online version check so builds stay deterministic/offline-friendly
        NoUpdateCheck = $true
    }

    foreach ($key in $Overrides.Keys) {
        $compileParams[$key] = $Overrides[$key]
    }

    try {
        ps12exe @compileParams
        Write-OK "Compiled ($Label): $($compileParams.outputFile)"
    } catch {
        Write-Fail "Compilation failed ($Label): $_"
        exit 1
    }
}

Invoke-Ps12ExeBuild -Label 'GUI' -Overrides @{
    outputFile = $ExeOutput
    App        = @{
        Windowed = $true        # GUI app - hide the console window
        DpiAware = $true        # DPI-aware so the form renders crisp on high-DPI displays
    }
}

Invoke-Ps12ExeBuild -Label 'console' -Overrides @{
    outputFile = $ConsoleExe
    App        = @{
        Windowed = $false       # Keep the console attached for diagnostics
    }
}

# ============================================================================
# STEP 5 - Summary
# ============================================================================

Write-Host ''
Write-Host '  BUILD COMPLETE' -ForegroundColor Green
Write-Host ''
Write-Host "  Output directory : $OutputDir"
Write-Host ''
Write-Host '  Contents:'
Get-ChildItem $OutputDir | ForEach-Object {
    $size = if ($_.PSIsContainer) { "(dir)" } else { "$([math]::Round($_.Length / 1KB))KB" }
    Write-Host "    $($_.Name.PadRight(30)) $size"
}
Write-Host ''
Write-Host '  Distribute the entire dist\ folder — the .exe requires profiles\ alongside it.'
Write-Host '  Users double-click DisguiseBuddy.exe; Windows UAC will prompt for elevation.'
Write-Host '  If the GUI misbehaves, run DisguiseBuddy-console.exe to see the output live.'
Write-Host ''
