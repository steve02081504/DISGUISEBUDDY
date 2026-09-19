# Theme.ps1 - DISGUISE BUDDY Theme System

# Centralized path resolution
function Get-AppRootPath {
    if ($script:AppRootPath) { return $script:AppRootPath }
    $script:AppRootPath = if ($PSScriptRoot) {
        # Running from source: this file lives in modules/, so the app root is
        # its parent. Compiled with ps12exe: modules are inlined into the entry
        # script, so $PSScriptRoot is the .exe directory, which IS the app root.
        if ((Split-Path -Path $PSScriptRoot -Leaf) -ieq 'modules') {
            Split-Path -Path $PSScriptRoot -Parent
        } else {
            $PSScriptRoot
        }
    } else {
        $PWD.Path
    }
    return $script:AppRootPath
}

# Dark theme (default) - matches Electron/React UI design system
$script:DarkTheme = @{
    Background        = [System.Drawing.ColorTranslator]::FromHtml('#0F0F14')
    Surface           = [System.Drawing.ColorTranslator]::FromHtml('#1A1A24')
    SurfaceLight      = [System.Drawing.ColorTranslator]::FromHtml('#2A2A3C')
    Primary           = [System.Drawing.ColorTranslator]::FromHtml('#7C3AED')
    PrimaryLight      = [System.Drawing.ColorTranslator]::FromHtml('#8B5CF6')
    PrimaryDark       = [System.Drawing.ColorTranslator]::FromHtml('#6D28D9')
    Accent            = [System.Drawing.ColorTranslator]::FromHtml('#06B6D4')
    Text              = [System.Drawing.ColorTranslator]::FromHtml('#E2E8F0')
    TextSecondary     = [System.Drawing.ColorTranslator]::FromHtml('#94A3B8')
    TextMuted         = [System.Drawing.ColorTranslator]::FromHtml('#64748B')
    Success           = [System.Drawing.ColorTranslator]::FromHtml('#10B981')
    Warning           = [System.Drawing.ColorTranslator]::FromHtml('#F59E0B')
    Error             = [System.Drawing.ColorTranslator]::FromHtml('#EF4444')
    SuccessBackground = [System.Drawing.ColorTranslator]::FromHtml('#0D3B2E')
    WarningBackground = [System.Drawing.ColorTranslator]::FromHtml('#3B2E0D')
    ErrorBackground   = [System.Drawing.ColorTranslator]::FromHtml('#3B0D0D')
    Border            = [System.Drawing.ColorTranslator]::FromHtml('#2A2A3C')
    BorderLight       = [System.Drawing.ColorTranslator]::FromHtml('#3F3F5C')
    NavBackground     = [System.Drawing.ColorTranslator]::FromHtml('#0C0C16')
    NavHover          = [System.Drawing.ColorTranslator]::FromHtml('#1A1A24')
    NavActive         = [System.Drawing.ColorTranslator]::FromHtml('#7C3AED')
    CardBackground    = [System.Drawing.ColorTranslator]::FromHtml('#1E1E2E')
    InputBackground   = [System.Drawing.ColorTranslator]::FromHtml('#1A1A24')
    InputBorder       = [System.Drawing.ColorTranslator]::FromHtml('#2A2A3C')
    Scrollbar         = [System.Drawing.ColorTranslator]::FromHtml('#2A2A3C')
}

# Light theme
$script:LightTheme = @{
    Background        = [System.Drawing.ColorTranslator]::FromHtml('#F8FAFC')
    Surface           = [System.Drawing.ColorTranslator]::FromHtml('#FFFFFF')
    SurfaceLight      = [System.Drawing.ColorTranslator]::FromHtml('#F1F5F9')
    Primary           = [System.Drawing.ColorTranslator]::FromHtml('#7C3AED')
    PrimaryLight      = [System.Drawing.ColorTranslator]::FromHtml('#8B5CF6')
    PrimaryDark       = [System.Drawing.ColorTranslator]::FromHtml('#6D28D9')
    Accent            = [System.Drawing.ColorTranslator]::FromHtml('#0891B2')
    Text              = [System.Drawing.ColorTranslator]::FromHtml('#1E293B')
    TextSecondary     = [System.Drawing.ColorTranslator]::FromHtml('#475569')
    TextMuted         = [System.Drawing.ColorTranslator]::FromHtml('#94A3B8')
    Success           = [System.Drawing.ColorTranslator]::FromHtml('#059669')
    Warning           = [System.Drawing.ColorTranslator]::FromHtml('#D97706')
    Error             = [System.Drawing.ColorTranslator]::FromHtml('#DC2626')
    SuccessBackground = [System.Drawing.ColorTranslator]::FromHtml('#ECFDF5')
    WarningBackground = [System.Drawing.ColorTranslator]::FromHtml('#FFFBEB')
    ErrorBackground   = [System.Drawing.ColorTranslator]::FromHtml('#FEF2F2')
    Border            = [System.Drawing.ColorTranslator]::FromHtml('#E2E8F0')
    BorderLight       = [System.Drawing.ColorTranslator]::FromHtml('#CBD5E1')
    NavBackground     = [System.Drawing.ColorTranslator]::FromHtml('#FFFFFF')
    NavHover          = [System.Drawing.ColorTranslator]::FromHtml('#F1F5F9')
    NavActive         = [System.Drawing.ColorTranslator]::FromHtml('#7C3AED')
    CardBackground    = [System.Drawing.ColorTranslator]::FromHtml('#FFFFFF')
    InputBackground   = [System.Drawing.ColorTranslator]::FromHtml('#F8FAFC')
    InputBorder       = [System.Drawing.ColorTranslator]::FromHtml('#CBD5E1')
    Scrollbar         = [System.Drawing.ColorTranslator]::FromHtml('#E2E8F0')
}

# Current active theme
$script:Theme = $script:DarkTheme

function Set-AppTheme {
    param([string]$ThemeName)
    if ($ThemeName -eq 'Light') {
        $script:Theme = $script:LightTheme
    } else {
        $script:Theme = $script:DarkTheme
    }

    # Persist theme preference
    Save-ThemePreference -ThemeName $ThemeName
}

function Get-AppThemeName {
    <#
    .SYNOPSIS
        Returns the name of the currently active theme ('Dark' or 'Light').
    #>
    if ($script:Theme -eq $script:LightTheme) {
        return 'Light'
    } else {
        return 'Dark'
    }
}

# ============================================================================
# THEME PERSISTENCE
# ============================================================================

function Save-ThemePreference {
    <#
    .SYNOPSIS
        Saves the user's theme preference to settings/theme.json.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ThemeName
    )

    $scriptRoot = Get-AppRootPath
    $settingsDir = Join-Path -Path $scriptRoot -ChildPath 'settings'
    $settingsFile = Join-Path -Path $settingsDir -ChildPath 'theme.json'

    # Ensure the settings directory exists
    if (-not (Test-Path -Path $settingsDir)) {
        New-Item -Path $settingsDir -ItemType Directory -Force | Out-Null
    }

    $themeData = @{ Theme = $ThemeName } | ConvertTo-Json
    try {
        Set-Content -Path $settingsFile -Value $themeData -Encoding UTF8
    } catch {
        Write-AppLog -Message "Failed to save theme preference: $_" -Level 'WARN'
    }
}

function Import-ThemePreference {
    <#
    .SYNOPSIS
        Loads the user's saved theme preference from settings/theme.json.
        If no saved preference exists, keeps the current (default) theme.
    #>
    $scriptRoot = Get-AppRootPath
    $settingsFile = Join-Path -Path $scriptRoot -ChildPath 'settings' | Join-Path -ChildPath 'theme.json'

    if (Test-Path -Path $settingsFile) {
        try {
            $themeData = Get-Content -Path $settingsFile -Raw | ConvertFrom-Json
            if ($themeData.Theme -eq 'Light') {
                $script:Theme = $script:LightTheme
            } else {
                $script:Theme = $script:DarkTheme
            }
            Write-AppLog -Message "Loaded saved theme preference: $($themeData.Theme)" -Level 'DEBUG'
        } catch {
            Write-AppLog -Message "Failed to load theme preference: $_" -Level 'WARN'
        }
    }
}

# ============================================================================
# RECURSIVE CONTROL THEME UPDATER
# ============================================================================

function Update-ControlTheme {
    <#
    .SYNOPSIS
        Recursively walks a control tree and applies current theme colors
        to all controls based on their type and Tag property.
    .PARAMETER Control
        The root control to begin updating from. Typically the main form.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.Control]$Control
    )

    # Update the control based on its type
    switch ($Control.GetType().Name) {
        'Form' {
            $Control.BackColor = $script:Theme.Background
            $Control.ForeColor = $script:Theme.Text
        }

        'Panel' {
            # Determine panel type from Tag or current styling context
            switch ($Control.Tag) {
                'Card' {
                    $Control.BackColor = $script:Theme.CardBackground
                }
                'Nav' {
                    $Control.BackColor = $script:Theme.NavBackground
                }
                'NavSeparator' {
                    $Control.BackColor = $script:Theme.Border
                }
                'Surface' {
                    $Control.BackColor = $script:Theme.Surface
                }
                default {
                    # Check if the panel is acting as a card (has CardBackground-like padding)
                    # or a generic container; preserve transparent panels
                    if ($Control.BackColor -ne [System.Drawing.Color]::Transparent) {
                        $Control.BackColor = $script:Theme.Background
                    }
                }
            }
        }

        'GroupBox' {
            $Control.BackColor = $script:Theme.Surface
            $Control.ForeColor = $script:Theme.Text
        }

        'Label' {
            # Determine label color based on Tag
            switch ($Control.Tag) {
                'Muted' {
                    $Control.ForeColor = $script:Theme.TextMuted
                }
                'Secondary' {
                    $Control.ForeColor = $script:Theme.TextSecondary
                }
                'Primary' {
                    $Control.ForeColor = $script:Theme.Primary
                }
                'Success' {
                    $Control.ForeColor = [System.Drawing.Color]::White
                    $Control.BackColor = $script:Theme.Success
                }
                'Warning' {
                    $Control.ForeColor = [System.Drawing.Color]::White
                    $Control.BackColor = $script:Theme.Warning
                }
                'Error' {
                    $Control.ForeColor = [System.Drawing.Color]::White
                    $Control.BackColor = $script:Theme.Error
                }
                'Info' {
                    $Control.ForeColor = [System.Drawing.Color]::White
                    $Control.BackColor = $script:Theme.Accent
                }
                default {
                    $Control.ForeColor = $script:Theme.Text
                }
            }
        }

        'Button' {
            # Determine button style from Tag (set by New-StyledButton)
            switch ($Control.Tag) {
                'Primary' {
                    $Control.BackColor = $script:Theme.Primary
                    $Control.ForeColor = [System.Drawing.Color]::White
                }
                'Destructive' {
                    $Control.BackColor = $script:Theme.Error
                    $Control.ForeColor = [System.Drawing.Color]::White
                }
                'NavButton' {
                    # Nav buttons are handled separately by Set-ActiveView
                    $Control.FlatAppearance.MouseOverBackColor = $script:Theme.NavHover
                }
                default {
                    $Control.BackColor = $script:Theme.Surface
                    $Control.ForeColor = $script:Theme.Text
                }
            }
            # Update border color if the button has a flat border
            if ($Control.FlatStyle -eq [System.Windows.Forms.FlatStyle]::Flat -and
                $Control.FlatAppearance.BorderSize -gt 0) {
                $Control.FlatAppearance.BorderColor = $script:Theme.Border
            }
        }

        'TextBox' {
            $Control.BackColor = $script:Theme.InputBackground
            # If the textbox is showing placeholder text (ForeColor matches TextMuted),
            # keep it muted; otherwise use normal text color
            if ($Control.Tag -and $Control.Text -eq $Control.Tag) {
                $Control.ForeColor = $script:Theme.TextMuted
            } else {
                $Control.ForeColor = $script:Theme.Text
            }
        }

        'ComboBox' {
            $Control.BackColor = $script:Theme.InputBackground
            $Control.ForeColor = $script:Theme.Text
        }

        'CheckBox' {
            $Control.ForeColor = $script:Theme.Text
        }

        'DataGridView' {
            $dgv = $Control
            $dgv.BackgroundColor = $script:Theme.Surface
            $dgv.GridColor = $script:Theme.Border

            # Default cell style
            $dgv.DefaultCellStyle.BackColor = $script:Theme.Surface
            $dgv.DefaultCellStyle.ForeColor = $script:Theme.Text
            $dgv.DefaultCellStyle.SelectionBackColor = $script:Theme.Primary
            $dgv.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White

            # Column header style
            $dgv.ColumnHeadersDefaultCellStyle.BackColor = $script:Theme.NavBackground
            $dgv.ColumnHeadersDefaultCellStyle.ForeColor = $script:Theme.Text
            $dgv.ColumnHeadersDefaultCellStyle.SelectionBackColor = $script:Theme.NavBackground
            $dgv.ColumnHeadersDefaultCellStyle.SelectionForeColor = $script:Theme.Text

            # Alternating row style
            $dgv.AlternatingRowsDefaultCellStyle.BackColor = $script:Theme.CardBackground
        }
    }

    # Recurse into child controls
    foreach ($child in $Control.Controls) {
        Update-ControlTheme -Control $child
    }
}

function Write-AppLog {
    <#
    .SYNOPSIS
        Writes a timestamped log message to the DISGUISE BUDDY log file.
    .DESCRIPTION
        Appends a formatted log entry with timestamp and severity level to
        logs/disguisebuddy.log relative to the script root directory.
    .PARAMETER Message
        The log message text to write.
    .PARAMETER Level
        The severity level of the log entry. Valid values: INFO, WARN, ERROR, DEBUG.
        Defaults to INFO.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    # Determine the script root directory
    # $PSScriptRoot is set when the script is dot-sourced; fall back to current directory
    $scriptRoot = Get-AppRootPath

    $logDir = Join-Path -Path $scriptRoot -ChildPath 'logs'
    $logFile = Join-Path -Path $logDir -ChildPath 'disguisebuddy.log'

    # Ensure the logs directory exists
    if (-not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    # Log rotation - rotate if over 10MB
    if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt 10MB) {
        try {
            $archiveName = [System.IO.Path]::GetFileNameWithoutExtension($logFile)
            $archivePath = Join-Path $logDir "$archiveName-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
            Move-Item -Path $logFile -Destination $archivePath -Force
            # Keep only last 5 archives
            Get-ChildItem $logDir -Filter "$archiveName-*.log" |
                Sort-Object LastWriteTime -Descending |
                Select-Object -Skip 5 |
                Remove-Item -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Log rotation failed: $_"
        }
    }

    # Format the log entry with timestamp, level, and message
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $logEntry = "[$timestamp] [$Level] $Message"

    # Append the entry to the log file
    try {
        Add-Content -Path $logFile -Value $logEntry -Encoding UTF8
    } catch {
        # If logging fails, write to console as a fallback
        Write-Warning "Failed to write to log file: $_"
        Write-Warning "Log entry was: $logEntry"
    }
}
