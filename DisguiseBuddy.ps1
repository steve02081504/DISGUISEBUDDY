# DisguiseBuddy.ps1 - DISGUISE BUDDY Server Configuration Manager
# Main application entry point
# Version 1.0

#Requires -Version 5.1

# ============================================================================
# PRIVILEGE CHECK
# ============================================================================

# Check for Administrator privileges before proceeding
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        "DISGUISE BUDDY requires Administrator privileges.`n`nPlease right-click PowerShell and choose 'Run as Administrator', then relaunch the application.",
        "Insufficient Privileges",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}

# ============================================================================
# INITIALIZATION
# ============================================================================

# Load Windows Forms and Drawing assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Enable visual styles for modern look
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# Set DPI awareness for high-DPI displays
try {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    public class DPIAware {
        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();
    }
"@
    [DPIAware]::SetProcessDPIAware() | Out-Null
} catch {
    # Non-critical - continue without DPI awareness
}

# ============================================================================
# APPLICATION STATE (initialize before modules so they can reference it)
# ============================================================================

$script:AppState = @{
    LastAppliedProfile = ''
    LastScanResults    = @()
    CurrentView        = 'Dashboard'
}

# Holds references to action buttons exposed by the active view for keyboard shortcuts.
# New-DeployView populates this; Set-ActiveView clears it on view change.
$script:DeployViewActions = $null

# ============================================================================
# DOT-SOURCE MODULES (order matters: Theme -> UIComponents -> everything else)
#
# Each path is written as "$PSScriptRoot/modules/<name>.ps1" on purpose:
# ps12exe recognises this exact form and inlines the module into the compiled
# executable at build time, so no manual merge step is needed. Keep the paths
# in this shape (no $modulesPath indirection) or the build will silently ship
# a script that tries to dot-source files that are not next to the .exe.
# ============================================================================

# Foundation modules (must load first)
. "$PSScriptRoot/modules/Theme.ps1"
. "$PSScriptRoot/modules/UIComponents.ps1"

# Feature modules (order doesn't matter)
. "$PSScriptRoot/modules/ProfileManager.ps1"
. "$PSScriptRoot/modules/NetworkConfig.ps1"
. "$PSScriptRoot/modules/SMBConfig.ps1"
. "$PSScriptRoot/modules/ServerIdentity.ps1"
. "$PSScriptRoot/modules/Discovery.ps1"
. "$PSScriptRoot/modules/Dashboard.ps1"

Write-AppLog -Message 'DISGUISE BUDDY starting up' -Level 'INFO'

# ============================================================================
# MAIN FORM
# ============================================================================

$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = 'DISGUISE BUDDY - Server Configuration Manager'
$mainForm.Size = New-Object System.Drawing.Size(1280, 850)
$mainForm.MinimumSize = New-Object System.Drawing.Size(1100, 700)
$mainForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$mainForm.BackColor = $script:Theme.Background
$mainForm.ForeColor = $script:Theme.Text
$mainForm.Font = New-Object System.Drawing.Font('Segoe UI', 10)

# Remove default Windows title bar style for a cleaner look
$mainForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable

# Set application icon (if available)
try {
    $iconPath = Join-Path $PSScriptRoot 'icon.ico'
    if (Test-Path $iconPath) {
        $mainForm.Icon = New-Object System.Drawing.Icon($iconPath)
    }
} catch { }

# ============================================================================
# NAVIGATION SIDEBAR (Left Panel - 250px)
# ============================================================================

$navPanel = New-Object System.Windows.Forms.Panel
$navPanel.Dock = [System.Windows.Forms.DockStyle]::Left
$navPanel.Width = 250
$navPanel.BackColor = $script:Theme.NavBackground
$navPanel.Padding = New-Object System.Windows.Forms.Padding(0)

# --- App title/logo area at top of nav ---
$logoPanel = New-Object System.Windows.Forms.Panel
$logoPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$logoPanel.Height = 80
$logoPanel.BackColor = $script:Theme.NavBackground
$logoPanel.Padding = New-Object System.Windows.Forms.Padding(15, 15, 15, 10)

$appTitleLabel = New-Object System.Windows.Forms.Label
$appTitleLabel.Text = 'DISGUISE BUDDY'
$appTitleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$appTitleLabel.ForeColor = $script:Theme.Primary
$appTitleLabel.Location = New-Object System.Drawing.Point(15, 15)
$appTitleLabel.AutoSize = $true
$logoPanel.Controls.Add($appTitleLabel)

$appSubtitleLabel = New-Object System.Windows.Forms.Label
$appSubtitleLabel.Text = 'Server Configuration Manager'
$appSubtitleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
$appSubtitleLabel.ForeColor = $script:Theme.TextMuted
$appSubtitleLabel.Location = New-Object System.Drawing.Point(15, 45)
$appSubtitleLabel.AutoSize = $true
$logoPanel.Controls.Add($appSubtitleLabel)

$navPanel.Controls.Add($logoPanel)

# --- Separator line under logo ---
$navSeparator = New-Object System.Windows.Forms.Panel
$navSeparator.Dock = [System.Windows.Forms.DockStyle]::Top
$navSeparator.Height = 1
$navSeparator.BackColor = $script:Theme.Border
$navPanel.Controls.Add($navSeparator)

# --- Navigation buttons container ---
$navButtonsPanel = New-Object System.Windows.Forms.Panel
$navButtonsPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$navButtonsPanel.BackColor = $script:Theme.NavBackground
$navButtonsPanel.Padding = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)
$navPanel.Controls.Add($navButtonsPanel)

# --- Theme toggle at bottom of nav ---
$navBottomPanel = New-Object System.Windows.Forms.Panel
$navBottomPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
$navBottomPanel.Height = 90
$navBottomPanel.BackColor = $script:Theme.NavBackground

$themeToggleBtn = New-Object System.Windows.Forms.Button
$themeToggleBtn.Text = 'Toggle Theme'
$themeToggleBtn.Location = New-Object System.Drawing.Point(15, 10)
$themeToggleBtn.Size = New-Object System.Drawing.Size(220, 30)
$themeToggleBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$themeToggleBtn.FlatAppearance.BorderSize = 1
$themeToggleBtn.FlatAppearance.BorderColor = $script:Theme.Border
$themeToggleBtn.BackColor = $script:Theme.NavBackground
$themeToggleBtn.ForeColor = $script:Theme.TextMuted
$themeToggleBtn.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
$themeToggleBtn.Cursor = [System.Windows.Forms.Cursors]::Hand

$versionLabel = New-Object System.Windows.Forms.Label
$versionLabel.Text = 'v1.0 | disguise Configuration Tool'
$versionLabel.Font = New-Object System.Drawing.Font('Segoe UI', 7.5)
$versionLabel.ForeColor = $script:Theme.TextMuted
$versionLabel.Location = New-Object System.Drawing.Point(15, 50)
$versionLabel.AutoSize = $true

$navBottomPanel.Controls.Add($themeToggleBtn)
$navBottomPanel.Controls.Add($versionLabel)
$navPanel.Controls.Add($navBottomPanel)

# ============================================================================
# CONTENT PANEL (Right side - fills remaining space)
# ============================================================================

$contentPanel = New-Object System.Windows.Forms.Panel
$contentPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$contentPanel.BackColor = $script:Theme.Background
$contentPanel.Padding = New-Object System.Windows.Forms.Padding(0)

# ============================================================================
# NAVIGATION BUTTON CREATION
# ============================================================================

# Navigation item definitions: Name, DisplayText, Unicode symbol
# The & prefix enables Alt+letter WinForms access keys.
# Chosen accelerators (all unique): D, P, N, M, S, E
$navItems = @(
    @{ Name = 'Dashboard';      Display = '&Dashboard';          Symbol = [char]0x229E }  # ⊞ grid       | Alt+D
    @{ Name = 'Profiles';       Display = '&Profiles';           Symbol = [char]0x2261 }  # ≡ list       | Alt+P
    @{ Name = 'Network';        Display = '&Network Adapters';   Symbol = [char]0x2295 }  # ⊕ connection | Alt+N
    @{ Name = 'SMB';            Display = 'S&MB Sharing';        Symbol = [char]0x22A1 }  # ⊡ folder     | Alt+M
    @{ Name = 'ServerIdentity'; Display = '&Server Identity';    Symbol = [char]0x2299 }  # ⊙ server     | Alt+S
    @{ Name = 'Deploy';         Display = 'D&eploy';             Symbol = [char]0x21E2 }  # ⇢ deploy     | Alt+E
)

# Store nav buttons for state management
$script:NavButtons = @{}

# Function to create a navigation button
function New-NavButton {
    param(
        [string]$Name,
        [string]$DisplayText,
        [char]$Symbol,
        [int]$YPosition
    )

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = "  $Symbol  $DisplayText"
    $btn.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $btn.Location = New-Object System.Drawing.Point(0, $YPosition)
    $btn.Size = New-Object System.Drawing.Size(250, 42)
    $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btn.FlatAppearance.BorderSize = 0
    $btn.FlatAppearance.MouseOverBackColor = $script:Theme.NavHover
    $btn.BackColor = $script:Theme.NavBackground
    $btn.ForeColor = $script:Theme.TextSecondary
    $btn.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btn.Tag = $Name

    # Hover effects
    $btn.Add_MouseEnter({
        if ($this.Tag -ne $script:AppState.CurrentView) {
            $this.BackColor = $script:Theme.NavHover
            $this.ForeColor = $script:Theme.Text
        }
    })
    $btn.Add_MouseLeave({
        if ($this.Tag -ne $script:AppState.CurrentView) {
            $this.BackColor = $script:Theme.NavBackground
            $this.ForeColor = $script:Theme.TextSecondary
        }
    })

    return $btn
}

# Create navigation buttons
$yPos = 5
foreach ($item in $navItems) {
    $navBtn = New-NavButton -Name $item.Name -DisplayText $item.Display -Symbol $item.Symbol -YPosition $yPos
    $script:NavButtons[$item.Name] = $navBtn
    $navButtonsPanel.Controls.Add($navBtn)
    $yPos += 44
}

# ============================================================================
# VIEW SWITCHING LOGIC
# ============================================================================

function Set-ActiveView {
    param([string]$ViewName)

    # Clear any view-specific action references before loading a new view
    $script:DeployViewActions = $null

    # Update visual state of nav buttons
    foreach ($key in $script:NavButtons.Keys) {
        $btn = $script:NavButtons[$key]
        if ($key -eq $ViewName) {
            # Active button styling
            $btn.BackColor = $script:Theme.NavActive
            $btn.ForeColor = [System.Drawing.Color]::White
            $btn.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
        } else {
            # Inactive button styling
            $btn.BackColor = $script:Theme.NavBackground
            $btn.ForeColor = $script:Theme.TextSecondary
            $btn.Font = New-Object System.Drawing.Font('Segoe UI', 10)
        }
    }

    # Update state
    $script:AppState.CurrentView = $ViewName

    # Load the requested view directly into the content panel.
    # Each view creates its own scroll panel internally -- do NOT add
    # another wrapper here (nested AutoScroll panels fight each other).
    $contentPanel.SuspendLayout()
    $contentPanel.Controls.Clear()

    switch ($ViewName) {
        'Dashboard'      { New-DashboardView -ContentPanel $contentPanel }
        'Profiles'       { New-ProfilesView -ContentPanel $contentPanel }
        'Network'        { New-NetworkView -ContentPanel $contentPanel }
        'SMB'            { New-SMBView -ContentPanel $contentPanel }
        'ServerIdentity' { New-ServerIdentityView -ContentPanel $contentPanel }
        'Deploy'         { New-DeployView -ContentPanel $contentPanel }
    }

    $contentPanel.ResumeLayout()

    Write-AppLog -Message "Switched to view: $ViewName" -Level 'DEBUG'
}

# Wire up click events for each nav button
foreach ($key in $script:NavButtons.Keys) {
    $btn = $script:NavButtons[$key]
    $btn.Add_Click({
        Set-ActiveView -ViewName $this.Tag
    })
}

# ============================================================================
# THEME TOGGLE
# ============================================================================

$themeToggleBtn.Add_Click({
    if ($script:Theme -eq $script:DarkTheme) {
        Set-AppTheme -ThemeName 'Light'
    } else {
        Set-AppTheme -ThemeName 'Dark'
    }

    # Recursively update all controls in the form with new theme colors
    Update-ControlTheme -Control $mainForm

    # Re-apply nav-specific colors that Update-ControlTheme can't infer from Tags
    $navPanel.BackColor = $script:Theme.NavBackground
    $logoPanel.BackColor = $script:Theme.NavBackground
    $appTitleLabel.ForeColor = $script:Theme.Primary
    $appSubtitleLabel.ForeColor = $script:Theme.TextMuted
    $navSeparator.BackColor = $script:Theme.Border
    $navButtonsPanel.BackColor = $script:Theme.NavBackground
    $navBottomPanel.BackColor = $script:Theme.NavBackground
    $themeToggleBtn.BackColor = $script:Theme.NavBackground
    $themeToggleBtn.ForeColor = $script:Theme.TextMuted
    $themeToggleBtn.FlatAppearance.BorderColor = $script:Theme.Border
    $versionLabel.ForeColor = $script:Theme.TextMuted

    # Re-render current view to rebuild all content with new theme
    Set-ActiveView -ViewName $script:AppState.CurrentView

    Write-AppLog -Message "Theme toggled to: $(Get-AppThemeName)" -Level 'INFO'
})

# ============================================================================
# FORM ASSEMBLY
# ============================================================================

# Add panels to form (order matters for docking)
$mainForm.Controls.Add($contentPanel)  # Fill - must be added first
$mainForm.Controls.Add($navPanel)      # Left dock

# ============================================================================
# KEYBOARD SHORTCUTS
# ============================================================================

# Enable the form to intercept key events before child controls handle them
$mainForm.KeyPreview = $true

# Global key handler
# Ctrl+1..6  : navigate to views in order
# F5         : refresh/scan (scan if on Deploy view, otherwise reload current view)
# Ctrl+Enter : trigger deploy (Deploy view only)
# Escape     : close any open modal dialog
$mainForm.Add_KeyDown({
    param($sender, $e)

    $view = $script:AppState.CurrentView

    switch ($e.KeyCode) {

        # --- Ctrl+1 through Ctrl+6 : navigate to views ---
        ([System.Windows.Forms.Keys]::D1) {
            if ($e.Control) {
                Set-ActiveView -ViewName 'Dashboard'
                $e.Handled = $true
                $e.SuppressKeyPress = $true
            }
        }
        ([System.Windows.Forms.Keys]::D2) {
            if ($e.Control) {
                Set-ActiveView -ViewName 'Profiles'
                $e.Handled = $true
                $e.SuppressKeyPress = $true
            }
        }
        ([System.Windows.Forms.Keys]::D3) {
            if ($e.Control) {
                Set-ActiveView -ViewName 'Network'
                $e.Handled = $true
                $e.SuppressKeyPress = $true
            }
        }
        ([System.Windows.Forms.Keys]::D4) {
            if ($e.Control) {
                Set-ActiveView -ViewName 'SMB'
                $e.Handled = $true
                $e.SuppressKeyPress = $true
            }
        }
        ([System.Windows.Forms.Keys]::D5) {
            if ($e.Control) {
                Set-ActiveView -ViewName 'ServerIdentity'
                $e.Handled = $true
                $e.SuppressKeyPress = $true
            }
        }
        ([System.Windows.Forms.Keys]::D6) {
            if ($e.Control) {
                Set-ActiveView -ViewName 'Deploy'
                $e.Handled = $true
                $e.SuppressKeyPress = $true
            }
        }

        # --- F5 : scan (Deploy view) or refresh current view ---
        ([System.Windows.Forms.Keys]::F5) {
            if ($view -eq 'Deploy' -and $script:DeployViewActions -and $script:DeployViewActions.ScanButton -and $script:DeployViewActions.ScanButton.Enabled) {
                $script:DeployViewActions.ScanButton.PerformClick()
            } else {
                Set-ActiveView -ViewName $view
            }
            $e.Handled = $true
            $e.SuppressKeyPress = $true
        }

        # --- Ctrl+Enter : trigger deploy (Deploy view only) ---
        ([System.Windows.Forms.Keys]::Return) {
            if ($e.Control -and $view -eq 'Deploy' -and $script:DeployViewActions -and $script:DeployViewActions.DeployButton -and $script:DeployViewActions.DeployButton.Enabled) {
                $script:DeployViewActions.DeployButton.PerformClick()
                $e.Handled = $true
                $e.SuppressKeyPress = $true
            }
        }

        # --- Escape : close any open modal (SendKeys approach) ---
        ([System.Windows.Forms.Keys]::Escape) {
            # Let Escape propagate naturally -- WinForms modal dialogs handle it
            # via their CancelButton or DialogResult. Nothing to do here unless
            # a non-standard popup is open.
        }
    }
})

# ============================================================================
# STARTUP
# ============================================================================

# Load saved theme preference (if any) before rendering the first view
Import-ThemePreference

# Apply loaded theme to all existing controls before the first view render
$mainForm.BackColor = $script:Theme.Background
$mainForm.ForeColor = $script:Theme.Text
$navPanel.BackColor = $script:Theme.NavBackground
$logoPanel.BackColor = $script:Theme.NavBackground
$appTitleLabel.ForeColor = $script:Theme.Primary
$appSubtitleLabel.ForeColor = $script:Theme.TextMuted
$navSeparator.BackColor = $script:Theme.Border
$navButtonsPanel.BackColor = $script:Theme.NavBackground
$navBottomPanel.BackColor = $script:Theme.NavBackground
$themeToggleBtn.BackColor = $script:Theme.NavBackground
$themeToggleBtn.ForeColor = $script:Theme.TextMuted
$themeToggleBtn.FlatAppearance.BorderColor = $script:Theme.Border
$versionLabel.ForeColor = $script:Theme.TextMuted
$contentPanel.BackColor = $script:Theme.Background

# Update nav buttons with loaded theme
foreach ($key in $script:NavButtons.Keys) {
    $btn = $script:NavButtons[$key]
    $btn.BackColor = $script:Theme.NavBackground
    $btn.ForeColor = $script:Theme.TextSecondary
    $btn.FlatAppearance.MouseOverBackColor = $script:Theme.NavHover
}

# Load default view
Set-ActiveView -ViewName 'Dashboard'

# Handle form closing
$mainForm.Add_FormClosing({
    Write-AppLog -Message 'DISGUISE BUDDY shutting down' -Level 'INFO'
})

Write-AppLog -Message 'DISGUISE BUDDY initialized successfully' -Level 'INFO'

# ============================================================================
# RUN APPLICATION
# ============================================================================

[System.Windows.Forms.Application]::Run($mainForm)
