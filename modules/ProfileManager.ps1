# ============================================================================
# ProfileManager.ps1 - DISGUISE BUDDY Profile Management Module
# Purpose: Manage configuration profiles for disguise (d3) media servers.
#          Profiles store hostname, network adapter IPs, SMB sharing settings,
#          and custom settings as JSON files in the profiles/ directory.
# Dependencies: Theme.ps1 (for $script:Theme), UIComponents.ps1 (for New-Styled* functions)
# ============================================================================

# ============================================================================
# BACKEND FUNCTIONS - Profile Data Management
# ============================================================================

function Get-ProfilesDirectory {
    <#
    .SYNOPSIS
        Returns the absolute path to the profiles directory.
    .DESCRIPTION
        Resolves the profiles directory relative to the module location.
        Creates the directory if it does not exist.
    .OUTPUTS
        [string] - Absolute path to profiles/ directory.
    #>
    $profilesDir = Join-Path -Path (Get-AppRootPath) -ChildPath 'profiles'

    # Normalize the path to resolve the ".." segment
    $profilesDir = [System.IO.Path]::GetFullPath($profilesDir)

    # Ensure the directory exists
    if (-not (Test-Path -Path $profilesDir)) {
        New-Item -Path $profilesDir -ItemType Directory -Force | Out-Null
        Write-AppLog "Created profiles directory: $profilesDir" -Level 'INFO'
    }

    return $profilesDir
}


function New-DefaultProfile {
    <#
    .SYNOPSIS
        Creates a new profile object populated with default disguise server values.
    .PARAMETER Name
        The name for the new profile.
    .PARAMETER Description
        Optional description for the profile.
    .OUTPUTS
        [PSCustomObject] - A profile object matching the standard JSON schema.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    $now = (Get-Date).ToString('o')

    $profile = [PSCustomObject]@{
        Name            = $Name
        Description     = $Description
        Created         = $now
        Modified        = $now
        ServerName      = "D3-SERVER-01"
        NetworkAdapters = @(
            [PSCustomObject]@{
                Index       = 0
                Role        = "d3Net"
                DisplayName = "NIC A - d3 Network"
                AdapterName = "NIC A"
                IPAddress   = "192.168.10.11"
                SubnetMask  = "255.255.255.0"
                Gateway     = ""
                DNS1        = ""
                DNS2        = ""
                DHCP        = $false
                VLANID      = $null
                Enabled     = $true
            },
            [PSCustomObject]@{
                Index       = 1
                Role        = "sACN"
                DisplayName = "NIC B - Lighting (sACN/Art-Net)"
                AdapterName = "NIC B"
                IPAddress   = ""
                SubnetMask  = ""
                Gateway     = ""
                DNS1        = ""
                DNS2        = ""
                DHCP        = $true
                VLANID      = $null
                Enabled     = $true
            },
            [PSCustomObject]@{
                Index       = 2
                Role        = "Media"
                DisplayName = "NIC C - Media Network"
                AdapterName = "NIC C"
                IPAddress   = "192.168.20.11"
                SubnetMask  = "255.255.255.0"
                Gateway     = ""
                DNS1        = ""
                DNS2        = ""
                DHCP        = $false
                VLANID      = $null
                Enabled     = $true
            },
            [PSCustomObject]@{
                Index       = 3
                Role        = "NDI"
                DisplayName = "NIC D - NDI Video"
                AdapterName = "NIC D"
                IPAddress   = ""
                SubnetMask  = ""
                Gateway     = ""
                DNS1        = ""
                DNS2        = ""
                DHCP        = $true
                VLANID      = $null
                Enabled     = $true
            },
            [PSCustomObject]@{
                Index       = 4
                Role        = "100G"
                DisplayName = "NIC E - 100G"
                AdapterName = "NIC E"
                IPAddress   = ""
                SubnetMask  = ""
                Gateway     = ""
                DNS1        = ""
                DNS2        = ""
                DHCP        = $true
                VLANID      = $null
                Enabled     = $true
            },
            [PSCustomObject]@{
                Index       = 5
                Role        = "100G"
                DisplayName = "NIC F - 100G"
                AdapterName = "NIC F"
                IPAddress   = ""
                SubnetMask  = ""
                Gateway     = ""
                DNS1        = ""
                DNS2        = ""
                DHCP        = $true
                VLANID      = $null
                Enabled     = $true
            }
        )
        SMBSettings     = [PSCustomObject]@{
            ShareD3Projects  = $true
            ProjectsPath     = "D:\d3 Projects"
            ShareName        = "d3 Projects"
            SharePermissions = "Administrators:Full"
            AdditionalShares = @()
        }
        CustomSettings  = [PSCustomObject]@{}
    }

    Write-AppLog "Created new default profile: '$Name'" -Level 'INFO'
    return $profile
}


function Get-AllProfiles {
    <#
    .SYNOPSIS
        Returns an array of all saved profile objects from the profiles directory.
    .DESCRIPTION
        Reads every .json file in the profiles/ directory and deserializes each
        into a PSCustomObject. Files that fail to parse are logged and skipped.
    .OUTPUTS
        [PSCustomObject[]] - Array of profile objects, sorted by Name.
    #>
    $profilesDir = Get-ProfilesDirectory
    $profiles = @()

    $jsonFiles = Get-ChildItem -Path $profilesDir -Filter '*.json' -File -ErrorAction SilentlyContinue

    foreach ($file in $jsonFiles) {
        try {
            $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8
            $profileObj = $content | ConvertFrom-Json
            $profiles += $profileObj
        }
        catch {
            Write-AppLog "Failed to read profile file '$($file.Name)': $_" -Level 'ERROR'
        }
    }

    # Sort profiles alphabetically by name
    $profiles = $profiles | Sort-Object -Property Name
    return $profiles
}


function Test-ProfileSchema {
    <#
    .SYNOPSIS
        Validates a profile object against the expected schema. Returns validation result.
    #>
    param([PSCustomObject]$Profile)
    $errors = @()

    # Validate required fields
    if (-not $Profile.Name) { $errors += "Profile name is required" }
    if (-not $Profile.NetworkAdapters) { $errors += "NetworkAdapters array is required" }
    if ($Profile.NetworkAdapters -and $Profile.NetworkAdapters -isnot [array]) { $errors += "NetworkAdapters must be an array" }

    # Block SMB1 enablement (security policy)
    if ($Profile.PSObject.Properties['SMBSettings'] -and $Profile.SMBSettings.PSObject.Properties['EnableSMB1']) {
        if ($Profile.SMBSettings.EnableSMB1 -eq $true) {
            $errors += "SMB1 enablement is blocked by security policy"
        }
    }

    # Validate adapter roles against allowlist
    $validRoles = @('d3Net','Media','sACN','NDI','Control','Internet','100G','KVM','Backup','Management','')
    if ($Profile.NetworkAdapters) {
        foreach ($adapter in $Profile.NetworkAdapters) {
            if ($adapter.Role -and $adapter.Role -notin $validRoles) {
                $errors += "Unrecognized adapter role: '$($adapter.Role)'"
            }
        }
    }

    # Validate share paths if present (legacy Shares[] array form)
    if ($Profile.SMBSettings -and $Profile.SMBSettings.PSObject.Properties['Shares']) {
        foreach ($share in $Profile.SMBSettings.Shares) {
            if ($share.Path -and $share.Path -match '^\\\\') {
                $errors += "UNC paths not allowed in share configuration: $($share.Path)"
            }
            if ($share.Path -and $share.Path -match '(?i)(system32|[\\\/]windows([\\\/]|$)|program.files)') {
                $errors += "System paths not allowed in share configuration: $($share.Path)"
            }
        }
    }

    # Validate AdditionalShares paths
    if ($Profile.SMBSettings.AdditionalShares) {
        foreach ($share in $Profile.SMBSettings.AdditionalShares) {
            if ($share.Path -match '^\\\\') {
                $errors += "UNC paths not allowed in AdditionalShares: $($share.Path)"
            }
            if ($share.Path -match '^[A-Z]:\\Windows' -or $share.Path -match '^[A-Z]:\\Program Files') {
                $errors += "System paths not allowed in AdditionalShares: $($share.Path)"
            }
        }
    }

    # Validate ProjectsPath (the actual field used in profile schema)
    if ($Profile.SMBSettings -and $Profile.SMBSettings.PSObject.Properties['ProjectsPath']) {
        $pp = $Profile.SMBSettings.ProjectsPath
        if ($pp -and $pp -match '^\\\\') {
            $errors += "UNC path not allowed in SMBSettings.ProjectsPath: $pp"
        }
        if ($pp -and $pp -match '(?i)(system32|[\\\/]windows([\\\/]|$)|program.files)') {
            $errors += "System path not allowed in SMBSettings.ProjectsPath: $pp"
        }
    }

    return @{
        IsValid = ($errors.Count -eq 0)
        Errors  = $errors
    }
}


function Get-Profile {
    <#
    .SYNOPSIS
        Reads a specific profile by name from the profiles directory.
    .PARAMETER Name
        The profile name (without .json extension).
    .OUTPUTS
        [PSCustomObject] - The profile object, or $null if not found.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $profilesDir = Get-ProfilesDirectory
    # Sanitize name to prevent path traversal (matching Save-Profile behavior)
    $safeName = $Name -replace '[\\/:*?"<>|]', '_'
    $filePath = Join-Path -Path $profilesDir -ChildPath "$safeName.json"

    # Verify resolved path stays within profiles directory
    $resolvedPath = [System.IO.Path]::GetFullPath($filePath)
    $resolvedDir = [System.IO.Path]::GetFullPath($profilesDir)
    if (-not $resolvedPath.StartsWith($resolvedDir, [StringComparison]::OrdinalIgnoreCase)) {
        Write-AppLog "Path traversal attempt blocked for profile name '$Name'" -Level 'ERROR'
        return $null
    }

    if (-not (Test-Path -Path $filePath)) {
        Write-AppLog "Profile not found: '$Name'" -Level 'WARN'
        return $null
    }

    try {
        $content = Get-Content -Path $filePath -Raw -Encoding UTF8
        $profileObj = $content | ConvertFrom-Json
        return $profileObj
    }
    catch {
        Write-AppLog "Failed to read profile '$Name': $($_.Exception.Message)" -Level 'ERROR'
        return $null
    }
}


function Save-Profile {
    <#
    .SYNOPSIS
        Saves a profile object to a JSON file in the profiles directory.
    .DESCRIPTION
        Updates the Modified timestamp and writes the profile to
        profiles/{Name}.json with UTF-8 encoding.
    .PARAMETER Profile
        The profile PSCustomObject to save.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Profile
    )

    # Validate that the profile has a Name
    if ([string]::IsNullOrWhiteSpace($Profile.Name)) {
        Write-AppLog "Cannot save profile: Name is empty." -Level 'ERROR'
        throw "Profile name cannot be empty."
    }

    # Validate ServerName if present (NetBIOS rules: max 15 chars, no invalid chars)
    if ($Profile.PSObject.Properties['ServerName'] -and -not [string]::IsNullOrWhiteSpace($Profile.ServerName)) {
        $serverName = $Profile.ServerName
        if ($serverName.Length -gt 15) {
            Write-AppLog "Profile validation failed: ServerName '$serverName' exceeds 15 characters." -Level 'ERROR'
            throw "ServerName '$serverName' exceeds the 15-character NetBIOS limit."
        }
        # NetBIOS invalid characters: \ / : * ? " < > | , plus spaces and periods (as sole name)
        if ($serverName -match '[\\/:*?"<>|,\.\s]') {
            Write-AppLog "Profile validation failed: ServerName '$serverName' contains invalid characters." -Level 'ERROR'
            throw "ServerName '$serverName' contains characters not allowed in NetBIOS names (\ / : * ? `" < > | , . or spaces)."
        }
    }

    # Validate IP addresses in NetworkAdapters if present
    if ($Profile.PSObject.Properties['NetworkAdapters'] -and $null -ne $Profile.NetworkAdapters) {
        foreach ($adapter in $Profile.NetworkAdapters) {
            if ($null -eq $adapter) { continue }

            # Skip validation for DHCP-enabled or disabled adapters with no IP set
            $isDHCP = $false
            if ($adapter.PSObject.Properties['DHCP']) { $isDHCP = $adapter.DHCP }
            if ($isDHCP) { continue }

            $isEnabled = $true
            if ($adapter.PSObject.Properties['Enabled']) { $isEnabled = $adapter.Enabled }
            if (-not $isEnabled) { continue }

            # Validate IPAddress if non-empty
            if ($adapter.PSObject.Properties['IPAddress'] -and -not [string]::IsNullOrWhiteSpace($adapter.IPAddress)) {
                $ipAddr = $adapter.IPAddress
                $parsed = $null
                $isValidIP = [System.Net.IPAddress]::TryParse($ipAddr.Trim(), [ref]$parsed)
                if (-not $isValidIP -or $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $roleName = if ($adapter.PSObject.Properties['Role']) { $adapter.Role } else { "Index $($adapter.Index)" }
                    Write-AppLog "Profile validation failed: Invalid IP '$ipAddr' for adapter $roleName." -Level 'ERROR'
                    throw "Invalid IP address '$ipAddr' for adapter $roleName. Expected IPv4 format (e.g. 10.0.0.10)."
                }
            }

            # Validate SubnetMask if non-empty
            if ($adapter.PSObject.Properties['SubnetMask'] -and -not [string]::IsNullOrWhiteSpace($adapter.SubnetMask)) {
                $mask = $adapter.SubnetMask
                $parsed = $null
                $isValidMask = [System.Net.IPAddress]::TryParse($mask.Trim(), [ref]$parsed)
                if (-not $isValidMask -or $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $roleName = if ($adapter.PSObject.Properties['Role']) { $adapter.Role } else { "Index $($adapter.Index)" }
                    Write-AppLog "Profile validation failed: Invalid SubnetMask '$mask' for adapter $roleName." -Level 'ERROR'
                    throw "Invalid subnet mask '$mask' for adapter $roleName. Expected format (e.g. 255.255.255.0)."
                }
            }

            # Validate Gateway if non-empty
            if ($adapter.PSObject.Properties['Gateway'] -and -not [string]::IsNullOrWhiteSpace($adapter.Gateway)) {
                $gw = $adapter.Gateway
                $parsed = $null
                $isValidGW = [System.Net.IPAddress]::TryParse($gw.Trim(), [ref]$parsed)
                if (-not $isValidGW -or $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $roleName = if ($adapter.PSObject.Properties['Role']) { $adapter.Role } else { "Index $($adapter.Index)" }
                    Write-AppLog "Profile validation failed: Invalid Gateway '$gw' for adapter $roleName." -Level 'ERROR'
                    throw "Invalid gateway '$gw' for adapter $roleName. Expected IPv4 format."
                }
            }
        }
    }

    # Update the Modified timestamp
    $Profile.Modified = (Get-Date).ToString('o')

    $profilesDir = Get-ProfilesDirectory

    # Sanitize filename: remove characters invalid for Windows file paths
    $safeName = $Profile.Name -replace '[\\/:*?"<>|]', '_'
    $filePath = Join-Path -Path $profilesDir -ChildPath "$safeName.json"

    # Path boundary check -- ensure resolved path stays inside profiles directory
    $resolvedPath = [System.IO.Path]::GetFullPath($filePath)
    $resolvedDir  = [System.IO.Path]::GetFullPath($profilesDir)
    if (-not $resolvedPath.StartsWith($resolvedDir, [StringComparison]::OrdinalIgnoreCase)) {
        Write-AppLog "Save-Profile: Path traversal blocked for '$($Profile.Name)' (resolved to '$resolvedPath')" -Level 'ERROR'
        throw "Invalid profile name - path traversal detected."
    }

    try {
        $json = $Profile | ConvertTo-Json -Depth 10
        Set-Content -Path $filePath -Value $json -Encoding UTF8 -Force
        Write-AppLog "Saved profile '$($Profile.Name)' to '$filePath'" -Level 'INFO'
    }
    catch {
        Write-AppLog "Failed to save profile '$($Profile.Name)': $_" -Level 'ERROR'
        throw "Failed to save profile: $_"
    }
}


function Remove-Profile {
    <#
    .SYNOPSIS
        Deletes a profile JSON file from the profiles directory.
    .PARAMETER Name
        The profile name to delete.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $profilesDir = Get-ProfilesDirectory
    $safeName = $Name -replace '[\\/:*?"<>|]', '_'
    $filePath = Join-Path -Path $profilesDir -ChildPath "$safeName.json"

    # Path boundary check -- ensure resolved path stays inside profiles directory
    $resolvedPath = [System.IO.Path]::GetFullPath($filePath)
    $resolvedDir  = [System.IO.Path]::GetFullPath($profilesDir)
    if (-not $resolvedPath.StartsWith($resolvedDir, [StringComparison]::OrdinalIgnoreCase)) {
        Write-AppLog "Remove-Profile: Path traversal blocked for '$Name' (resolved to '$resolvedPath')" -Level 'ERROR'
        throw "Invalid profile name: path escapes the profiles directory"
    }

    if (Test-Path -Path $filePath) {
        try {
            Remove-Item -Path $filePath -Force
            Write-AppLog "Deleted profile '$Name'" -Level 'INFO'
        }
        catch {
            Write-AppLog "Failed to delete profile '$Name': $_" -Level 'ERROR'
            throw "Failed to delete profile: $_"
        }
    }
    else {
        Write-AppLog "Cannot delete profile '$Name': file not found." -Level 'WARN'
    }
}


function Export-ProfileToFile {
    <#
    .SYNOPSIS
        Exports a profile to a user-chosen location using a SaveFileDialog.
    .PARAMETER Profile
        The profile object to export.
    .OUTPUTS
        [bool] - $true if the export succeeded, $false otherwise.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Profile
    )

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Title = "Export Profile - $($Profile.Name)"
    $saveDialog.Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*"
    $saveDialog.DefaultExt = "json"
    $saveDialog.FileName = "$($Profile.Name).json"
    $saveDialog.OverwritePrompt = $true

    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $json = $Profile | ConvertTo-Json -Depth 10
            Set-Content -Path $saveDialog.FileName -Value $json -Encoding UTF8 -Force
            Write-AppLog "Exported profile '$($Profile.Name)' to '$($saveDialog.FileName)'" -Level 'INFO'
            [System.Windows.Forms.MessageBox]::Show(
                "Profile '$($Profile.Name)' exported successfully.`n`nLocation: $($saveDialog.FileName)",
                "Export Successful",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return $true
        }
        catch {
            Write-AppLog "Failed to export profile: $_" -Level 'ERROR'
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to export profile:`n$_",
                "Export Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
            return $false
        }
    }

    return $false
}


function Import-ProfileFromFile {
    <#
    .SYNOPSIS
        Imports a profile from a user-chosen JSON file using an OpenFileDialog.
    .DESCRIPTION
        Presents a file picker, reads the selected JSON file, validates the
        structure, and returns the profile object. If a profile with the same
        name already exists, the user is prompted to rename or overwrite.
    .OUTPUTS
        [PSCustomObject] - The imported profile, or $null if cancelled/failed.
    #>
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Title = "Import Profile"
    $openDialog.Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*"
    $openDialog.Multiselect = $false

    if ($openDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return $null
    }

    try {
        $content = Get-Content -Path $openDialog.FileName -Raw -Encoding UTF8
        $importedProfile = $content | ConvertFrom-Json
    }
    catch {
        Write-AppLog "Failed to read imported file '$($openDialog.FileName)': $_" -Level 'ERROR'
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to read the selected file. Ensure it is a valid JSON profile.`n`nError: $_",
            "Import Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return $null
    }

    # Validate that required fields exist
    if (-not $importedProfile.Name) {
        [System.Windows.Forms.MessageBox]::Show(
            "The selected file does not contain a valid profile (missing 'Name' field).",
            "Invalid Profile",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return $null
    }

    if (-not $importedProfile.NetworkAdapters) {
        [System.Windows.Forms.MessageBox]::Show(
            "The selected file does not contain a valid profile (missing 'NetworkAdapters' field).",
            "Invalid Profile",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return $null
    }

    # Check if a profile with this name already exists
    $existingProfile = Get-Profile -Name $importedProfile.Name
    if ($null -ne $existingProfile) {
        $overwriteResult = [System.Windows.Forms.MessageBox]::Show(
            "A profile named '$($importedProfile.Name)' already exists.`n`nDo you want to overwrite it?",
            "Profile Exists",
            [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )

        if ($overwriteResult -eq [System.Windows.Forms.DialogResult]::Cancel) {
            return $null
        }
        elseif ($overwriteResult -eq [System.Windows.Forms.DialogResult]::No) {
            # Prompt for a new name
            $newName = Show-InputDialog -Title "Rename Imported Profile" `
                -Message "Enter a new name for the imported profile:" `
                -DefaultValue "$($importedProfile.Name) (Imported)"
            if ([string]::IsNullOrWhiteSpace($newName)) {
                return $null
            }
            $importedProfile.Name = $newName
        }
        # If Yes, we fall through and overwrite
    }

    # Validate schema before saving
    $schemaResult = Test-ProfileSchema -Profile $importedProfile
    if (-not $schemaResult.IsValid) {
        $errorMsg = "Imported profile failed validation:`n`n" + ($schemaResult.Errors -join "`n")
        $validationErrorStr = $schemaResult.Errors -join '; '
        Write-AppLog "Import blocked by schema validation: $validationErrorStr" -Level 'WARN'
        [System.Windows.Forms.MessageBox]::Show(
            $errorMsg,
            "Profile Validation Failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return $null
    }

    # Update timestamps for the import
    $importedProfile.Modified = (Get-Date).ToString('o')

    # Save the imported profile
    try {
        Save-Profile -Profile $importedProfile
        Write-AppLog "Imported profile '$($importedProfile.Name)' from '$($openDialog.FileName)'" -Level 'INFO'
        [System.Windows.Forms.MessageBox]::Show(
            "Profile '$($importedProfile.Name)' imported successfully.",
            "Import Successful",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return $importedProfile
    }
    catch {
        Write-AppLog "Failed to save imported profile: $_" -Level 'ERROR'
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to save imported profile:`n$_",
            "Import Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return $null
    }
}


function Apply-FullProfile {
    <#
    .SYNOPSIS
        Applies all settings from a profile to the local machine.
    .DESCRIPTION
        Shows a confirmation dialog listing all changes, then applies:
        1. Hostname change via Set-ServerHostname (if different from current)
        2. Network adapter configuration via Set-AdapterStaticIP / Set-AdapterDHCP
        3. SMB share creation via New-D3ProjectShare (if enabled)
        Each step is wrapped in error handling so one failure does not block
        the remaining steps. A results summary dialog is shown after all
        steps complete. If the hostname was changed, the user is prompted
        to restart.
    .PARAMETER Profile
        The profile object to apply.
    .OUTPUTS
        [bool] - $true if all steps succeeded (or were skipped), $false if any failed.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Profile
    )

    # Validate profile schema before proceeding
    $schemaResult = Test-ProfileSchema -Profile $Profile
    if (-not $schemaResult.IsValid) {
        $errorMsg = "Profile '$($Profile.Name)' failed schema validation:`n`n" + ($schemaResult.Errors -join "`n")
        $validationErrorStr = $schemaResult.Errors -join '; '
        Write-AppLog "Apply-FullProfile blocked by schema validation: $validationErrorStr" -Level 'ERROR'
        [System.Windows.Forms.MessageBox]::Show(
            $errorMsg,
            "Profile Validation Failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return $false
    }

    # Build a summary of all changes that would be applied
    $changesList = [System.Text.StringBuilder]::new()
    [void]$changesList.AppendLine("The following settings will be applied from profile '$($Profile.Name)':")
    [void]$changesList.AppendLine("")

    # Server name
    $summaryServerName = if ($Profile.PSObject.Properties['ServerName'] -and $Profile.ServerName) { $Profile.ServerName } else { "(Not set)" }
    [void]$changesList.AppendLine("SERVER NAME:")
    [void]$changesList.AppendLine("  Hostname: $summaryServerName")
    [void]$changesList.AppendLine("")

    # Network adapters
    [void]$changesList.AppendLine("NETWORK ADAPTERS:")
    $summaryAdapters = @()
    if ($Profile.PSObject.Properties['NetworkAdapters'] -and $null -ne $Profile.NetworkAdapters) {
        $summaryAdapters = @($Profile.NetworkAdapters)
    }
    if ($summaryAdapters.Count -eq 0) {
        [void]$changesList.AppendLine("  (No adapters defined)")
    }
    foreach ($adapter in $summaryAdapters) {
        if ($null -eq $adapter) { continue }

        $sAdIndex = if ($adapter.PSObject.Properties['Index']) { $adapter.Index } else { "?" }
        $sAdDisplayName = if ($adapter.PSObject.Properties['DisplayName']) { $adapter.DisplayName } else { "Unknown" }
        $sAdRole = if ($adapter.PSObject.Properties['Role']) { $adapter.Role } else { "Unknown" }
        $sAdEnabled = if ($adapter.PSObject.Properties['Enabled']) { $adapter.Enabled } else { $true }
        $sAdDHCP = if ($adapter.PSObject.Properties['DHCP']) { $adapter.DHCP } else { $false }
        $sAdIP = if ($adapter.PSObject.Properties['IPAddress']) { $adapter.IPAddress } else { "" }
        $sAdSubnet = if ($adapter.PSObject.Properties['SubnetMask']) { $adapter.SubnetMask } else { "" }
        $sAdGateway = if ($adapter.PSObject.Properties['Gateway']) { $adapter.Gateway } else { "" }
        $sAdDNS1 = if ($adapter.PSObject.Properties['DNS1']) { $adapter.DNS1 } else { "" }
        $sAdDNS2 = if ($adapter.PSObject.Properties['DNS2']) { $adapter.DNS2 } else { "" }

        if ($sAdEnabled) {
            $ipInfo = if ($sAdDHCP) { "DHCP" } else { "$sAdIP / $sAdSubnet" }
            [void]$changesList.AppendLine("  [$sAdIndex] $sAdDisplayName ($sAdRole): $ipInfo")
            if ($sAdGateway) {
                [void]$changesList.AppendLine("       Gateway: $sAdGateway")
            }
            if ($sAdDNS1) {
                $dnsStr = $sAdDNS1
                if ($sAdDNS2) { $dnsStr += ", $sAdDNS2" }
                [void]$changesList.AppendLine("       DNS: $dnsStr")
            }
        }
        else {
            [void]$changesList.AppendLine("  [$sAdIndex] $sAdDisplayName ($sAdRole): DISABLED")
        }
    }
    [void]$changesList.AppendLine("")

    # SMB settings
    [void]$changesList.AppendLine("SMB SHARING:")
    $summarySMBEnabled = $Profile.PSObject.Properties['SMBSettings'] -and
                         $null -ne $Profile.SMBSettings -and
                         $Profile.SMBSettings.PSObject.Properties['ShareD3Projects'] -and
                         $Profile.SMBSettings.ShareD3Projects
    if ($summarySMBEnabled) {
        $sSmbShareName = if ($Profile.SMBSettings.PSObject.Properties['ShareName']) { $Profile.SMBSettings.ShareName } else { "(Unknown)" }
        $sSmbPath = if ($Profile.SMBSettings.PSObject.Properties['ProjectsPath']) { $Profile.SMBSettings.ProjectsPath } else { "(Unknown)" }
        $sSmbPerms = if ($Profile.SMBSettings.PSObject.Properties['SharePermissions']) { $Profile.SMBSettings.SharePermissions } else { "(Unknown)" }
        [void]$changesList.AppendLine("  Share Name: $sSmbShareName")
        [void]$changesList.AppendLine("  Path: $sSmbPath")
        [void]$changesList.AppendLine("  Permissions: $sSmbPerms")
    }
    else {
        [void]$changesList.AppendLine("  d3 Projects sharing: Disabled")
    }

    [void]$changesList.AppendLine("")
    [void]$changesList.AppendLine("WARNING: This will modify system network and sharing settings.")
    [void]$changesList.AppendLine("Ensure you have reviewed all values before proceeding.")

    # Show confirmation dialog
    $confirmResult = [System.Windows.Forms.MessageBox]::Show(
        $changesList.ToString(),
        "Confirm Profile Application - $($Profile.Name)",
        [System.Windows.Forms.MessageBoxButtons]::OKCancel,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($confirmResult -ne [System.Windows.Forms.DialogResult]::OK) {
        Write-AppLog "User cancelled profile application for '$($Profile.Name)'" -Level 'INFO'
        return $false
    }

    # ---- Execute profile application ----
    Write-AppLog "=== PROFILE APPLICATION START: '$($Profile.Name)' ===" -Level 'INFO'

    $results = [System.Text.StringBuilder]::new()
    $successCount = 0
    $failCount = 0
    $skipCount = 0
    $restartNeeded = $false

    # ================================================================
    # Step 1: Change hostname (if different from current)
    # ================================================================
    try {
        if ($Profile.PSObject.Properties['ServerName'] -and $Profile.ServerName -and $Profile.ServerName -ne $env:COMPUTERNAME) {
            Write-AppLog "Applying hostname change: '$env:COMPUTERNAME' -> '$($Profile.ServerName)'" -Level 'INFO'
            $hostnameResult = Set-ServerHostname -NewName $Profile.ServerName

            if ($hostnameResult.Success) {
                $successCount++
                $restartNeeded = $hostnameResult.RestartRequired
                [void]$results.AppendLine("[OK] Hostname: $($hostnameResult.Message)")
                Write-AppLog "Hostname change succeeded: $($hostnameResult.Message)" -Level 'INFO'
            }
            else {
                $failCount++
                [void]$results.AppendLine("[FAIL] Hostname: $($hostnameResult.Message)")
                Write-AppLog "Hostname change failed: $($hostnameResult.Message)" -Level 'ERROR'
            }
        }
        else {
            $skipCount++
            if ([string]::IsNullOrWhiteSpace($Profile.ServerName)) {
                [void]$results.AppendLine("[SKIP] Hostname: Not configured in profile")
                Write-AppLog "Hostname unchanged (not configured in profile)" -Level 'INFO'
            } else {
                [void]$results.AppendLine("[SKIP] Hostname: Already set to '$($Profile.ServerName)'")
                Write-AppLog "Hostname unchanged (already '$($Profile.ServerName)')" -Level 'INFO'
            }
        }
    }
    catch {
        $failCount++
        [void]$results.AppendLine("[FAIL] Hostname: Unexpected error - $_")
        Write-AppLog "Hostname change error: $_" -Level 'ERROR'
    }

    # ================================================================
    # Step 2: Configure network adapters
    # ================================================================
    $adaptersToApply = @()
    if ($Profile.PSObject.Properties['NetworkAdapters'] -and $null -ne $Profile.NetworkAdapters) {
        $adaptersToApply = @($Profile.NetworkAdapters)
    }

    if ($adaptersToApply.Count -eq 0) {
        $skipCount++
        [void]$results.AppendLine("[SKIP] Network Adapters: No adapters defined in profile")
        Write-AppLog "No NetworkAdapters defined in profile - skipping network config" -Level 'WARN'
    }

    foreach ($adapter in $adaptersToApply) {
        if ($null -eq $adapter) {
            $skipCount++
            [void]$results.AppendLine("[SKIP] Network Adapter: Null adapter entry in profile")
            continue
        }

        $adIndex = if ($adapter.PSObject.Properties['Index']) { $adapter.Index } else { "?" }
        $adDisplayName = if ($adapter.PSObject.Properties['DisplayName']) { $adapter.DisplayName } else { "Unknown" }
        $adRole = if ($adapter.PSObject.Properties['Role']) { $adapter.Role } else { "Unknown" }
        $adapterLabel = "[$adIndex] $adDisplayName ($adRole)"

        try {
            $adEnabled = if ($adapter.PSObject.Properties['Enabled']) { $adapter.Enabled } else { $true }
            if (-not $adEnabled) {
                $skipCount++
                [void]$results.AppendLine("[SKIP] $adapterLabel : Disabled in profile")
                Write-AppLog "Skipping adapter $adapterLabel - disabled in profile" -Level 'INFO'
                continue
            }

            $adapterName = if ($adapter.PSObject.Properties['AdapterName']) { $adapter.AdapterName } else { "" }
            if ([string]::IsNullOrWhiteSpace($adapterName)) {
                $skipCount++
                [void]$results.AppendLine("[SKIP] $adapterLabel : No physical adapter assigned")
                Write-AppLog "Skipping adapter $adapterLabel - no AdapterName set" -Level 'WARN'
                continue
            }

            $adDHCP = if ($adapter.PSObject.Properties['DHCP']) { $adapter.DHCP } else { $false }
            if ($adDHCP) {
                Write-AppLog "Setting adapter '$adapterName' ($adapterLabel) to DHCP" -Level 'INFO'
                $adapterResult = Set-AdapterDHCP -AdapterName $adapterName
            }
            else {
                $adIP = if ($adapter.PSObject.Properties['IPAddress']) { $adapter.IPAddress } else { "" }
                $adSubnet = if ($adapter.PSObject.Properties['SubnetMask']) { $adapter.SubnetMask } else { "" }
                $adGateway = if ($adapter.PSObject.Properties['Gateway']) { $adapter.Gateway } else { "" }
                $adDNS1 = if ($adapter.PSObject.Properties['DNS1']) { $adapter.DNS1 } else { "" }
                $adDNS2 = if ($adapter.PSObject.Properties['DNS2']) { $adapter.DNS2 } else { "" }

                Write-AppLog "Setting adapter '$adapterName' ($adapterLabel) to static IP=$adIP" -Level 'INFO'
                $adapterResult = Set-AdapterStaticIP -AdapterName $adapterName `
                    -IPAddress $adIP `
                    -SubnetMask $adSubnet `
                    -Gateway $adGateway `
                    -DNS1 $adDNS1 `
                    -DNS2 $adDNS2
            }

            if ($adapterResult.Success) {
                $successCount++
                [void]$results.AppendLine("[OK] $adapterLabel : $($adapterResult.Message)")
                Write-AppLog "Adapter $adapterLabel succeeded: $($adapterResult.Message)" -Level 'INFO'
            }
            else {
                $failCount++
                [void]$results.AppendLine("[FAIL] $adapterLabel : $($adapterResult.Message)")
                Write-AppLog "Adapter $adapterLabel failed: $($adapterResult.Message)" -Level 'ERROR'
            }

            # VLAN support
            if ($adapter.VLANID -and $adapter.VLANID -gt 0) {
                try {
                    $adapterObj = Get-NetAdapter | Where-Object { $_.Name -eq $adapterName } | Select-Object -First 1
                    if (-not $adapterObj) {
                        $adapterObj = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*$adapterName*" } | Select-Object -First 1
                    }
                    if (-not $adapterObj) {
                        $adapterObj = (Get-NetAdapter | Sort-Object InterfaceIndex)[$adIndex]
                    }
                    if ($adapterObj) {
                        Set-NetAdapterAdvancedProperty -Name $adapterObj.Name -RegistryKeyword "VlanID" -RegistryValue $adapter.VLANID
                        Write-AppLog "VLAN $($adapter.VLANID) set on $adapterName" "INFO"
                    }
                } catch {
                    Write-AppLog "VLAN config failed for $adapterName : $_" "WARN"
                }
            }
        }
        catch {
            $failCount++
            [void]$results.AppendLine("[FAIL] $adapterLabel : Unexpected error - $_")
            Write-AppLog "Adapter $adapterLabel error: $_" -Level 'ERROR'
        }
    }

    # ================================================================
    # Step 3: Configure SMB sharing
    # ================================================================
    try {
        $applySMB = $Profile.PSObject.Properties['SMBSettings'] -and
                    $null -ne $Profile.SMBSettings -and
                    $Profile.SMBSettings.PSObject.Properties['ShareD3Projects'] -and
                    $Profile.SMBSettings.ShareD3Projects

        if ($applySMB) {
            $smbShareName = if ($Profile.SMBSettings.PSObject.Properties['ShareName']) { $Profile.SMBSettings.ShareName } else { "d3 Projects" }
            $smbLocalPath = if ($Profile.SMBSettings.PSObject.Properties['ProjectsPath']) { $Profile.SMBSettings.ProjectsPath } else { "D:\d3 Projects" }
            $smbPerms = if ($Profile.SMBSettings.PSObject.Properties['SharePermissions']) { $Profile.SMBSettings.SharePermissions } else { "Administrators:Full" }

            Write-AppLog "Creating SMB share '$smbShareName' at '$smbLocalPath'" -Level 'INFO'
            $smbResult = New-D3ProjectShare `
                -LocalPath $smbLocalPath `
                -ShareName $smbShareName `
                -Permissions $smbPerms

            if ($smbResult.Success) {
                $successCount++
                [void]$results.AppendLine("[OK] SMB Share: $($smbResult.Message)")
                Write-AppLog "SMB share creation succeeded: $($smbResult.Message)" -Level 'INFO'
            }
            else {
                $failCount++
                [void]$results.AppendLine("[FAIL] SMB Share: $($smbResult.Message)")
                Write-AppLog "SMB share creation failed: $($smbResult.Message)" -Level 'ERROR'
            }
        }
        else {
            $skipCount++
            [void]$results.AppendLine("[SKIP] SMB Share: Disabled in profile")
            Write-AppLog "SMB sharing disabled in profile - skipping" -Level 'INFO'
        }
    }
    catch {
        $failCount++
        [void]$results.AppendLine("[FAIL] SMB Share: Unexpected error - $_")
        Write-AppLog "SMB share error: $_" -Level 'ERROR'
    }

    # ================================================================
    # Step 4: Update AppState (only on full success)
    # ================================================================
    if ($failCount -eq 0) {
        $script:AppState.LastAppliedProfile = $Profile.Name
        Write-AppLog "Updated LastAppliedProfile to '$($Profile.Name)'" -Level 'INFO'
    } else {
        Write-AppLog "Profile '$($Profile.Name)' applied with $failCount failure(s). LastAppliedProfile NOT updated." -Level 'WARN'
    }

    Write-AppLog "=== PROFILE APPLICATION END: '$($Profile.Name)' ===" -Level 'INFO'

    # ================================================================
    # Show results summary dialog
    # ================================================================
    $summaryText = [System.Text.StringBuilder]::new()
    [void]$summaryText.AppendLine("Profile '$($Profile.Name)' application results:")
    [void]$summaryText.AppendLine("")
    [void]$summaryText.AppendLine("  Succeeded: $successCount")
    [void]$summaryText.AppendLine("  Failed:    $failCount")
    [void]$summaryText.AppendLine("  Skipped:   $skipCount")
    [void]$summaryText.AppendLine("")
    [void]$summaryText.AppendLine("Details:")
    [void]$summaryText.AppendLine($results.ToString())

    $summaryIcon = if ($failCount -gt 0) {
        [System.Windows.Forms.MessageBoxIcon]::Warning
    }
    else {
        [System.Windows.Forms.MessageBoxIcon]::Information
    }

    [System.Windows.Forms.MessageBox]::Show(
        $summaryText.ToString(),
        "Profile Application Results - $($Profile.Name)",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        $summaryIcon
    ) | Out-Null

    # ================================================================
    # If hostname was changed, prompt for restart
    # ================================================================
    if ($restartNeeded) {
        $restartChoice = [System.Windows.Forms.MessageBox]::Show(
            "Hostname was changed. A restart is required for the new hostname to take effect.`n`nRestart now?",
            "Restart Required",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )

        if ($restartChoice -eq [System.Windows.Forms.DialogResult]::Yes) {
            Write-AppLog "User chose to restart after hostname change" -Level 'INFO'
            try {
                Restart-Computer -Force
            }
            catch {
                Write-AppLog "Failed to initiate restart: $_" -Level 'ERROR'
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to initiate restart: $_`n`nPlease restart manually.",
                    "Restart Failed",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                ) | Out-Null
            }
        }
        else {
            Write-AppLog "User deferred restart after hostname change" -Level 'INFO'
        }
    }

    return ($failCount -eq 0)
}


function Get-CurrentSystemProfile {
    <#
    .SYNOPSIS
        Captures the current system settings into a profile object.
    .DESCRIPTION
        Reads the current hostname, network adapter configurations, and SMB
        shares from the local machine and assembles them into a profile object
        matching the standard schema.
    .OUTPUTS
        [PSCustomObject] - A profile object populated with current system values.
    #>
    $now = (Get-Date).ToString('o')
    $currentHostname = $env:COMPUTERNAME

    # Build network adapters array from the system
    $adapters = @()

    # Define the expected adapter roles and their indices
    $roleDefinitions = @(
        @{ Index = 0; Role = "d3Net";  DisplayName = "d3 Network" },
        @{ Index = 1; Role = "sACN";   DisplayName = "Lighting (sACN/Art-Net)" },
        @{ Index = 2; Role = "Media";  DisplayName = "Media Network" },
        @{ Index = 3; Role = "NDI";    DisplayName = "NDI Video" },
        @{ Index = 4; Role = "100G";   DisplayName = "100G" },
        @{ Index = 5; Role = "100G";   DisplayName = "100G" }
    )

    # Try to read physical network adapters from the system
    $systemAdapters = @()
    try {
        # Get-NetAdapter is available on Windows; gracefully handle if unavailable
        $systemAdapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -ne 'Not Present' } |
            Sort-Object -Property InterfaceIndex)
    }
    catch {
        Write-AppLog "Unable to enumerate network adapters: $_" -Level 'WARN'
    }

    for ($i = 0; $i -lt 6; $i++) {
        $roleDef = $roleDefinitions[$i]
        $adapterObj = [PSCustomObject]@{
            Index       = $roleDef.Index
            Role        = $roleDef.Role
            DisplayName = $roleDef.DisplayName
            AdapterName = ""
            IPAddress   = ""
            SubnetMask  = ""
            Gateway     = ""
            DNS1        = ""
            DNS2        = ""
            DHCP        = $false
            VLANID      = $null
            Enabled     = $true
        }

        # Map system adapters to profile slots (if enough adapters exist)
        if ($i -lt $systemAdapters.Count) {
            $sysAdapter = $systemAdapters[$i]
            $adapterObj.AdapterName = $sysAdapter.Name
            $adapterObj.Enabled = ($sysAdapter.Status -eq 'Up')

            try {
                $ipConfig = Get-NetIPConfiguration -InterfaceIndex $sysAdapter.InterfaceIndex -ErrorAction SilentlyContinue
                if ($ipConfig) {
                    # Get IPv4 address
                    $ipv4 = $ipConfig.IPv4Address | Select-Object -First 1
                    if ($ipv4) {
                        $adapterObj.IPAddress = $ipv4.IPAddress
                        # Convert prefix length to subnet mask
                        $prefixLength = $ipv4.PrefixLength
                        $adapterObj.SubnetMask = Convert-PrefixToSubnetMask -PrefixLength $prefixLength
                    }

                    # Gateway
                    $gw = $ipConfig.IPv4DefaultGateway | Select-Object -First 1
                    if ($gw) {
                        $adapterObj.Gateway = $gw.NextHop
                    }

                    # DNS servers
                    $dnsServers = $ipConfig.DNSServer | Where-Object { $_.AddressFamily -eq 2 } |
                        Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue
                    if ($dnsServers) {
                        if ($dnsServers.Count -ge 1) { $adapterObj.DNS1 = $dnsServers[0] }
                        if ($dnsServers.Count -ge 2) { $adapterObj.DNS2 = $dnsServers[1] }
                    }

                    # DHCP status
                    try {
                        $dhcpStatus = Get-NetIPInterface -InterfaceIndex $sysAdapter.InterfaceIndex `
                            -AddressFamily IPv4 -ErrorAction SilentlyContinue
                        if ($dhcpStatus -and $dhcpStatus.Dhcp -eq 'Enabled') {
                            $adapterObj.DHCP = $true
                        }
                    }
                    catch {
                        # DHCP detection failed; default to false
                    }
                }
            }
            catch {
                Write-AppLog "Failed to read IP config for adapter '$($sysAdapter.Name)': $_" -Level 'WARN'
            }
        }

        $adapters += $adapterObj
    }

    # Capture SMB share settings
    $smbSettings = [PSCustomObject]@{
        ShareD3Projects  = $false
        ProjectsPath     = "D:\d3 Projects"
        ShareName        = "d3 Projects"
        SharePermissions = "Administrators:Full"
        AdditionalShares = @()
    }

    try {
        $d3Share = Get-SmbShare -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*d3*' -or $_.Name -like '*Projects*' } |
            Select-Object -First 1

        if ($d3Share) {
            $smbSettings.ShareD3Projects = $true
            $smbSettings.ShareName = $d3Share.Name
            $smbSettings.ProjectsPath = $d3Share.Path

            # Try to read share permissions
            try {
                $shareAccess = Get-SmbShareAccess -Name $d3Share.Name -ErrorAction SilentlyContinue
                if ($shareAccess) {
                    $permStrings = $shareAccess | ForEach-Object {
                        "$($_.AccountName):$($_.AccessRight)"
                    }
                    $smbSettings.SharePermissions = ($permStrings -join '; ')
                }
            }
            catch {
                # Permissions read failed; keep default
            }
        }
    }
    catch {
        Write-AppLog "Unable to read SMB shares: $_" -Level 'WARN'
    }

    # Assemble the full profile object
    $capturedProfile = [PSCustomObject]@{
        Name            = "Captured - $currentHostname - $(Get-Date -Format 'yyyy-MM-dd')"
        Description     = "System capture from $currentHostname on $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Created         = $now
        Modified        = $now
        ServerName      = $currentHostname
        NetworkAdapters = $adapters
        SMBSettings     = $smbSettings
        CustomSettings  = [PSCustomObject]@{}
    }

    Write-AppLog "Captured current system profile from '$currentHostname'" -Level 'INFO'
    return $capturedProfile
}


# NOTE: Convert-PrefixToSubnetMask is defined in NetworkConfig.ps1 and available
# in the shared scope since both modules are dot-sourced by DisguiseBuddy.ps1.

# ============================================================================
# UI HELPER FUNCTIONS - Dialogs and small components
# ============================================================================

function Show-InputDialog {
    <#
    .SYNOPSIS
        Displays a simple input dialog with a text field.
    .PARAMETER Title
        The dialog window title.
    .PARAMETER Message
        The prompt message.
    .PARAMETER DefaultValue
        The initial value in the text field.
    .OUTPUTS
        [string] - The entered value, or empty string if cancelled.
    #>
    param(
        [string]$Title = "Input",
        [string]$Message = "Enter a value:",
        [string]$DefaultValue = ""
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size(420, 200)
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.BackColor = $script:Theme.Background
    $form.ForeColor = $script:Theme.Text

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Message
    $label.Location = New-Object System.Drawing.Point(15, 20)
    $label.Size = New-Object System.Drawing.Size(370, 25)
    $label.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $label.ForeColor = $script:Theme.Text
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(15, 55)
    $textBox.Size = New-Object System.Drawing.Size(370, 28)
    $textBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $textBox.Text = $DefaultValue
    $textBox.BackColor = $script:Theme.InputBackground
    $textBox.ForeColor = $script:Theme.Text
    $form.Controls.Add($textBox)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = New-Object System.Drawing.Point(200, 105)
    $okButton.Size = New-Object System.Drawing.Size(85, 35)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $okButton.FlatStyle = 'Flat'
    $okButton.BackColor = $script:Theme.Primary
    $okButton.ForeColor = [System.Drawing.Color]::White
    $okButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Location = New-Object System.Drawing.Point(300, 105)
    $cancelButton.Size = New-Object System.Drawing.Size(85, 35)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancelButton.FlatStyle = 'Flat'
    $cancelButton.BackColor = $script:Theme.Surface
    $cancelButton.ForeColor = $script:Theme.Text
    $cancelButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $form.Controls.Add($cancelButton)

    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton

    $result = $form.ShowDialog()
    $value = $textBox.Text

    $form.Dispose()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $value
    }
    return ""
}


function Show-NewProfileDialog {
    <#
    .SYNOPSIS
        Displays a dialog for creating a new profile with name and description fields.
    .OUTPUTS
        [PSCustomObject] - Object with Name and Description, or $null if cancelled.
    #>
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "New Profile"
    $form.Size = New-Object System.Drawing.Size(460, 280)
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.BackColor = $script:Theme.Background
    $form.ForeColor = $script:Theme.Text

    # Profile Name
    $nameLabel = New-Object System.Windows.Forms.Label
    $nameLabel.Text = "Profile Name:"
    $nameLabel.Location = New-Object System.Drawing.Point(15, 20)
    $nameLabel.Size = New-Object System.Drawing.Size(410, 22)
    $nameLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $nameLabel.ForeColor = $script:Theme.Text
    $form.Controls.Add($nameLabel)

    $nameBox = New-Object System.Windows.Forms.TextBox
    $nameBox.Location = New-Object System.Drawing.Point(15, 45)
    $nameBox.Size = New-Object System.Drawing.Size(410, 28)
    $nameBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $nameBox.BackColor = $script:Theme.InputBackground
    $nameBox.ForeColor = $script:Theme.Text
    $form.Controls.Add($nameBox)

    # Description
    $descLabel = New-Object System.Windows.Forms.Label
    $descLabel.Text = "Description (optional):"
    $descLabel.Location = New-Object System.Drawing.Point(15, 85)
    $descLabel.Size = New-Object System.Drawing.Size(410, 22)
    $descLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $descLabel.ForeColor = $script:Theme.Text
    $form.Controls.Add($descLabel)

    $descBox = New-Object System.Windows.Forms.TextBox
    $descBox.Location = New-Object System.Drawing.Point(15, 110)
    $descBox.Size = New-Object System.Drawing.Size(410, 60)
    $descBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $descBox.Multiline = $true
    $descBox.BackColor = $script:Theme.InputBackground
    $descBox.ForeColor = $script:Theme.Text
    $form.Controls.Add($descBox)

    # Buttons
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "Create"
    $okButton.Location = New-Object System.Drawing.Point(240, 190)
    $okButton.Size = New-Object System.Drawing.Size(85, 35)
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $okButton.FlatStyle = 'Flat'
    $okButton.BackColor = $script:Theme.Primary
    $okButton.ForeColor = [System.Drawing.Color]::White
    $okButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Location = New-Object System.Drawing.Point(340, 190)
    $cancelButton.Size = New-Object System.Drawing.Size(85, 35)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancelButton.FlatStyle = 'Flat'
    $cancelButton.BackColor = $script:Theme.Surface
    $cancelButton.ForeColor = $script:Theme.Text
    $cancelButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $form.Controls.Add($cancelButton)

    $form.AcceptButton = $okButton
    $form.CancelButton = $cancelButton

    $result = $form.ShowDialog()
    $name = $nameBox.Text.Trim()
    $desc = $descBox.Text.Trim()

    $form.Dispose()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK -and -not [string]::IsNullOrWhiteSpace($name)) {
        return [PSCustomObject]@{
            Name        = $name
            Description = $desc
        }
    }
    return $null
}


function Show-EditFullProfileDialog {
    <#
    .SYNOPSIS
        Opens a scrollable dialog to edit all sections of a profile:
        ServerName, all 6 network adapters, and SMB settings.
    .PARAMETER Profile
        The profile object to edit. Modified in-place if user clicks Save.
    .OUTPUTS
        [bool] - $true if changes were saved, $false if cancelled.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Profile
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Edit Profile - $($Profile.Name)"
    $form.Size = New-Object System.Drawing.Size(620, 860)
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = 'Sizable'
    $form.MinimumSize = New-Object System.Drawing.Size(600, 600)
    $form.MaximizeBox = $true
    $form.MinimizeBox = $false
    $form.BackColor = $script:Theme.Background
    $form.ForeColor = $script:Theme.Text

    # Scrollable content panel
    $scrollPanel = New-Object System.Windows.Forms.Panel
    $scrollPanel.Location = New-Object System.Drawing.Point(0, 0)
    $scrollPanel.Size = New-Object System.Drawing.Size(($form.ClientSize.Width), ($form.ClientSize.Height - 50))
    $scrollPanel.AutoScroll = $true
    $scrollPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor
        [System.Windows.Forms.AnchorStyles]::Left -bor
        [System.Windows.Forms.AnchorStyles]::Right -bor
        [System.Windows.Forms.AnchorStyles]::Bottom

    $labelFont = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $inputFont = New-Object System.Drawing.Font("Segoe UI", 9)
    $sectionFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $innerWidth = 540
    $currentY = 15

    # ---- Server Name Section ----
    $serverSectionLabel = New-Object System.Windows.Forms.Label
    $serverSectionLabel.Text = "Server Name"
    $serverSectionLabel.Location = New-Object System.Drawing.Point(15, $currentY)
    $serverSectionLabel.Size = New-Object System.Drawing.Size($innerWidth, 22)
    $serverSectionLabel.Font = $sectionFont
    $serverSectionLabel.ForeColor = $script:Theme.Primary
    $scrollPanel.Controls.Add($serverSectionLabel)
    $currentY += 28

    $serverNameLabel = New-Object System.Windows.Forms.Label
    $serverNameLabel.Text = "Hostname (max 15 chars):"
    $serverNameLabel.Location = New-Object System.Drawing.Point(15, $currentY)
    $serverNameLabel.Size = New-Object System.Drawing.Size(180, 20)
    $serverNameLabel.Font = $labelFont
    $serverNameLabel.ForeColor = $script:Theme.Text
    $scrollPanel.Controls.Add($serverNameLabel)

    $serverNameBox = New-Object System.Windows.Forms.TextBox
    $serverNameBox.Location = New-Object System.Drawing.Point(200, ($currentY - 2))
    $serverNameBox.Size = New-Object System.Drawing.Size(200, 24)
    $serverNameBox.Font = $inputFont
    $serverNameBox.MaxLength = 15
    $serverNameBox.BackColor = $script:Theme.InputBackground
    $serverNameBox.ForeColor = $script:Theme.Text
    $serverNameBox.Text = if ($Profile.PSObject.Properties['ServerName']) { $Profile.ServerName } else { "" }
    $scrollPanel.Controls.Add($serverNameBox)
    $currentY += 35

    # ---- Separator ----
    $sep1 = New-Object System.Windows.Forms.Label
    $sep1.Location = New-Object System.Drawing.Point(15, $currentY)
    $sep1.Size = New-Object System.Drawing.Size($innerWidth, 1)
    $sep1.BackColor = $script:Theme.Border
    $scrollPanel.Controls.Add($sep1)
    $currentY += 10

    # ---- Network Adapters Section ----
    $netSectionLabel = New-Object System.Windows.Forms.Label
    $netSectionLabel.Text = "Network Adapters"
    $netSectionLabel.Location = New-Object System.Drawing.Point(15, $currentY)
    $netSectionLabel.Size = New-Object System.Drawing.Size($innerWidth, 22)
    $netSectionLabel.Font = $sectionFont
    $netSectionLabel.ForeColor = $script:Theme.Primary
    $scrollPanel.Controls.Add($netSectionLabel)
    $currentY += 28

    # Store adapter textbox references for reading on Save
    $adapterControls = @()

    $adapters = @()
    if ($Profile.PSObject.Properties['NetworkAdapters'] -and $null -ne $Profile.NetworkAdapters) {
        $adapters = @($Profile.NetworkAdapters)
    }

    # Helper scriptblock: attach LostFocus IP validation to a TextBox.
    # Tints background red on invalid input, resets on valid/empty.
    $attachIPValidation = {
        param($box)
        $box.Add_LostFocus({
            $tb = $this
            $text = $tb.Text.Trim()
            if ([string]::IsNullOrWhiteSpace($text)) {
                $tb.BackColor = $script:Theme.InputBackground
                return
            }
            $parsed = $null
            $isValid = [System.Net.IPAddress]::TryParse($text, [ref]$parsed) -and
                       $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
            if ($isValid) {
                $tb.BackColor = $script:Theme.InputBackground
            } else {
                $tb.BackColor = [System.Drawing.Color]::FromArgb(40, 239, 68, 68)
            }
        })
    }

    for ($i = 0; $i -lt 6; $i++) {
        $adapter = if ($i -lt $adapters.Count) { $adapters[$i] } else { $null }

        $roleName = if ($null -ne $adapter -and $adapter.PSObject.Properties['Role']) { $adapter.Role } else { "Adapter $i" }
        $displayName = if ($null -ne $adapter -and $adapter.PSObject.Properties['DisplayName']) { $adapter.DisplayName } else { "Adapter $i" }

        # Adapter header
        $adHeaderLabel = New-Object System.Windows.Forms.Label
        $adHeaderLabel.Text = "[$i] $displayName ($roleName)"
        $adHeaderLabel.Location = New-Object System.Drawing.Point(15, $currentY)
        $adHeaderLabel.Size = New-Object System.Drawing.Size($innerWidth, 20)
        $adHeaderLabel.Font = $labelFont
        $adHeaderLabel.ForeColor = $script:Theme.Accent
        $scrollPanel.Controls.Add($adHeaderLabel)
        $currentY += 24

        # ---- Adapter Name (physical interface name used by Push-ProfileToServer) ----
        $adNameLbl = New-Object System.Windows.Forms.Label
        $adNameLbl.Text = "Adapter Name:"
        $adNameLbl.Location = New-Object System.Drawing.Point(30, ($currentY + 2))
        $adNameLbl.Size = New-Object System.Drawing.Size(95, 20)
        $adNameLbl.Font = $inputFont
        $adNameLbl.ForeColor = $script:Theme.TextSecondary
        $scrollPanel.Controls.Add($adNameLbl)

        $adNameBox = New-Object System.Windows.Forms.TextBox
        $adNameBox.Location = New-Object System.Drawing.Point(130, $currentY)
        $adNameBox.Size = New-Object System.Drawing.Size(200, 22)
        $adNameBox.Font = $inputFont
        $adNameBox.BackColor = $script:Theme.InputBackground
        $adNameBox.ForeColor = $script:Theme.Text
        $adNameBox.Text = if ($null -ne $adapter -and $adapter.PSObject.Properties['AdapterName']) { $adapter.AdapterName } else { "" }
        $adNameBox.Tag = "adapterName_$i"
        $scrollPanel.Controls.Add($adNameBox)

        # Warn via border color when AdapterName is left empty (non-blocking)
        $adNameBox.Add_LostFocus({
            $tb = $this
            if ([string]::IsNullOrWhiteSpace($tb.Text)) {
                $tb.BackColor = [System.Drawing.Color]::FromArgb(25, 245, 158, 11)
            } else {
                $tb.BackColor = $script:Theme.InputBackground
            }
        })
        $adNameBox.Add_GotFocus({
            $this.BackColor = $script:Theme.InputBackground
        })
        $currentY += 28

        # ---- IP Address ----
        $ipLbl = New-Object System.Windows.Forms.Label
        $ipLbl.Text = "IP:"
        $ipLbl.Location = New-Object System.Drawing.Point(30, ($currentY + 2))
        $ipLbl.Size = New-Object System.Drawing.Size(30, 20)
        $ipLbl.Font = $inputFont
        $ipLbl.ForeColor = $script:Theme.TextSecondary
        $scrollPanel.Controls.Add($ipLbl)

        $ipBox = New-Object System.Windows.Forms.TextBox
        $ipBox.Location = New-Object System.Drawing.Point(65, $currentY)
        $ipBox.Size = New-Object System.Drawing.Size(120, 22)
        $ipBox.Font = $inputFont
        $ipBox.BackColor = $script:Theme.InputBackground
        $ipBox.ForeColor = $script:Theme.Text
        $ipBox.Text = if ($null -ne $adapter -and $adapter.PSObject.Properties['IPAddress']) { $adapter.IPAddress } else { "" }
        $scrollPanel.Controls.Add($ipBox)
        & $attachIPValidation $ipBox

        # Subnet Mask
        $subLbl = New-Object System.Windows.Forms.Label
        $subLbl.Text = "Mask:"
        $subLbl.Location = New-Object System.Drawing.Point(195, ($currentY + 2))
        $subLbl.Size = New-Object System.Drawing.Size(40, 20)
        $subLbl.Font = $inputFont
        $subLbl.ForeColor = $script:Theme.TextSecondary
        $scrollPanel.Controls.Add($subLbl)

        $subBox = New-Object System.Windows.Forms.TextBox
        $subBox.Location = New-Object System.Drawing.Point(240, $currentY)
        $subBox.Size = New-Object System.Drawing.Size(120, 22)
        $subBox.Font = $inputFont
        $subBox.BackColor = $script:Theme.InputBackground
        $subBox.ForeColor = $script:Theme.Text
        $subBox.Text = if ($null -ne $adapter -and $adapter.PSObject.Properties['SubnetMask']) { $adapter.SubnetMask } else { "" }
        $scrollPanel.Controls.Add($subBox)
        & $attachIPValidation $subBox

        # Gateway
        $gwLbl = New-Object System.Windows.Forms.Label
        $gwLbl.Text = "GW:"
        $gwLbl.Location = New-Object System.Drawing.Point(370, ($currentY + 2))
        $gwLbl.Size = New-Object System.Drawing.Size(30, 20)
        $gwLbl.Font = $inputFont
        $gwLbl.ForeColor = $script:Theme.TextSecondary
        $scrollPanel.Controls.Add($gwLbl)

        $gwBox = New-Object System.Windows.Forms.TextBox
        $gwBox.Location = New-Object System.Drawing.Point(405, $currentY)
        $gwBox.Size = New-Object System.Drawing.Size(120, 22)
        $gwBox.Font = $inputFont
        $gwBox.BackColor = $script:Theme.InputBackground
        $gwBox.ForeColor = $script:Theme.Text
        $gwBox.Text = if ($null -ne $adapter -and $adapter.PSObject.Properties['Gateway']) { $adapter.Gateway } else { "" }
        $scrollPanel.Controls.Add($gwBox)
        & $attachIPValidation $gwBox
        $currentY += 26

        # ---- DNS1 / DNS2 ----
        $dns1Lbl = New-Object System.Windows.Forms.Label
        $dns1Lbl.Text = "Primary DNS:"
        $dns1Lbl.Location = New-Object System.Drawing.Point(30, ($currentY + 2))
        $dns1Lbl.Size = New-Object System.Drawing.Size(85, 20)
        $dns1Lbl.Font = $inputFont
        $dns1Lbl.ForeColor = $script:Theme.TextSecondary
        $scrollPanel.Controls.Add($dns1Lbl)

        $dns1Box = New-Object System.Windows.Forms.TextBox
        $dns1Box.Location = New-Object System.Drawing.Point(120, $currentY)
        $dns1Box.Size = New-Object System.Drawing.Size(120, 22)
        $dns1Box.Font = $inputFont
        $dns1Box.BackColor = $script:Theme.InputBackground
        $dns1Box.ForeColor = $script:Theme.Text
        $dns1Box.Text = if ($null -ne $adapter -and $adapter.PSObject.Properties['DNS1']) { $adapter.DNS1 } else { "" }
        $scrollPanel.Controls.Add($dns1Box)
        & $attachIPValidation $dns1Box

        $dns2Lbl = New-Object System.Windows.Forms.Label
        $dns2Lbl.Text = "Secondary DNS:"
        $dns2Lbl.Location = New-Object System.Drawing.Point(250, ($currentY + 2))
        $dns2Lbl.Size = New-Object System.Drawing.Size(105, 20)
        $dns2Lbl.Font = $inputFont
        $dns2Lbl.ForeColor = $script:Theme.TextSecondary
        $scrollPanel.Controls.Add($dns2Lbl)

        $dns2Box = New-Object System.Windows.Forms.TextBox
        $dns2Box.Location = New-Object System.Drawing.Point(360, $currentY)
        $dns2Box.Size = New-Object System.Drawing.Size(120, 22)
        $dns2Box.Font = $inputFont
        $dns2Box.BackColor = $script:Theme.InputBackground
        $dns2Box.ForeColor = $script:Theme.Text
        $dns2Box.Text = if ($null -ne $adapter -and $adapter.PSObject.Properties['DNS2']) { $adapter.DNS2 } else { "" }
        $scrollPanel.Controls.Add($dns2Box)
        & $attachIPValidation $dns2Box
        $currentY += 26

        # ---- DHCP / Enabled checkboxes ----
        $dhcpCheck = New-Object System.Windows.Forms.CheckBox
        $dhcpCheck.Text = "DHCP"
        $dhcpCheck.Location = New-Object System.Drawing.Point(30, $currentY)
        $dhcpCheck.Size = New-Object System.Drawing.Size(65, 20)
        $dhcpCheck.Font = $inputFont
        $dhcpCheck.ForeColor = $script:Theme.Text
        $dhcpCheck.Checked = if ($null -ne $adapter -and $adapter.PSObject.Properties['DHCP']) { $adapter.DHCP } else { $false }
        $scrollPanel.Controls.Add($dhcpCheck)

        $enabledCheck = New-Object System.Windows.Forms.CheckBox
        $enabledCheck.Text = "Enabled"
        $enabledCheck.Location = New-Object System.Drawing.Point(100, $currentY)
        $enabledCheck.Size = New-Object System.Drawing.Size(75, 20)
        $enabledCheck.Font = $inputFont
        $enabledCheck.ForeColor = $script:Theme.Text
        $enabledCheck.Checked = if ($null -ne $adapter -and $adapter.PSObject.Properties['Enabled']) { $adapter.Enabled } else { $true }
        $scrollPanel.Controls.Add($enabledCheck)

        $currentY += 32

        # Store references for all new and existing fields
        $adapterControls += @{
            Index        = $i
            AdapterNameBox = $adNameBox
            IPBox        = $ipBox
            SubnetBox    = $subBox
            GatewayBox   = $gwBox
            DNS1Box      = $dns1Box
            DNS2Box      = $dns2Box
            DHCPCheck    = $dhcpCheck
            EnabledCheck = $enabledCheck
        }
    }

    # ---- Separator ----
    $sep2 = New-Object System.Windows.Forms.Label
    $sep2.Location = New-Object System.Drawing.Point(15, $currentY)
    $sep2.Size = New-Object System.Drawing.Size($innerWidth, 1)
    $sep2.BackColor = $script:Theme.Border
    $scrollPanel.Controls.Add($sep2)
    $currentY += 10

    # ---- SMB Settings Section ----
    $smbSectionLabel = New-Object System.Windows.Forms.Label
    $smbSectionLabel.Text = "SMB Sharing"
    $smbSectionLabel.Location = New-Object System.Drawing.Point(15, $currentY)
    $smbSectionLabel.Size = New-Object System.Drawing.Size($innerWidth, 22)
    $smbSectionLabel.Font = $sectionFont
    $smbSectionLabel.ForeColor = $script:Theme.Primary
    $scrollPanel.Controls.Add($smbSectionLabel)
    $currentY += 28

    $smbSettings = if ($Profile.PSObject.Properties['SMBSettings'] -and $null -ne $Profile.SMBSettings) { $Profile.SMBSettings } else { $null }

    $shareCheck = New-Object System.Windows.Forms.CheckBox
    $shareCheck.Text = "Share d3 Projects"
    $shareCheck.Location = New-Object System.Drawing.Point(15, $currentY)
    $shareCheck.Size = New-Object System.Drawing.Size(150, 20)
    $shareCheck.Font = $inputFont
    $shareCheck.ForeColor = $script:Theme.Text
    $shareCheck.Checked = if ($null -ne $smbSettings -and $smbSettings.PSObject.Properties['ShareD3Projects']) { $smbSettings.ShareD3Projects } else { $false }
    $scrollPanel.Controls.Add($shareCheck)
    $currentY += 26

    # Share Name
    $shareNameLbl = New-Object System.Windows.Forms.Label
    $shareNameLbl.Text = "Share Name:"
    $shareNameLbl.Location = New-Object System.Drawing.Point(15, ($currentY + 2))
    $shareNameLbl.Size = New-Object System.Drawing.Size(85, 20)
    $shareNameLbl.Font = $inputFont
    $shareNameLbl.ForeColor = $script:Theme.TextSecondary
    $scrollPanel.Controls.Add($shareNameLbl)

    $shareNameBox = New-Object System.Windows.Forms.TextBox
    $shareNameBox.Location = New-Object System.Drawing.Point(105, $currentY)
    $shareNameBox.Size = New-Object System.Drawing.Size(200, 22)
    $shareNameBox.Font = $inputFont
    $shareNameBox.BackColor = $script:Theme.InputBackground
    $shareNameBox.ForeColor = $script:Theme.Text
    $shareNameBox.Text = if ($null -ne $smbSettings -and $smbSettings.PSObject.Properties['ShareName']) { $smbSettings.ShareName } else { "d3 Projects" }
    $scrollPanel.Controls.Add($shareNameBox)
    $currentY += 26

    # Projects Path
    $projPathLbl = New-Object System.Windows.Forms.Label
    $projPathLbl.Text = "Path:"
    $projPathLbl.Location = New-Object System.Drawing.Point(15, ($currentY + 2))
    $projPathLbl.Size = New-Object System.Drawing.Size(85, 20)
    $projPathLbl.Font = $inputFont
    $projPathLbl.ForeColor = $script:Theme.TextSecondary
    $scrollPanel.Controls.Add($projPathLbl)

    $projPathBox = New-Object System.Windows.Forms.TextBox
    $projPathBox.Location = New-Object System.Drawing.Point(105, $currentY)
    $projPathBox.Size = New-Object System.Drawing.Size(380, 22)
    $projPathBox.Font = $inputFont
    $projPathBox.BackColor = $script:Theme.InputBackground
    $projPathBox.ForeColor = $script:Theme.Text
    $projPathBox.Text = if ($null -ne $smbSettings -and $smbSettings.PSObject.Properties['ProjectsPath']) { $smbSettings.ProjectsPath } else { "D:\d3 Projects" }
    $scrollPanel.Controls.Add($projPathBox)
    $currentY += 30

    # Add padding at end for scroll
    $padLabel = New-Object System.Windows.Forms.Label
    $padLabel.Location = New-Object System.Drawing.Point(0, $currentY)
    $padLabel.Size = New-Object System.Drawing.Size(1, 10)
    $scrollPanel.Controls.Add($padLabel)

    $form.Controls.Add($scrollPanel)

    # ---- Button bar at bottom ----
    $btnPanel = New-Object System.Windows.Forms.Panel
    $btnPanel.Location = New-Object System.Drawing.Point(0, ($form.ClientSize.Height - 50))
    $btnPanel.Size = New-Object System.Drawing.Size($form.ClientSize.Width, 50)
    $btnPanel.BackColor = $script:Theme.Surface
    $btnPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor
        [System.Windows.Forms.AnchorStyles]::Left -bor
        [System.Windows.Forms.AnchorStyles]::Right

    $saveButton = New-Object System.Windows.Forms.Button
    $saveButton.Text = "Save"
    $saveButton.Location = New-Object System.Drawing.Point(($form.ClientSize.Width - 200), 8)
    $saveButton.Size = New-Object System.Drawing.Size(85, 34)
    $saveButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $saveButton.FlatStyle = 'Flat'
    $saveButton.BackColor = $script:Theme.Primary
    $saveButton.ForeColor = [System.Drawing.Color]::White
    $saveButton.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $saveButton.Anchor = [System.Windows.Forms.AnchorStyles]::Right
    $btnPanel.Controls.Add($saveButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Location = New-Object System.Drawing.Point(($form.ClientSize.Width - 100), 8)
    $cancelButton.Size = New-Object System.Drawing.Size(85, 34)
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancelButton.FlatStyle = 'Flat'
    $cancelButton.BackColor = $script:Theme.Surface
    $cancelButton.ForeColor = $script:Theme.Text
    $cancelButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $cancelButton.Anchor = [System.Windows.Forms.AnchorStyles]::Right
    $btnPanel.Controls.Add($cancelButton)

    $form.Controls.Add($btnPanel)
    $form.AcceptButton = $saveButton
    $form.CancelButton = $cancelButton

    $dialogResult = $form.ShowDialog()

    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        # Apply changes to the profile object
        $Profile.ServerName = $serverNameBox.Text.Trim()

        # Update network adapters
        for ($i = 0; $i -lt $adapterControls.Count; $i++) {
            $ctrl = $adapterControls[$i]
            $idx = $ctrl.Index

            # Ensure the adapter array and entry exist
            if ($null -eq $Profile.NetworkAdapters) {
                $Profile.NetworkAdapters = @()
            }
            if ($idx -lt $Profile.NetworkAdapters.Count -and $null -ne $Profile.NetworkAdapters[$idx]) {
                $Profile.NetworkAdapters[$idx].AdapterName = $ctrl.AdapterNameBox.Text.Trim()
                $Profile.NetworkAdapters[$idx].IPAddress   = $ctrl.IPBox.Text.Trim()
                $Profile.NetworkAdapters[$idx].SubnetMask  = $ctrl.SubnetBox.Text.Trim()
                $Profile.NetworkAdapters[$idx].Gateway     = $ctrl.GatewayBox.Text.Trim()
                $Profile.NetworkAdapters[$idx].DNS1        = $ctrl.DNS1Box.Text.Trim()
                $Profile.NetworkAdapters[$idx].DNS2        = $ctrl.DNS2Box.Text.Trim()
                $Profile.NetworkAdapters[$idx].DHCP        = $ctrl.DHCPCheck.Checked
                $Profile.NetworkAdapters[$idx].Enabled     = $ctrl.EnabledCheck.Checked
            }
        }

        # Update SMB settings
        if ($null -eq $Profile.SMBSettings) {
            $Profile.SMBSettings = [PSCustomObject]@{
                ShareD3Projects  = $false
                ProjectsPath     = "D:\d3 Projects"
                ShareName        = "d3 Projects"
                SharePermissions = "Administrators:Full"
                AdditionalShares = @()
            }
        }
        $Profile.SMBSettings.ShareD3Projects = $shareCheck.Checked
        $Profile.SMBSettings.ShareName = $shareNameBox.Text.Trim()
        $Profile.SMBSettings.ProjectsPath = $projPathBox.Text.Trim()

        $form.Dispose()
        return $true
    }

    $form.Dispose()
    return $false
}


# ============================================================================
# BATCH PROFILE GENERATION & RIG BUNDLE IMPORT/EXPORT
# ============================================================================

function Show-BatchProfileWizard {
    <#
    .SYNOPSIS
        Opens a wizard dialog for generating a complete rig's worth of profiles.
    .DESCRIPTION
        Presents a form with fields for show prefix, machine counts, base subnet,
        and starting IP offset. Generates Director, Actor, and Understudy profiles
        with properly sequenced network adapter IPs and standard SMB settings.
    .OUTPUTS
        System.Int32
        Number of profiles generated, or 0 if cancelled or failed.
    #>

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Batch Profile Generator - Rig Setup"
    $form.Size = New-Object System.Drawing.Size(500, 480)
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.BackColor = $script:Theme.Background
    $form.ForeColor = $script:Theme.Text

    $labelFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $inputFont = New-Object System.Drawing.Font("Segoe UI", 10)
    $sectionFont = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $currentY = 15
    $labelX = 15
    $inputX = 250
    $inputWidth = 210

    # ---- Section: General ----
    $sectionLabel = New-Object System.Windows.Forms.Label
    $sectionLabel.Text = "Rig Configuration"
    $sectionLabel.Location = New-Object System.Drawing.Point($labelX, $currentY)
    $sectionLabel.Size = New-Object System.Drawing.Size(450, 25)
    $sectionLabel.Font = $sectionFont
    $sectionLabel.ForeColor = $script:Theme.Primary
    $form.Controls.Add($sectionLabel)
    $currentY += 35

    # Show Prefix
    $prefixLabel = New-Object System.Windows.Forms.Label
    $prefixLabel.Text = "Show Prefix:"
    $prefixLabel.Location = New-Object System.Drawing.Point($labelX, ($currentY + 3))
    $prefixLabel.Size = New-Object System.Drawing.Size(220, 22)
    $prefixLabel.Font = $labelFont
    $prefixLabel.ForeColor = $script:Theme.Text
    $form.Controls.Add($prefixLabel)

    $prefixBox = New-Object System.Windows.Forms.TextBox
    $prefixBox.Location = New-Object System.Drawing.Point($inputX, $currentY)
    $prefixBox.Size = New-Object System.Drawing.Size($inputWidth, 28)
    $prefixBox.Font = $inputFont
    $prefixBox.Text = "SHOW"
    $prefixBox.BackColor = $script:Theme.InputBackground
    $prefixBox.ForeColor = $script:Theme.Text
    $prefixBox.MaxLength = 10
    $form.Controls.Add($prefixBox)
    $currentY += 38

    # Director Count
    $dirLabel = New-Object System.Windows.Forms.Label
    $dirLabel.Text = "Director Count:"
    $dirLabel.Location = New-Object System.Drawing.Point($labelX, ($currentY + 3))
    $dirLabel.Size = New-Object System.Drawing.Size(220, 22)
    $dirLabel.Font = $labelFont
    $dirLabel.ForeColor = $script:Theme.Text
    $form.Controls.Add($dirLabel)

    $dirCountUpDown = New-Object System.Windows.Forms.NumericUpDown
    $dirCountUpDown.Location = New-Object System.Drawing.Point($inputX, $currentY)
    $dirCountUpDown.Size = New-Object System.Drawing.Size(80, 28)
    $dirCountUpDown.Font = $inputFont
    $dirCountUpDown.Minimum = 0
    $dirCountUpDown.Maximum = 2
    $dirCountUpDown.Value = 1
    $dirCountUpDown.BackColor = $script:Theme.InputBackground
    $dirCountUpDown.ForeColor = $script:Theme.Text
    $form.Controls.Add($dirCountUpDown)
    $currentY += 38

    # Actor Count
    $actLabel = New-Object System.Windows.Forms.Label
    $actLabel.Text = "Actor Count:"
    $actLabel.Location = New-Object System.Drawing.Point($labelX, ($currentY + 3))
    $actLabel.Size = New-Object System.Drawing.Size(220, 22)
    $actLabel.Font = $labelFont
    $actLabel.ForeColor = $script:Theme.Text
    $form.Controls.Add($actLabel)

    $actCountUpDown = New-Object System.Windows.Forms.NumericUpDown
    $actCountUpDown.Location = New-Object System.Drawing.Point($inputX, $currentY)
    $actCountUpDown.Size = New-Object System.Drawing.Size(80, 28)
    $actCountUpDown.Font = $inputFont
    $actCountUpDown.Minimum = 1
    $actCountUpDown.Maximum = 16
    $actCountUpDown.Value = 4
    $actCountUpDown.BackColor = $script:Theme.InputBackground
    $actCountUpDown.ForeColor = $script:Theme.Text
    $form.Controls.Add($actCountUpDown)
    $currentY += 38

    # Understudy Count
    $undLabel = New-Object System.Windows.Forms.Label
    $undLabel.Text = "Understudy Count:"
    $undLabel.Location = New-Object System.Drawing.Point($labelX, ($currentY + 3))
    $undLabel.Size = New-Object System.Drawing.Size(220, 22)
    $undLabel.Font = $labelFont
    $undLabel.ForeColor = $script:Theme.Text
    $form.Controls.Add($undLabel)

    $undCountUpDown = New-Object System.Windows.Forms.NumericUpDown
    $undCountUpDown.Location = New-Object System.Drawing.Point($inputX, $currentY)
    $undCountUpDown.Size = New-Object System.Drawing.Size(80, 28)
    $undCountUpDown.Font = $inputFont
    $undCountUpDown.Minimum = 0
    $undCountUpDown.Maximum = 8
    $undCountUpDown.Value = 0
    $undCountUpDown.BackColor = $script:Theme.InputBackground
    $undCountUpDown.ForeColor = $script:Theme.Text
    $form.Controls.Add($undCountUpDown)
    $currentY += 45

    # ---- Section: Network ----
    $netSectionLabel = New-Object System.Windows.Forms.Label
    $netSectionLabel.Text = "Network Settings"
    $netSectionLabel.Location = New-Object System.Drawing.Point($labelX, $currentY)
    $netSectionLabel.Size = New-Object System.Drawing.Size(450, 25)
    $netSectionLabel.Font = $sectionFont
    $netSectionLabel.ForeColor = $script:Theme.Primary
    $form.Controls.Add($netSectionLabel)
    $currentY += 35

    # Base Subnet
    $subnetLabel = New-Object System.Windows.Forms.Label
    $subnetLabel.Text = "Base Subnet (first 2 octets):"
    $subnetLabel.Location = New-Object System.Drawing.Point($labelX, ($currentY + 3))
    $subnetLabel.Size = New-Object System.Drawing.Size(220, 22)
    $subnetLabel.Font = $labelFont
    $subnetLabel.ForeColor = $script:Theme.Text
    $form.Controls.Add($subnetLabel)

    $subnetBox = New-Object System.Windows.Forms.TextBox
    $subnetBox.Location = New-Object System.Drawing.Point($inputX, $currentY)
    $subnetBox.Size = New-Object System.Drawing.Size($inputWidth, 28)
    $subnetBox.Font = $inputFont
    $subnetBox.Text = "192.168"
    $subnetBox.BackColor = $script:Theme.InputBackground
    $subnetBox.ForeColor = $script:Theme.Text
    $form.Controls.Add($subnetBox)
    $currentY += 38

    # Starting IP Offset
    $offsetLabel = New-Object System.Windows.Forms.Label
    $offsetLabel.Text = "Starting IP Offset (4th octet):"
    $offsetLabel.Location = New-Object System.Drawing.Point($labelX, ($currentY + 3))
    $offsetLabel.Size = New-Object System.Drawing.Size(220, 22)
    $offsetLabel.Font = $labelFont
    $offsetLabel.ForeColor = $script:Theme.Text
    $form.Controls.Add($offsetLabel)

    $offsetUpDown = New-Object System.Windows.Forms.NumericUpDown
    $offsetUpDown.Location = New-Object System.Drawing.Point($inputX, $currentY)
    $offsetUpDown.Size = New-Object System.Drawing.Size(80, 28)
    $offsetUpDown.Font = $inputFont
    $offsetUpDown.Minimum = 1
    $offsetUpDown.Maximum = 250
    $offsetUpDown.Value = 10
    $offsetUpDown.BackColor = $script:Theme.InputBackground
    $offsetUpDown.ForeColor = $script:Theme.Text
    $form.Controls.Add($offsetUpDown)
    $currentY += 50

    # ---- Buttons ----
    $generateBtn = New-Object System.Windows.Forms.Button
    $generateBtn.Text = "Generate"
    $generateBtn.Location = New-Object System.Drawing.Point(270, $currentY)
    $generateBtn.Size = New-Object System.Drawing.Size(100, 38)
    $generateBtn.FlatStyle = 'Flat'
    $generateBtn.FlatAppearance.BorderSize = 0
    $generateBtn.BackColor = $script:Theme.Primary
    $generateBtn.ForeColor = [System.Drawing.Color]::White
    $generateBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $generateBtn.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($generateBtn)

    $cancelBtn = New-Object System.Windows.Forms.Button
    $cancelBtn.Text = "Cancel"
    $cancelBtn.Location = New-Object System.Drawing.Point(380, $currentY)
    $cancelBtn.Size = New-Object System.Drawing.Size(85, 38)
    $cancelBtn.FlatStyle = 'Flat'
    $cancelBtn.FlatAppearance.BorderSize = 0
    $cancelBtn.BackColor = $script:Theme.Surface
    $cancelBtn.ForeColor = $script:Theme.Text
    $cancelBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $cancelBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancelBtn)

    $form.AcceptButton = $generateBtn
    $form.CancelButton = $cancelBtn

    $dialogResult = $form.ShowDialog()

    if ($dialogResult -ne [System.Windows.Forms.DialogResult]::OK) {
        $form.Dispose()
        return 0
    }

    # ---- Capture field values before disposing the form ----
    $prefix = $prefixBox.Text.Trim().ToUpper()
    $dirCount = [int]$dirCountUpDown.Value
    $actCount = [int]$actCountUpDown.Value
    $undCount = [int]$undCountUpDown.Value
    $baseSubnet = $subnetBox.Text.Trim()
    $startOffset = [int]$offsetUpDown.Value
    $form.Dispose()

    # ---- Validate inputs ----
    if ([string]::IsNullOrWhiteSpace($prefix)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Show Prefix cannot be empty.",
            "Validation Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return 0
    }

    # Validate prefix contains only NetBIOS-safe characters (alphanumeric and hyphens)
    if ($prefix -match '[^A-Z0-9\-]') {
        [System.Windows.Forms.MessageBox]::Show(
            "Show Prefix contains invalid characters. Use only letters, digits, and hyphens.",
            "Validation Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return 0
    }

    # Validate base subnet format (two octets like "192.168")
    if ($baseSubnet -notmatch '^\d{1,3}\.\d{1,3}$') {
        [System.Windows.Forms.MessageBox]::Show(
            "Base Subnet must be two octets separated by a dot (e.g. '192.168').",
            "Validation Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return 0
    }

    # Validate each octet of the base subnet is within 0-255
    $subnetOctets = $baseSubnet -split '\.'
    foreach ($octet in $subnetOctets) {
        $octetVal = [int]$octet
        if ($octetVal -lt 0 -or $octetVal -gt 255) {
            [System.Windows.Forms.MessageBox]::Show(
                "Base Subnet octets must be between 0 and 255.",
                "Validation Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return 0
        }
    }

    # Validate total machine count will not overflow the 4th octet
    $totalMachines = $dirCount + $actCount + $undCount
    if ($totalMachines -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Total machine count must be at least 1.",
            "Validation Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return 0
    }

    $maxOffset = $startOffset + $totalMachines - 1
    if ($maxOffset -gt 254) {
        [System.Windows.Forms.MessageBox]::Show(
            "IP offset overflow: $totalMachines machines starting at offset $startOffset would exceed .254.`nReduce machine count or lower the starting offset.",
            "Validation Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return 0
    }

    # ---- Build machine list ----
    $machines = @()

    for ($i = 1; $i -le $dirCount; $i++) {
        $suffix = if ($dirCount -eq 1) { "DIR" } else { "DIR{0:D2}" -f $i }
        $hostname = "$prefix-$suffix"
        $machines += @{
            Hostname    = $hostname
            ProfileName = "$prefix-$suffix"
            Type        = "Director"
            Description = "Director $i - sequences the show, sends start commands to Actors"
        }
    }

    for ($i = 1; $i -le $actCount; $i++) {
        $suffix = "ACT{0:D2}" -f $i
        $hostname = "$prefix-$suffix"
        $machines += @{
            Hostname    = $hostname
            ProfileName = "$prefix-$suffix"
            Type        = "Actor"
            Description = "Actor $i - outputs video according to assigned Feed scenes"
        }
    }

    for ($i = 1; $i -le $undCount; $i++) {
        $suffix = "UND{0:D2}" -f $i
        $hostname = "$prefix-$suffix"
        $machines += @{
            Hostname    = $hostname
            ProfileName = "$prefix-$suffix"
            Type        = "Understudy"
            Description = "Understudy $i - standby replacement for failover"
        }
    }

    # ---- Validate all hostnames are within 15-char NetBIOS limit ----
    foreach ($machine in $machines) {
        if ($machine.Hostname.Length -gt 15) {
            [System.Windows.Forms.MessageBox]::Show(
                "Hostname '$($machine.Hostname)' exceeds the 15-character NetBIOS limit.`nShorten the Show Prefix.",
                "Validation Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return 0
        }
    }

    # ---- Generate profiles ----
    $generatedNames = @()
    $currentOffset = $startOffset
    $errors = @()

    foreach ($machine in $machines) {
        try {
            $profile = New-DefaultProfile -Name $machine.ProfileName -Description $machine.Description
            $profile.ServerName = $machine.Hostname

            # Configure network adapter IPs based on the current offset
            # Adapter 0 - d3Net:   {base}.10.{offset}
            # Adapter 1 - Media:   {base}.20.{offset}
            # Adapter 2 - sACN:    2.0.0.{offset} (sACN standard)
            # Adapter 3 - NDI:     {base}.30.{offset}
            # Adapter 4 - Control: {base}.40.{offset}
            # Adapter 5 - Internet: DHCP (no changes needed, already default)

            if ($profile.NetworkAdapters.Count -ge 6) {
                $profile.NetworkAdapters[0].IPAddress  = "$baseSubnet.10.$currentOffset"
                $profile.NetworkAdapters[0].SubnetMask = "255.255.255.0"

                $profile.NetworkAdapters[1].IPAddress  = "$baseSubnet.20.$currentOffset"
                $profile.NetworkAdapters[1].SubnetMask = "255.255.255.0"

                $profile.NetworkAdapters[2].IPAddress  = "2.0.0.$currentOffset"
                $profile.NetworkAdapters[2].SubnetMask = "255.0.0.0"

                $profile.NetworkAdapters[3].IPAddress  = "$baseSubnet.30.$currentOffset"
                $profile.NetworkAdapters[3].SubnetMask = "255.255.255.0"

                $profile.NetworkAdapters[4].IPAddress  = "$baseSubnet.40.$currentOffset"
                $profile.NetworkAdapters[4].SubnetMask = "255.255.255.0"

                # Adapter 5 (Internet) stays DHCP - already set by New-DefaultProfile
            }

            # Configure SMB settings
            $profile.SMBSettings.ShareD3Projects  = $true
            $profile.SMBSettings.ShareName        = "d3 Projects"
            $profile.SMBSettings.ProjectsPath     = "D:\d3 Projects"
            $profile.SMBSettings.SharePermissions  = "Administrators:Full"

            Save-Profile -Profile $profile
            $generatedNames += $machine.ProfileName
            $currentOffset++
        }
        catch {
            $errors += "Failed to create '$($machine.ProfileName)': $_"
            Write-AppLog "Batch generation error for '$($machine.ProfileName)': $_" -Level 'ERROR'
        }
    }

    # ---- Show summary ----
    $generatedCount = $generatedNames.Count
    if ($generatedCount -gt 0) {
        $nameList = $generatedNames -join "`n  "
        $plural = if ($generatedCount -ne 1) { 's' } else { '' }
        $summaryMsg = "Generated $generatedCount profile${plural}:`n`n  $nameList"
        if ($errors.Count -gt 0) {
            $summaryMsg += "`n`nErrors ($($errors.Count)):`n" + ($errors -join "`n")
        }
        [System.Windows.Forms.MessageBox]::Show(
            $summaryMsg,
            "Batch Generation Complete",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        $generatedNameStr = $generatedNames -join ', '
        Write-AppLog "Batch generated $generatedCount profiles: $generatedNameStr" -Level 'INFO'
    }
    else {
        $errorMsg = "No profiles were generated."
        if ($errors.Count -gt 0) {
            $errorMsg += "`n`nErrors:`n" + ($errors -join "`n")
        }
        [System.Windows.Forms.MessageBox]::Show(
            $errorMsg,
            "Batch Generation Failed",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        $batchErrorStr = $errors -join '; '
        Write-AppLog "Batch generation failed: $batchErrorStr" -Level 'ERROR'
    }

    return $generatedCount
}


function Export-RigBundle {
    <#
    .SYNOPSIS
        Exports all saved profiles as a ZIP archive (rig bundle).
    .DESCRIPTION
        Collects all .json profile files from the profiles directory, copies them
        to a temporary directory, and creates a ZIP archive at a user-chosen location.
    .OUTPUTS
        [PSCustomObject] - @{ Success = [bool]; Message = [string] }
    #>
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $profilesDir = Get-ProfilesDirectory
    $jsonFiles = @(Get-ChildItem -Path $profilesDir -Filter '*.json' -File -ErrorAction SilentlyContinue)

    if ($jsonFiles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No profiles found to export. Create some profiles first.",
            "No Profiles",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return [PSCustomObject]@{ Success = $false; Message = "No profiles to export" }
    }

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Title = "Export Rig Bundle"
    $saveDialog.Filter = "Rig Bundle (*.zip)|*.zip"
    $saveDialog.DefaultExt = "zip"
    $saveDialog.FileName = "RigBundle_$(Get-Date -Format 'yyyyMMdd_HHmm').zip"
    $saveDialog.OverwritePrompt = $true

    if ($saveDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return [PSCustomObject]@{ Success = $false; Message = "Export cancelled" }
    }

    $zipPath = $saveDialog.FileName
    $tempDir = $null

    try {
        # Create a temp directory and copy profile files into it
        $tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "DisguiseBuddy_RigExport_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

        foreach ($file in $jsonFiles) {
            Copy-Item -Path $file.FullName -Destination $tempDir -Force
        }

        # Remove the target ZIP if it already exists (CreateFromDirectory fails on existing file)
        if (Test-Path -Path $zipPath) {
            Remove-Item -Path $zipPath -Force
        }

        [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $zipPath)

        $exportPlural = if ($jsonFiles.Count -ne 1) { 's' } else { '' }
        $successMsg = "Exported $($jsonFiles.Count) profile${exportPlural} to:`n$zipPath"
        [System.Windows.Forms.MessageBox]::Show(
            $successMsg,
            "Export Successful",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        Write-AppLog "Exported rig bundle with $($jsonFiles.Count) profiles to '$zipPath'" -Level 'INFO'
        return [PSCustomObject]@{ Success = $true; Message = "Exported $($jsonFiles.Count) profiles" }
    }
    catch {
        Write-AppLog "Failed to export rig bundle: $_" -Level 'ERROR'
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to create rig bundle:`n$_",
            "Export Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return [PSCustomObject]@{ Success = $false; Message = "Export failed: $_" }
    }
    finally {
        # Clean up temp directory
        if ($tempDir -and (Test-Path -Path $tempDir)) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}


function Import-RigBundle {
    <#
    .SYNOPSIS
        Imports profiles from a ZIP archive (rig bundle).
    .DESCRIPTION
        Opens a ZIP file, extracts .json profile files to a temp directory, validates
        each with Test-ProfileSchema, handles name conflicts (overwrite/skip/rename),
        and copies valid profiles to the profiles directory.
    .OUTPUTS
        [PSCustomObject] - @{ Success = [bool]; Message = [string]; ImportedCount = [int]; SkippedCount = [int] }
    #>
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Title = "Import Rig Bundle"
    $openDialog.Filter = "Rig Bundle (*.zip)|*.zip"
    $openDialog.Multiselect = $false

    if ($openDialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return [PSCustomObject]@{ Success = $false; Message = "Import cancelled"; ImportedCount = 0; SkippedCount = 0 }
    }

    $zipPath = $openDialog.FileName
    $profilesDir = Get-ProfilesDirectory
    $tempDir = $null
    $importedCount = 0
    $skippedCount = 0
    $errors = @()

    try {
        # Extract to a temp directory
        $tempDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "DisguiseBuddy_RigImport_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

        # Per-entry extraction with Zip Slip protection (validate before writing)
        $resolvedTempDir = [System.IO.Path]::GetFullPath($tempDir)
        $zipArchive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            foreach ($entry in $zipArchive.Entries) {
                if ([string]::IsNullOrWhiteSpace($entry.Name)) { continue }  # skip directory entries
                $destPath = [System.IO.Path]::GetFullPath((Join-Path $tempDir $entry.FullName))
                if (-not $destPath.StartsWith($resolvedTempDir, [System.StringComparison]::OrdinalIgnoreCase)) {
                    Write-AppLog "Import-RigBundle: Zip Slip blocked - '$($entry.FullName)' escapes temp dir. Aborting." -Level 'ERROR'
                    return [PSCustomObject]@{ Success = $false; Message = "Archive contains unsafe path: $($entry.FullName)"; ImportedCount = 0; SkippedCount = 0 }
                }
                $destDir = [System.IO.Path]::GetDirectoryName($destPath)
                if (-not (Test-Path $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destPath, $true)
            }
        } finally {
            $zipArchive.Dispose()
        }

        # Find all .json files in the extracted content (including subdirectories)
        $extractedFiles = @(Get-ChildItem -Path $tempDir -Filter '*.json' -File -Recurse -ErrorAction SilentlyContinue)

        if ($extractedFiles.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "The selected ZIP file does not contain any .json profile files.",
                "No Profiles Found",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return [PSCustomObject]@{ Success = $false; Message = "No profiles in archive"; ImportedCount = 0; SkippedCount = 0 }
        }

        foreach ($file in $extractedFiles) {
            try {
                $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8
                $importedProfile = $content | ConvertFrom-Json
            }
            catch {
                $errors += "Failed to parse '$($file.Name)': $_"
                $skippedCount++
                continue
            }

            # Basic field validation
            if (-not $importedProfile.Name) {
                $errors += "Skipped '$($file.Name)': missing 'Name' field"
                $skippedCount++
                continue
            }

            if (-not $importedProfile.NetworkAdapters) {
                $errors += "Skipped '$($file.Name)': missing 'NetworkAdapters' field"
                $skippedCount++
                continue
            }

            # Schema validation
            $schemaResult = Test-ProfileSchema -Profile $importedProfile
            if (-not $schemaResult.IsValid) {
                $schemaErrorStr = $schemaResult.Errors -join '; '
                $errors += "Skipped '$($importedProfile.Name)': $schemaErrorStr"
                $skippedCount++
                continue
            }

            # Check for name conflict
            $existingProfile = Get-Profile -Name $importedProfile.Name
            if ($null -ne $existingProfile) {
                $conflictResult = [System.Windows.Forms.MessageBox]::Show(
                    "A profile named '$($importedProfile.Name)' already exists.`n`nOverwrite it?`n`nYes = Overwrite  |  No = Skip  |  Cancel = Stop Import",
                    "Profile Conflict - $($importedProfile.Name)",
                    [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )

                if ($conflictResult -eq [System.Windows.Forms.DialogResult]::Cancel) {
                    # Stop the entire import
                    Write-AppLog "Rig bundle import cancelled by user at conflict for '$($importedProfile.Name)'" -Level 'INFO'
                    break
                }
                elseif ($conflictResult -eq [System.Windows.Forms.DialogResult]::No) {
                    $skippedCount++
                    continue
                }
                # If Yes, fall through and overwrite
            }

            # Save the profile
            try {
                $importedProfile.Modified = (Get-Date).ToString('o')
                Save-Profile -Profile $importedProfile
                $importedCount++
                Write-AppLog "Imported profile '$($importedProfile.Name)' from rig bundle" -Level 'INFO'
            }
            catch {
                $errors += "Failed to save '$($importedProfile.Name)': $_"
                $skippedCount++
            }
        }

        # Show summary
        $importPlural = if ($importedCount -ne 1) { 's' } else { '' }
        $summaryMsg = "Imported $importedCount profile${importPlural}, skipped $skippedCount."
        if ($errors.Count -gt 0) {
            $summaryMsg += "`n`nDetails:`n" + ($errors -join "`n")
        }

        $summaryIcon = if ($errors.Count -gt 0) {
            [System.Windows.Forms.MessageBoxIcon]::Warning
        } else {
            [System.Windows.Forms.MessageBoxIcon]::Information
        }

        [System.Windows.Forms.MessageBox]::Show(
            $summaryMsg,
            "Rig Bundle Import Complete",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            $summaryIcon
        ) | Out-Null

        Write-AppLog "Rig bundle import: $importedCount imported, $skippedCount skipped from '$zipPath'" -Level 'INFO'
        return [PSCustomObject]@{
            Success       = ($importedCount -gt 0)
            Message       = "Imported $importedCount, skipped $skippedCount"
            ImportedCount = $importedCount
            SkippedCount  = $skippedCount
        }
    }
    catch {
        Write-AppLog "Failed to import rig bundle: $_" -Level 'ERROR'
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to import rig bundle:`n$_",
            "Import Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return [PSCustomObject]@{ Success = $false; Message = "Import failed: $_"; ImportedCount = $importedCount; SkippedCount = $skippedCount }
    }
    finally {
        # Clean up temp directory
        if ($tempDir -and (Test-Path -Path $tempDir)) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}


# ============================================================================
# UI VIEW FUNCTION - Main Profiles Management View
# ============================================================================

function New-ProfilesView {
    <#
    .SYNOPSIS
        Creates the Profiles management view inside the given content panel.
    .DESCRIPTION
        Builds a two-column layout:
          - Left column: profile list with action buttons
          - Right column: profile detail view with summary cards and actions
    .PARAMETER ContentPanel
        The parent panel to populate with the profiles view controls.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.Panel]$ContentPanel
    )

    $ContentPanel.SuspendLayout()
    $ContentPanel.Controls.Clear()

    # ---- Module-scoped variables for cross-control communication ----
    $script:SelectedProfile = $null
    $script:ProfileListBox = $null
    $script:DetailPanel = $null

    # ---- Create a scroll panel to hold everything ----
    $scrollPanel = New-ScrollPanel -X 0 -Y 0 -Width $ContentPanel.Width -Height $ContentPanel.Height
    $scrollPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor
        [System.Windows.Forms.AnchorStyles]::Left -bor
        [System.Windows.Forms.AnchorStyles]::Right -bor
        [System.Windows.Forms.AnchorStyles]::Bottom

    # ---- Section Header ----
    $header = New-SectionHeader -Text "Configuration Profiles" -X 20 -Y 15 -Width ($ContentPanel.Width - 40)

    $scrollPanel.Controls.Add($header)

    # Subtitle label
    $subtitleLabel = New-StyledLabel -Text "Manage, apply, and share d3 server configuration profiles." `
        -X 20 -Y 55 -IsSecondary
    $scrollPanel.Controls.Add($subtitleLabel)

    # ========================================================================
    # LEFT COLUMN - Profile List (~350px)
    # ========================================================================
    $leftColumnX = 20
    $leftColumnY = 90
    $leftColumnWidth = 350

    $leftPanel = New-StyledPanel -X $leftColumnX -Y $leftColumnY `
        -Width $leftColumnWidth -Height 545 -IsCard
    $leftPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor
        [System.Windows.Forms.AnchorStyles]::Left -bor
        [System.Windows.Forms.AnchorStyles]::Bottom

    # Profile list header
    $listHeader = New-StyledLabel -Text "Saved Profiles" -X 12 -Y 10 -FontSize 12 -IsBold
    $leftPanel.Controls.Add($listHeader)

    # Profile count badge (updated dynamically)
    $script:ProfileCountLabel = New-StyledLabel -Text "" -X 12 -Y 35 -IsSecondary
    $leftPanel.Controls.Add($script:ProfileCountLabel)

    # Profile ListBox
    $profileListBox = New-Object System.Windows.Forms.ListBox
    $profileListBox.Location = New-Object System.Drawing.Point(12, 58)
    $profileListBox.Size = New-Object System.Drawing.Size(($leftColumnWidth - 24), 330)
    $profileListBox.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $profileListBox.BackColor = $script:Theme.InputBackground
    $profileListBox.ForeColor = $script:Theme.Text
    $profileListBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $profileListBox.DrawMode = [System.Windows.Forms.DrawMode]::OwnerDrawVariable
    $profileListBox.ItemHeight = 52
    $profileListBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor
        [System.Windows.Forms.AnchorStyles]::Left -bor
        [System.Windows.Forms.AnchorStyles]::Bottom

    $script:ProfileListBox = $profileListBox

    # Custom drawing for richer list items
    $profileListBox.Add_MeasureItem({
        param($sender, $e)
        $e.ItemHeight = 52
    })

    $profileListBox.Add_DrawItem({
        param($sender, $e)
        if ($e.Index -lt 0) { return }

        # Determine selection state
        $isSelected = ($e.State -band [System.Windows.Forms.DrawItemState]::Selected) -eq [System.Windows.Forms.DrawItemState]::Selected

        # Background
        if ($isSelected) {
            $bgBrush = New-Object System.Drawing.SolidBrush($script:Theme.Primary)
        }
        else {
            $bgBrush = New-Object System.Drawing.SolidBrush($script:Theme.InputBackground)
        }
        $e.Graphics.FillRectangle($bgBrush, $e.Bounds)
        $bgBrush.Dispose()

        # Get the profile data stored in the Tag
        $itemText = $sender.Items[$e.Index].ToString()
        $parts = $itemText -split '\|', 3

        $profileName = if ($parts.Count -ge 1) { $parts[0] } else { $itemText }
        $profileDesc = if ($parts.Count -ge 2) { $parts[1] } else { "" }
        $profileDate = if ($parts.Count -ge 3) { $parts[2] } else { "" }

        # Draw profile name (bold)
        $nameFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $nameBrush = New-Object System.Drawing.SolidBrush(
            $(if ($isSelected) { [System.Drawing.Color]::White } else { $script:Theme.Text })
        )
        $nameRect = New-Object System.Drawing.RectangleF($e.Bounds.X + 10, $e.Bounds.Y + 5, $e.Bounds.Width - 20, 22)
        $e.Graphics.DrawString($profileName, $nameFont, $nameBrush, $nameRect)
        $nameFont.Dispose()
        $nameBrush.Dispose()

        # Draw description / date (secondary, smaller)
        $subText = if ($profileDesc) { $profileDesc } else { $profileDate }
        if ($subText) {
            $subFont = New-Object System.Drawing.Font("Segoe UI", 8)
            $subBrush = New-Object System.Drawing.SolidBrush(
                $(if ($isSelected) { [System.Drawing.Color]::FromArgb(200, 200, 200) } else { $script:Theme.TextSecondary })
            )
            $subRect = New-Object System.Drawing.RectangleF($e.Bounds.X + 10, $e.Bounds.Y + 28, $e.Bounds.Width - 20, 18)
            $e.Graphics.DrawString($subText, $subFont, $subBrush, $subRect)
            $subFont.Dispose()
            $subBrush.Dispose()
        }

        # Draw bottom separator
        $sepPen = New-Object System.Drawing.Pen($script:Theme.Border, 1)
        $e.Graphics.DrawLine($sepPen, $e.Bounds.X + 10, $e.Bounds.Bottom - 1,
            $e.Bounds.Right - 10, $e.Bounds.Bottom - 1)
        $sepPen.Dispose()
    })

    # Selection changed handler
    $profileListBox.Add_SelectedIndexChanged({
        if ($script:ProfileListBox.SelectedIndex -ge 0) {
            $selectedText = $script:ProfileListBox.SelectedItem.ToString()
            $profileName = ($selectedText -split '\|', 3)[0]
            $script:SelectedProfile = Get-Profile -Name $profileName
            Update-ProfileDetailPanel
        }
        else {
            $script:SelectedProfile = $null
            Update-ProfileDetailPanel
        }
    })

    $leftPanel.Controls.Add($profileListBox)

    # ---- Buttons below the list ----
    $buttonY = 395
    $buttonWidth = 100
    $buttonSpacing = 8

    $newProfileBtn = New-StyledButton -Text "New Profile" -X 12 -Y $buttonY `
        -Width $buttonWidth -Height 34 -IsPrimary -OnClick {
        $dialogResult = Show-NewProfileDialog
        if ($null -ne $dialogResult) {
            # Check if profile name already exists
            $existingProfile = Get-Profile -Name $dialogResult.Name
            if ($null -ne $existingProfile) {
                [System.Windows.Forms.MessageBox]::Show(
                    "A profile named '$($dialogResult.Name)' already exists. Please choose a different name.",
                    "Name Conflict",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return
            }

            $newProfile = New-DefaultProfile -Name $dialogResult.Name -Description $dialogResult.Description
            Save-Profile -Profile $newProfile
            Refresh-ProfileList
            Select-ProfileInList -Name $dialogResult.Name
        }
    }
    $newProfileBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor
        [System.Windows.Forms.AnchorStyles]::Left
    $leftPanel.Controls.Add($newProfileBtn)

    $importBtn = New-StyledButton -Text "Import" -X (12 + $buttonWidth + $buttonSpacing) `
        -Y $buttonY -Width 80 -Height 34 -OnClick {
        $importedProfile = Import-ProfileFromFile
        if ($null -ne $importedProfile) {
            Refresh-ProfileList
            Select-ProfileInList -Name $importedProfile.Name
        }
    }
    $importBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor
        [System.Windows.Forms.AnchorStyles]::Left
    $leftPanel.Controls.Add($importBtn)

    $captureBtn = New-StyledButton -Text "Capture Current" `
        -X (12 + $buttonWidth + $buttonSpacing + 80 + $buttonSpacing) `
        -Y $buttonY -Width 120 -Height 34 -OnClick {
        try {
            $capturedProfile = Get-CurrentSystemProfile
            Save-Profile -Profile $capturedProfile
            Refresh-ProfileList
            Select-ProfileInList -Name $capturedProfile.Name

            [System.Windows.Forms.MessageBox]::Show(
                "Current system configuration captured as profile:`n'$($capturedProfile.Name)'",
                "Capture Complete",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
        }
        catch {
            Write-AppLog "Failed to capture system profile: $_" -Level 'ERROR'
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to capture current system configuration:`n$_",
                "Capture Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    }
    $captureBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor
        [System.Windows.Forms.AnchorStyles]::Left
    $leftPanel.Controls.Add($captureBtn)

    # ---- Second row of buttons: Generate Rig, Export/Import Rig Bundle ----
    $buttonY2 = $buttonY + 42

    $generateRigBtn = New-StyledButton -Text "Generate Rig" -X 12 -Y $buttonY2 `
        -Width $buttonWidth -Height 34 -IsPrimary -OnClick {
        $generatedCount = Show-BatchProfileWizard
        if ($generatedCount -gt 0) {
            Refresh-ProfileList
        }
    }
    $generateRigBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor
        [System.Windows.Forms.AnchorStyles]::Left
    $leftPanel.Controls.Add($generateRigBtn)

    $exportBundleBtn = New-StyledButton -Text "Export Bundle" `
        -X (12 + $buttonWidth + $buttonSpacing) `
        -Y $buttonY2 -Width 100 -Height 34 -OnClick {
        Export-RigBundle
    }
    $exportBundleBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor
        [System.Windows.Forms.AnchorStyles]::Left
    $leftPanel.Controls.Add($exportBundleBtn)

    $importBundleBtn = New-StyledButton -Text "Import Bundle" `
        -X (12 + $buttonWidth + $buttonSpacing + 100 + $buttonSpacing) `
        -Y $buttonY2 -Width 100 -Height 34 -OnClick {
        $importResult = Import-RigBundle
        if ($importResult.ImportedCount -gt 0) {
            Refresh-ProfileList
        }
    }
    $importBundleBtn.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor
        [System.Windows.Forms.AnchorStyles]::Left
    $leftPanel.Controls.Add($importBundleBtn)

    $scrollPanel.Controls.Add($leftPanel)

    # ========================================================================
    # RIGHT COLUMN - Profile Detail View (~550px)
    # ========================================================================
    $rightColumnX = $leftColumnX + $leftColumnWidth + 20
    $rightColumnY = $leftColumnY
    $rightColumnWidth = 550

    $detailPanel = New-StyledPanel -X $rightColumnX -Y $rightColumnY `
        -Width $rightColumnWidth -Height 545 -IsCard
    $detailPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor
        [System.Windows.Forms.AnchorStyles]::Left -bor
        [System.Windows.Forms.AnchorStyles]::Right -bor
        [System.Windows.Forms.AnchorStyles]::Bottom
    $detailPanel.AutoScroll = $true

    $script:DetailPanel = $detailPanel
    $scrollPanel.Controls.Add($detailPanel)

    # ---- Add the scroll panel to the content panel ----
    $ContentPanel.Controls.Add($scrollPanel)

    # ---- Initial load ----
    Refresh-ProfileList
    Show-EmptyDetailState

    $ContentPanel.ResumeLayout()
}


# ============================================================================
# UI HELPER FUNCTIONS - Profile List & Detail Panel Management
# ============================================================================

function Refresh-ProfileList {
    <#
    .SYNOPSIS
        Reloads the profile list from disk and updates the ListBox.
    #>
    if ($null -eq $script:ProfileListBox) { return }

    $script:ProfileListBox.Items.Clear()

    # Ensure profiles directory exists (first-run scenario)
    $profilesDir = Get-ProfilesDirectory

    $profiles = @()
    try {
        $profiles = @(Get-AllProfiles)
    }
    catch {
        Write-AppLog "Failed to load profiles during refresh: $_" -Level 'ERROR'
        $profiles = @()
    }

    if ($null -eq $profiles) { $profiles = @() }

    foreach ($p in $profiles) {
        if ($null -eq $p) { continue }

        # Format: Name|Description|ModifiedDate (pipe-delimited for custom drawing)
        $pName = if ($p.PSObject.Properties['Name'] -and $p.Name) { $p.Name } else { "(Unnamed)" }
        $pDesc = if ($p.PSObject.Properties['Description']) { "$($p.Description)" } else { "" }
        $modifiedStr = ""
        if ($p.PSObject.Properties['Modified'] -and $p.Modified) {
            try {
                $modifiedDate = [DateTime]::Parse($p.Modified)
                $modifiedStr = "Modified: $($modifiedDate.ToString('yyyy-MM-dd HH:mm'))"
            }
            catch {
                $modifiedStr = "Modified: $($p.Modified)"
            }
        }

        $displayText = $pName + '|' + $pDesc + '|' + $modifiedStr
        $script:ProfileListBox.Items.Add($displayText) | Out-Null
    }

    # Update the count label
    $count = $profiles.Count
    $plural = if ($count -ne 1) { 's' } else { '' }
    $script:ProfileCountLabel.Text = "$count profile$plural saved"
}


function Select-ProfileInList {
    <#
    .SYNOPSIS
        Selects a profile in the ListBox by name.
    .PARAMETER Name
        The profile name to select.
    #>
    param([string]$Name)

    if ($null -eq $script:ProfileListBox) { return }
    if ([string]::IsNullOrWhiteSpace($Name)) { return }

    for ($i = 0; $i -lt $script:ProfileListBox.Items.Count; $i++) {
        $item = $script:ProfileListBox.Items[$i]
        if ($null -eq $item) { continue }
        $itemText = $item.ToString()
        $itemName = ($itemText -split '\|', 3)[0]
        if ($itemName -eq $Name) {
            $script:ProfileListBox.SelectedIndex = $i
            return
        }
    }
}


function Show-EmptyDetailState {
    <#
    .SYNOPSIS
        Shows a placeholder message when no profile is selected.
    #>
    if ($null -eq $script:DetailPanel) { return }

    $script:DetailPanel.SuspendLayout()
    $script:DetailPanel.Controls.Clear()

    $emptyLabel = New-StyledLabel -Text "Select a profile from the list to view details," `
        -X 30 -Y 180 -IsMuted -FontSize 11
    $script:DetailPanel.Controls.Add($emptyLabel)

    $emptyLabel2 = New-StyledLabel -Text "or create a new profile to get started." `
        -X 30 -Y 210 -IsMuted -FontSize 11
    $script:DetailPanel.Controls.Add($emptyLabel2)

    $script:DetailPanel.ResumeLayout()
}


function Update-ProfileDetailPanel {
    <#
    .SYNOPSIS
        Updates the right-column detail panel with the currently selected profile's data.
    .DESCRIPTION
        Populates editable fields (name, description), summary cards (server name,
        network adapters, SMB settings), and action buttons.
    #>
    if ($null -eq $script:DetailPanel) { return }

    $script:DetailPanel.SuspendLayout()
    $script:DetailPanel.Controls.Clear()

    if ($null -eq $script:SelectedProfile) {
        Show-EmptyDetailState
        $script:DetailPanel.ResumeLayout()
        return
    }

    $p = $script:SelectedProfile
    $panelWidth = $script:DetailPanel.Width
    $currentY = 12
    $innerWidth = $panelWidth - 40

    # Safely read profile properties with null fallbacks
    $profileName = if ($p.PSObject.Properties['Name'] -and $p.Name) { $p.Name } else { "(Unnamed)" }
    $profileDesc = if ($p.PSObject.Properties['Description']) { "$($p.Description)" } else { "" }
    $profileServerName = if ($p.PSObject.Properties['ServerName'] -and $p.ServerName) { $p.ServerName } else { "(Not set)" }
    $profileCreated = if ($p.PSObject.Properties['Created']) { "$($p.Created)" } else { "" }
    $profileModified = if ($p.PSObject.Properties['Modified']) { "$($p.Modified)" } else { "" }
    $profileAdapters = if ($p.PSObject.Properties['NetworkAdapters'] -and $null -ne $p.NetworkAdapters) { @($p.NetworkAdapters) } else { @() }
    $profileSMB = if ($p.PSObject.Properties['SMBSettings'] -and $null -ne $p.SMBSettings) { $p.SMBSettings } else { $null }

    # ---- Profile Name (editable) ----
    $nameLabel = New-StyledLabel -Text "Profile Name" -X 15 -Y $currentY -FontSize 9 -IsSecondary
    $script:DetailPanel.Controls.Add($nameLabel)
    $currentY += 22

    $script:ProfileNameBox = New-StyledTextBox -X 15 -Y $currentY -Width $innerWidth -Height 30
    $script:ProfileNameBox.Text = $profileName
    $script:ProfileNameBox.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $script:DetailPanel.Controls.Add($script:ProfileNameBox)
    $currentY += 40

    # ---- Description (editable) ----
    $descLabel = New-StyledLabel -Text "Description" -X 15 -Y $currentY -FontSize 9 -IsSecondary
    $script:DetailPanel.Controls.Add($descLabel)
    $currentY += 22

    $script:ProfileDescBox = New-StyledTextBox -X 15 -Y $currentY -Width $innerWidth -Height 28
    $script:ProfileDescBox.Text = $profileDesc
    $script:DetailPanel.Controls.Add($script:ProfileDescBox)
    $currentY += 38

    # ---- Timestamps (read-only) ----
    $createdStr = ""
    $modifiedStr = ""
    if ($profileCreated) {
        try {
            $createdStr = ([DateTime]::Parse($profileCreated)).ToString('yyyy-MM-dd HH:mm')
        }
        catch { $createdStr = $profileCreated }
    }
    if ($profileModified) {
        try {
            $modifiedStr = ([DateTime]::Parse($profileModified)).ToString('yyyy-MM-dd HH:mm')
        }
        catch { $modifiedStr = $profileModified }
    }

    $timestampLabel = New-StyledLabel -Text "Created: $createdStr  |  Modified: $modifiedStr" `
        -X 15 -Y $currentY -IsMuted -FontSize 8
    $script:DetailPanel.Controls.Add($timestampLabel)
    $currentY += 25

    # ---- Server Name Card ----
    $serverCard = New-StyledCard -Title "Server Name" -X 15 -Y $currentY `
        -Width $innerWidth -Height 70
    $serverValueLabel = New-StyledLabel -Text $profileServerName -X 12 -Y 42 -FontSize 11 -IsBold
    $serverCard.Controls.Add($serverValueLabel)
    $script:DetailPanel.Controls.Add($serverCard)
    $currentY += 80

    # ---- Network Adapters Summary Card ----
    $adapterCount = $profileAdapters.Count
    $adapterCardHeight = 50 + ($adapterCount * 24)

    $adapterCard = New-StyledCard -Title "Network Adapters ($adapterCount)" -X 15 -Y $currentY `
        -Width $innerWidth -Height $adapterCardHeight

    $adapterY = 42
    foreach ($adapter in $profileAdapters) {
        if ($null -eq $adapter) { continue }

        $adIndex = if ($adapter.PSObject.Properties['Index']) { $adapter.Index } else { "?" }
        $adRole = if ($adapter.PSObject.Properties['Role']) { $adapter.Role } else { "Unknown" }
        $adDisplayName = if ($adapter.PSObject.Properties['DisplayName']) { $adapter.DisplayName } else { $adRole }
        $adIPAddress = if ($adapter.PSObject.Properties['IPAddress']) { $adapter.IPAddress } else { "" }
        $adDHCP = if ($adapter.PSObject.Properties['DHCP']) { $adapter.DHCP } else { $false }
        $adEnabled = if ($adapter.PSObject.Properties['Enabled']) { $adapter.Enabled } else { $true }

        $roleText = "[$adIndex] $adRole"
        $ipText = if ($adDHCP) { "DHCP" }
                  elseif ($adIPAddress) { $adIPAddress }
                  else { "Not configured" }

        $statusColor = if (-not $adEnabled) { $script:Theme.TextMuted }
                       elseif ($adDHCP) { $script:Theme.Accent }
                       elseif ($adIPAddress) { $script:Theme.Success }
                       else { $script:Theme.Warning }

        # Role label (left-aligned)
        $roleLabel = New-Object System.Windows.Forms.Label
        $roleLabel.Text = $roleText
        $roleLabel.Location = New-Object System.Drawing.Point(12, $adapterY)
        $roleLabel.Size = New-Object System.Drawing.Size(160, 20)
        $roleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $roleLabel.ForeColor = $script:Theme.Text
        $roleLabel.BackColor = [System.Drawing.Color]::Transparent
        $adapterCard.Controls.Add($roleLabel)

        # Display name label (center)
        $displayLabel = New-Object System.Windows.Forms.Label
        $displayLabel.Text = $adDisplayName
        $displayLabel.Location = New-Object System.Drawing.Point(175, $adapterY)
        $displayLabel.Size = New-Object System.Drawing.Size(180, 20)
        $displayLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
        $displayLabel.ForeColor = $script:Theme.TextSecondary
        $displayLabel.BackColor = [System.Drawing.Color]::Transparent
        $adapterCard.Controls.Add($displayLabel)

        # IP / status label (right-aligned)
        $ipLabel = New-Object System.Windows.Forms.Label
        $ipLabel.Text = if (-not $adEnabled) { "Disabled" } else { $ipText }
        $ipLabel.Location = New-Object System.Drawing.Point(360, $adapterY)
        $ipLabel.Size = New-Object System.Drawing.Size(150, 20)
        $ipLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $ipLabel.ForeColor = $statusColor
        $ipLabel.BackColor = [System.Drawing.Color]::Transparent
        $ipLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
        $adapterCard.Controls.Add($ipLabel)

        $adapterY += 24
    }

    $script:DetailPanel.Controls.Add($adapterCard)
    $currentY += ($adapterCardHeight + 10)

    # ---- SMB Settings Summary Card ----
    $smbCard = New-StyledCard -Title "SMB Sharing" -X 15 -Y $currentY `
        -Width $innerWidth -Height 105

    $smbShareEnabled = $false
    if ($null -ne $profileSMB -and $profileSMB.PSObject.Properties['ShareD3Projects']) {
        $smbShareEnabled = $profileSMB.ShareD3Projects
    }

    $smbStatus = if ($smbShareEnabled) { "Enabled" } else { "Disabled" }
    $smbStatusType = if ($smbShareEnabled) { "Success" } else { "Warning" }
    $smbBadge = New-StatusBadge -Text $smbStatus -X 12 -Y 42 -Type $smbStatusType
    $smbCard.Controls.Add($smbBadge)

    if ($smbShareEnabled -and $null -ne $profileSMB) {
        $smbShareName = if ($profileSMB.PSObject.Properties['ShareName']) { $profileSMB.ShareName } else { "(Unknown)" }
        $smbProjectsPath = if ($profileSMB.PSObject.Properties['ProjectsPath']) { $profileSMB.ProjectsPath } else { "(Unknown)" }
        $smbPermissions = if ($profileSMB.PSObject.Properties['SharePermissions']) { $profileSMB.SharePermissions } else { "(Unknown)" }

        $shareInfoLabel = New-StyledLabel -Text "Share: $smbShareName  |  Path: $smbProjectsPath" `
            -X 100 -Y 43 -IsSecondary -FontSize 9
        $smbCard.Controls.Add($shareInfoLabel)

        $permLabel = New-StyledLabel -Text "Permissions: $smbPermissions" `
            -X 12 -Y 68 -IsMuted -FontSize 8
        $smbCard.Controls.Add($permLabel)
    }

    $script:DetailPanel.Controls.Add($smbCard)
    $currentY += 95

    # ---- Save Changes Button ----
    $saveBtn = New-StyledButton -Text "Save Changes" -X 15 -Y $currentY `
        -Width 120 -Height 36 -IsPrimary -OnClick {
        if ($null -eq $script:SelectedProfile) { return }

        $oldName = $script:SelectedProfile.Name
        $newName = $script:ProfileNameBox.Text.Trim()
        $newDesc = $script:ProfileDescBox.Text.Trim()

        if ([string]::IsNullOrWhiteSpace($newName)) {
            [System.Windows.Forms.MessageBox]::Show(
                "Profile name cannot be empty.",
                "Validation Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }

        # If the name changed, check for conflicts and remove the old file
        if ($newName -ne $oldName) {
            $existingProfile = Get-Profile -Name $newName
            if ($null -ne $existingProfile) {
                [System.Windows.Forms.MessageBox]::Show(
                    "A profile named '$newName' already exists.",
                    "Name Conflict",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
                return
            }
            # Remove the old profile file
            Remove-Profile -Name $oldName
        }

        $script:SelectedProfile.Name = $newName
        $script:SelectedProfile.Description = $newDesc

        try {
            Save-Profile -Profile $script:SelectedProfile
            Refresh-ProfileList
            Select-ProfileInList -Name $newName
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to save profile:`n$_",
                "Save Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    }
    $script:DetailPanel.Controls.Add($saveBtn)

    # ---- Action Buttons Row ----
    $actionY = $currentY + 46
    $actionX = 15

    # "Apply to This Machine" button -- visually distinct from remote deploy buttons
    $applyBtn = New-StyledButton -Text "Apply to This Machine" -X $actionX -Y $actionY `
        -Width 160 -Height 36 -IsPrimary -OnClick {
        if ($null -eq $script:SelectedProfile) { return }
        Apply-FullProfile -Profile $script:SelectedProfile
    }
    # Amber border to signal local-machine scope
    $applyBtn.FlatAppearance.BorderColor = $script:Theme.Warning
    $applyBtn.FlatAppearance.BorderSize  = 2
    $script:DetailPanel.Controls.Add($applyBtn)

    # Warning label below the apply button explaining scope
    $applyWarningLabel = New-Object System.Windows.Forms.Label
    $applyWarningLabel.Text = "This will modify this computer's network, hostname, and shares."
    $applyWarningLabel.Location = New-Object System.Drawing.Point($actionX, ($actionY + 40))
    $applyWarningLabel.Size = New-Object System.Drawing.Size(($innerWidth - $actionX), 18)
    $applyWarningLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
    $applyWarningLabel.ForeColor = $script:Theme.Warning
    $applyWarningLabel.BackColor = [System.Drawing.Color]::Transparent
    $script:DetailPanel.Controls.Add($applyWarningLabel)

    $actionX += 170

    $editBtn = New-StyledButton -Text "Edit Full Profile" -X $actionX -Y $actionY `
        -Width 130 -Height 36 -OnClick {
        if ($null -eq $script:SelectedProfile) { return }

        $editResult = Show-EditFullProfileDialog -Profile $script:SelectedProfile
        if ($editResult) {
            try {
                Save-Profile -Profile $script:SelectedProfile
                Refresh-ProfileList
                Select-ProfileInList -Name $script:SelectedProfile.Name
                Update-ProfileDetailPanel
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to save profile changes:`n$_",
                    "Save Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                ) | Out-Null
            }
        }
    }
    $script:DetailPanel.Controls.Add($editBtn)
    $actionX += 140

    $exportBtn = New-StyledButton -Text "Export" -X $actionX -Y $actionY `
        -Width 80 -Height 36 -OnClick {
        if ($null -eq $script:SelectedProfile) { return }
        Export-ProfileToFile -Profile $script:SelectedProfile
    }
    $script:DetailPanel.Controls.Add($exportBtn)
    $actionX += 90

    $deleteBtn = New-StyledButton -Text "Delete" -X $actionX -Y $actionY `
        -Width 80 -Height 36 -IsDestructive -OnClick {
        if ($null -eq $script:SelectedProfile) { return }

        $confirmResult = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to permanently delete the profile '$($script:SelectedProfile.Name)'?`n`nThis action cannot be undone.",
            "Confirm Delete",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )

        if ($confirmResult -eq [System.Windows.Forms.DialogResult]::Yes) {
            try {
                Remove-Profile -Name $script:SelectedProfile.Name
                $script:SelectedProfile = $null
                Refresh-ProfileList
                Show-EmptyDetailState
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to delete profile:`n$_",
                    "Delete Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                ) | Out-Null
            }
        }
    }
    $script:DetailPanel.Controls.Add($deleteBtn)

    $script:DetailPanel.ResumeLayout()
}
