# ============================================================================
# NetworkConfig.ps1 - DISGUISE BUDDY Network Adapter Configuration Module
# ============================================================================
# Provides backend functions for querying/configuring Windows network adapters
# and a WinForms UI view for managing 6 adapter roles used by disguise (d3)
# media servers.
#
# Adapter role indices (by convention):
#   0 = d3Net        - Core disguise server-to-server communication
#   1 = Media        - High-bandwidth media/content transfer
#   2 = sACN/Art-Net - Lighting control DMX over Ethernet
#   3 = NDI          - NDI video networking
#   4 = Control      - OSC/Automation/PSN show control
#   5 = Internet     - Updates, remote access, management
#
# Prerequisites: Theme.ps1 and UIComponents.ps1 must be dot-sourced before
# this file so that $script:Theme and New-Styled* functions are available.
# ============================================================================

# ---------------------------------------------------------------------------
# Module-scoped state
# ---------------------------------------------------------------------------

# Detected physical adapters cache (populated by Detect Adapters button)
$script:DetectedAdapters = @()

# Canonical adapter roles for disguise servers
$script:StandardAdapterRoles = @('d3Net', 'sACN', 'Media', 'NDI', 'Control', 'Internet')

# Adapter role definitions with display metadata
$script:AdapterRoles = @(
    @{
        Index      = 0
        RoleName   = 'd3 Network'
        ShortName  = 'd3Net'
        Color      = '#7C3AED'   # Purple
        DefaultIP  = '192.168.10.11'
        DefaultSub = '255.255.255.0'
        DefaultGW  = ''
        DefaultDNS1 = ''
        DefaultDNS2 = ''
        DefaultDHCP = $false
    }
    @{
        Index      = 1
        RoleName   = 'sACN / Art-Net'
        ShortName  = 'sACN'
        Color      = '#F59E0B'   # Amber
        DefaultIP  = ''
        DefaultSub = ''
        DefaultGW  = ''
        DefaultDNS1 = ''
        DefaultDNS2 = ''
        DefaultDHCP = $true
    }
    @{
        Index      = 2
        RoleName   = 'Media'
        ShortName  = 'Media'
        Color      = '#06B6D4'   # Cyan
        DefaultIP  = '192.168.20.11'
        DefaultSub = '255.255.255.0'
        DefaultGW  = ''
        DefaultDNS1 = ''
        DefaultDNS2 = ''
        DefaultDHCP = $false
    }
    @{
        Index      = 3
        RoleName   = 'NDI'
        ShortName  = 'NDI'
        Color      = '#10B981'   # Green
        DefaultIP  = ''
        DefaultSub = ''
        DefaultGW  = ''
        DefaultDNS1 = ''
        DefaultDNS2 = ''
        DefaultDHCP = $true
    }
    @{
        Index      = 4
        RoleName   = 'Control'
        ShortName  = 'Control'
        Color      = '#3B82F6'   # Blue
        DefaultIP  = ''
        DefaultSub = ''
        DefaultGW  = ''
        DefaultDNS1 = ''
        DefaultDNS2 = ''
        DefaultDHCP = $true
    }
    @{
        Index      = 5
        RoleName   = 'Internet'
        ShortName  = 'Internet'
        Color      = '#64748B'   # Gray
        DefaultIP  = ''
        DefaultSub = ''
        DefaultGW  = ''
        DefaultDNS1 = ''
        DefaultDNS2 = ''
        DefaultDHCP = $true
    }
)

# Stores references to card UI controls so we can read/write values later.
# Each entry is a hashtable keyed by role index with sub-keys for each control.
$script:CardControls = @{}

# ============================================================================
# BACKEND FUNCTIONS
# ============================================================================

function Test-IPAddressFormat {
    <#
    .SYNOPSIS
        Validates whether a string is a well-formed IPv4 address.
    .DESCRIPTION
        Checks format (4 dotted-decimal octets, each 0-255, no leading zeros)
        and optionally rejects reserved/invalid ranges:
          - 0.x.x.x (current network, invalid as host address)
          - 255.255.255.255 (limited broadcast)
          - 127.x.x.x (loopback - warned but allowed when -AllowReserved is set)
        Use -AllowReserved to permit loopback addresses for testing scenarios.
    .PARAMETER IP
        The string to validate.
    .PARAMETER AllowReserved
        When set, loopback (127.x.x.x) addresses produce a warning but return $true.
        Without this switch, loopback addresses return $false.
    .OUTPUTS
        [bool] $true if the string is a valid IPv4 address, $false otherwise.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$IP,

        [switch]$AllowReserved
    )

    if ([string]::IsNullOrWhiteSpace($IP)) { return $false }

    # Use the .NET parser and ensure it round-trips as IPv4
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($IP.Trim(), [ref]$parsed)) {
        # Ensure the address is IPv4 and the string representation matches
        # (rejects shorthand like "10.1" that .NET expands to "10.0.0.1")
        if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $octets = $IP.Trim().Split('.')
            if ($octets.Count -eq 4) {
                foreach ($octet in $octets) {
                    # Reject leading zeros (e.g., "010") and non-numeric
                    if ($octet -notmatch '^\d{1,3}$') { return $false }
                    $val = [int]$octet
                    if ($val -lt 0 -or $val -gt 255) { return $false }
                    # Reject leading zeros (e.g., "01", "001")
                    if ($octet.Length -gt 1 -and $octet.StartsWith('0')) { return $false }
                }

                # --- Reserved / invalid range checks ---
                $firstOctet = [int]$octets[0]

                # Reject 0.x.x.x (current network / invalid as host)
                if ($firstOctet -eq 0) {
                    return $false
                }

                # Reject 255.255.255.255 (limited broadcast)
                if ($IP.Trim() -eq '255.255.255.255') {
                    return $false
                }

                # Loopback range 127.x.x.x
                if ($firstOctet -eq 127) {
                    if ($AllowReserved) {
                        Write-Warning "IP address '$IP' is in the loopback range (127.x.x.x). Allowed for testing."
                        return $true
                    }
                    return $false
                }

                return $true
            }
        }
    }
    return $false
}

function Test-SubnetMaskFormat {
    <#
    .SYNOPSIS
        Validates whether a string is a valid dotted-decimal subnet mask.
    .DESCRIPTION
        Checks that the mask is a well-formed IPv4 address AND that the binary
        representation is contiguous (a run of 1-bits followed by 0-bits only).
        Invalid / non-contiguous masks like 255.255.128.255 are rejected.
        Uses its own octet parsing rather than Test-IPAddressFormat to avoid
        the reserved-range checks that would reject valid mask octets.
    .PARAMETER Mask
        The subnet mask string (e.g., "255.255.255.0").
    .OUTPUTS
        [bool]
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mask
    )

    if ([string]::IsNullOrWhiteSpace($Mask)) { return $false }

    # Parse as dotted-decimal: must be exactly 4 numeric octets 0-255
    $octets = $Mask.Trim().Split('.')
    if ($octets.Count -ne 4) { return $false }

    foreach ($octet in $octets) {
        if ($octet -notmatch '^\d{1,3}$') { return $false }
        $val = [int]$octet
        if ($val -lt 0 -or $val -gt 255) { return $false }
        # Reject leading zeros (e.g., "01", "001")
        if ($octet.Length -gt 1 -and $octet.StartsWith('0')) { return $false }
    }

    # Build full 32-bit binary string and verify contiguity
    $binary = ''
    foreach ($octet in $octets) {
        $binary += [Convert]::ToString([int]$octet, 2).PadLeft(8, '0')
    }

    # A valid subnet mask in binary is a contiguous run of 1s followed by 0s.
    # Reject all-zeros (0.0.0.0) as it is not a usable subnet mask.
    if ($binary -eq '00000000000000000000000000000000') { return $false }

    # The regex ensures no '1' appears after the first '0' -- i.e., contiguous.
    return ($binary -match '^1+0*$')
}

function Convert-SubnetMaskToPrefix {
    <#
    .SYNOPSIS
        Converts a dotted-decimal subnet mask to a CIDR prefix length.
    .PARAMETER SubnetMask
        The subnet mask string (e.g., "255.255.255.0").
    .OUTPUTS
        [int] The prefix length (e.g., 24).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubnetMask
    )

    if (-not (Test-SubnetMaskFormat -Mask $SubnetMask)) {
        Write-Warning "Invalid subnet mask: $SubnetMask"
        return -1
    }

    $octets = $SubnetMask.Trim().Split('.')
    $binary = ''
    foreach ($octet in $octets) {
        $binary += [Convert]::ToString([int]$octet, 2).PadLeft(8, '0')
    }

    # Count the number of leading 1-bits
    return ($binary.ToCharArray() | Where-Object { $_ -eq '1' }).Count
}

function Convert-PrefixToSubnetMask {
    <#
    .SYNOPSIS
        Converts a CIDR prefix length to a dotted-decimal subnet mask.
    .PARAMETER PrefixLength
        The prefix length (0-32).
    .OUTPUTS
        [string] The dotted-decimal subnet mask (e.g., "255.255.255.0").
    #>
    param(
        [Parameter(Mandatory = $true)]
        [int]$PrefixLength
    )

    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) {
        Write-Warning "Prefix length must be between 0 and 32. Got: $PrefixLength"
        return '0.0.0.0'
    }

    $binary = ('1' * $PrefixLength).PadRight(32, '0')
    $octets = @()
    for ($i = 0; $i -lt 4; $i++) {
        $octets += [Convert]::ToInt32($binary.Substring($i * 8, 8), 2)
    }
    return ($octets -join '.')
}

function Get-SystemNetworkAdapters {
    <#
    .SYNOPSIS
        Returns all physical network adapters on the system.
    .DESCRIPTION
        Uses Get-NetAdapter (Windows only) to enumerate physical adapters,
        filtering out virtual/Hyper-V/VPN adapters. Returns an array of
        objects with adapter metadata.
    .OUTPUTS
        [array] Each element is a PSCustomObject with: Name, InterfaceIndex,
        MacAddress, Status, LinkSpeed.
    #>

    $adapters = @()

    try {
        # Get-NetAdapter is available on Windows 8+ / Server 2012+
        $raw = Get-NetAdapter -Physical -ErrorAction Stop |
            Where-Object {
                # Exclude common virtual adapter patterns
                $_.InterfaceDescription -notmatch 'Hyper-V|Virtual|VPN|Loopback|WAN Miniport|Bluetooth'
            } |
            Sort-Object -Property InterfaceIndex

        foreach ($nic in $raw) {
            $adapters += [PSCustomObject]@{
                Name           = $nic.Name
                InterfaceIndex = $nic.InterfaceIndex
                MacAddress     = $nic.MacAddress
                Status         = $nic.Status            # Up, Disconnected, etc.
                LinkSpeed      = $nic.LinkSpeed          # e.g., "1 Gbps"
                Description    = $nic.InterfaceDescription
            }
        }

        Write-AppLog -Message "Detected $($adapters.Count) physical network adapter(s)." -Level 'INFO'
    }
    catch {
        Write-AppLog -Message "Failed to enumerate network adapters: $($_.Exception.Message)" -Level 'ERROR'
        Write-Warning "Could not detect network adapters. Ensure you are running on Windows with administrator privileges."
    }

    return $adapters
}

function Get-AdapterIPConfiguration {
    <#
    .SYNOPSIS
        Gets the current IP configuration for a specific network adapter.
    .PARAMETER AdapterName
        The name of the adapter (as shown by Get-NetAdapter).
    .OUTPUTS
        [PSCustomObject] with IPAddress, SubnetPrefix, SubnetMask, Gateway,
        DNS, DHCPEnabled.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName
    )

    $result = [PSCustomObject]@{
        IPAddress    = ''
        SubnetPrefix = 0
        SubnetMask   = ''
        Gateway      = ''
        DNS          = @()
        DHCPEnabled  = $false
    }

    try {
        # Get the adapter object to retrieve InterfaceIndex
        $adapter = Get-NetAdapter -Name $AdapterName -ErrorAction Stop

        # Retrieve the IPv4 address(es); take the first non-link-local one
        $ipInfo = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex `
                                   -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Where-Object { $_.IPAddress -notlike '169.254.*' } |
                  Select-Object -First 1

        if ($ipInfo) {
            $result.IPAddress    = $ipInfo.IPAddress
            $result.SubnetPrefix = $ipInfo.PrefixLength
            $result.SubnetMask   = Convert-PrefixToSubnetMask -PrefixLength $ipInfo.PrefixLength
        }

        # Gateway
        $gwInfo = Get-NetIPConfiguration -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
        if ($gwInfo -and $gwInfo.IPv4DefaultGateway) {
            $result.Gateway = $gwInfo.IPv4DefaultGateway.NextHop
        }

        # DNS servers
        $dnsInfo = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex `
                                               -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($dnsInfo -and $dnsInfo.ServerAddresses) {
            $result.DNS = $dnsInfo.ServerAddresses
        }

        # DHCP enabled?
        $dhcpInfo = Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex `
                                        -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($dhcpInfo) {
            $result.DHCPEnabled = ($dhcpInfo.Dhcp -eq 'Enabled')
        }

        Write-AppLog -Message "Retrieved IP config for adapter '$AdapterName': $($result.IPAddress)/$($result.SubnetPrefix)" -Level 'INFO'
    }
    catch {
        Write-AppLog -Message "Failed to get IP config for '$AdapterName': $($_.Exception.Message)" -Level 'ERROR'
    }

    return $result
}

function Set-AdapterStaticIP {
    <#
    .SYNOPSIS
        Configures a static IPv4 address on a network adapter.
    .DESCRIPTION
        Removes existing IPv4 addresses, sets a new static IP, optional
        gateway, and optional DNS servers.
    .PARAMETER AdapterName
        The adapter name.
    .PARAMETER IPAddress
        The IPv4 address to assign.
    .PARAMETER SubnetMask
        The subnet mask in dotted-decimal notation.
    .PARAMETER Gateway
        Optional default gateway.
    .PARAMETER DNS1
        Optional primary DNS server.
    .PARAMETER DNS2
        Optional secondary DNS server.
    .OUTPUTS
        [PSCustomObject] with Success ([bool]) and Message ([string]).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName,

        [Parameter(Mandatory = $true)]
        [string]$IPAddress,

        [Parameter(Mandatory = $true)]
        [string]$SubnetMask,

        [string]$Gateway = '',
        [string]$DNS1 = '',
        [string]$DNS2 = ''
    )

    # --- Validate inputs ----
    if (-not (Test-IPAddressFormat -IP $IPAddress)) {
        return [PSCustomObject]@{ Success = $false; Message = "Invalid IP address: $IPAddress" }
    }
    if (-not (Test-SubnetMaskFormat -Mask $SubnetMask)) {
        return [PSCustomObject]@{ Success = $false; Message = "Invalid subnet mask: $SubnetMask" }
    }
    if ($Gateway -and -not (Test-IPAddressFormat -IP $Gateway)) {
        return [PSCustomObject]@{ Success = $false; Message = "Invalid gateway: $Gateway" }
    }
    if ($DNS1 -and -not (Test-IPAddressFormat -IP $DNS1)) {
        return [PSCustomObject]@{ Success = $false; Message = "Invalid DNS 1: $DNS1" }
    }
    if ($DNS2 -and -not (Test-IPAddressFormat -IP $DNS2)) {
        return [PSCustomObject]@{ Success = $false; Message = "Invalid DNS 2: $DNS2" }
    }

    $prefix = Convert-SubnetMaskToPrefix -SubnetMask $SubnetMask
    if ($prefix -lt 0) {
        return [PSCustomObject]@{ Success = $false; Message = "Could not convert subnet mask to prefix length." }
    }

    try {
        $adapter = Get-NetAdapter -Name $AdapterName -ErrorAction Stop

        # Disable DHCP first so we can assign a static address
        Set-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex `
                           -AddressFamily IPv4 -Dhcp Disabled -ErrorAction SilentlyContinue

        # Remove existing IPv4 addresses on this adapter
        Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

        # Remove existing gateway routes for this adapter
        Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        # Assign new IP address (with or without gateway)
        $ipParams = @{
            InterfaceIndex = $adapter.InterfaceIndex
            IPAddress      = $IPAddress
            PrefixLength   = $prefix
            AddressFamily  = 'IPv4'
            ErrorAction    = 'Stop'
        }

        if ($Gateway) {
            $ipParams['DefaultGateway'] = $Gateway
        }

        New-NetIPAddress @ipParams | Out-Null

        # Configure DNS servers
        $dnsServers = @()
        if ($DNS1) { $dnsServers += $DNS1 }
        if ($DNS2) { $dnsServers += $DNS2 }

        if ($dnsServers.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex `
                                       -ServerAddresses $dnsServers -ErrorAction Stop
        } else {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex `
                                       -ResetServerAddresses -ErrorAction SilentlyContinue
        }

        $msg = "Successfully set $AdapterName to $IPAddress/$prefix"
        if ($Gateway) { $msg += " gw $Gateway" }
        Write-AppLog -Message $msg -Level 'INFO'
        return [PSCustomObject]@{ Success = $true; Message = $msg }
    }
    catch {
        $errMsg = "Failed to set static IP on '$AdapterName': $($_.Exception.Message)"
        Write-AppLog -Message $errMsg -Level 'ERROR'
        return [PSCustomObject]@{ Success = $false; Message = $errMsg }
    }
}

function Set-AdapterDHCP {
    <#
    .SYNOPSIS
        Configures a network adapter to obtain its IP address via DHCP.
    .PARAMETER AdapterName
        The adapter name.
    .OUTPUTS
        [PSCustomObject] with Success ([bool]) and Message ([string]).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdapterName
    )

    try {
        $adapter = Get-NetAdapter -Name $AdapterName -ErrorAction Stop

        # Remove existing static addresses so DHCP can take over cleanly
        Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

        # Remove static gateway routes
        Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        # Enable DHCP
        Set-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex `
                           -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop

        # Reset DNS to automatic (DHCP-provided)
        Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex `
                                   -ResetServerAddresses -ErrorAction SilentlyContinue

        $msg = "Successfully set '$AdapterName' to DHCP."
        Write-AppLog -Message $msg -Level 'INFO'
        return [PSCustomObject]@{ Success = $true; Message = $msg }
    }
    catch {
        $errMsg = "Failed to enable DHCP on '$AdapterName': $($_.Exception.Message)"
        Write-AppLog -Message $errMsg -Level 'ERROR'
        return [PSCustomObject]@{ Success = $false; Message = $errMsg }
    }
}

function Rename-NetworkAdapter {
    <#
    .SYNOPSIS
        Renames a network adapter.
    .PARAMETER CurrentName
        The current adapter name.
    .PARAMETER NewName
        The desired new name.
    .OUTPUTS
        [PSCustomObject] with Success ([bool]) and Message ([string]).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentName,

        [Parameter(Mandatory = $true)]
        [string]$NewName
    )

    if ([string]::IsNullOrWhiteSpace($NewName)) {
        return [PSCustomObject]@{ Success = $false; Message = "New adapter name cannot be empty." }
    }

    try {
        Rename-NetAdapter -Name $CurrentName -NewName $NewName -ErrorAction Stop
        $msg = "Renamed adapter '$CurrentName' to '$NewName'."
        Write-AppLog -Message $msg -Level 'INFO'
        return [PSCustomObject]@{ Success = $true; Message = $msg }
    }
    catch {
        $errMsg = "Failed to rename '$CurrentName' to '$NewName': $($_.Exception.Message)"
        Write-AppLog -Message $errMsg -Level 'ERROR'
        return [PSCustomObject]@{ Success = $false; Message = $errMsg }
    }
}

# ============================================================================
# HELPER: Apply one adapter card's configuration
# ============================================================================

function Invoke-ApplyAdapterConfig {
    <#
    .SYNOPSIS
        Reads the controls for a given role index and applies the configuration.
    .PARAMETER RoleIndex
        The 0-based role index (0-5).
    .OUTPUTS
        [PSCustomObject] with Success and Message.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [int]$RoleIndex
    )

    $controls = $script:CardControls[$RoleIndex]
    if (-not $controls) {
        return [PSCustomObject]@{ Success = $false; Message = "No controls found for role index $RoleIndex." }
    }

    # Check if enabled
    if (-not $controls.EnabledCheckBox.Checked) {
        return [PSCustomObject]@{ Success = $true; Message = "Adapter role $RoleIndex is disabled; skipped." }
    }

    # Get the selected physical adapter name
    $adapterName = $controls.AdapterCombo.SelectedItem
    if ([string]::IsNullOrWhiteSpace($adapterName) -or $adapterName -eq '(none)') {
        return [PSCustomObject]@{ Success = $false; Message = "No physical adapter selected for '$($script:AdapterRoles[$RoleIndex].RoleName)'." }
    }

    # DHCP mode?
    if ($controls.DHCPCheckBox.Checked) {
        return Set-AdapterDHCP -AdapterName $adapterName
    }

    # Static IP mode - read values from textboxes (handle placeholder text)
    $ip   = $controls.IPTextBox.Text.Trim()
    $sub  = $controls.SubnetTextBox.Text.Trim()
    $gw   = $controls.GatewayTextBox.Text.Trim()
    $dns1 = $controls.DNS1TextBox.Text.Trim()
    $dns2 = $controls.DNS2TextBox.Text.Trim()

    # Clear placeholder sentinel values
    $placeholders = @('IP Address', 'Subnet Mask', 'Gateway', 'DNS 1', 'DNS 2',
                      'e.g. 10.0.0.10', 'e.g. 255.255.255.0', 'e.g. 10.0.0.1',
                      'e.g. 8.8.8.8', 'e.g. 8.8.4.4')
    if ($ip   -in $placeholders) { $ip   = '' }
    if ($sub  -in $placeholders) { $sub  = '' }
    if ($gw   -in $placeholders) { $gw   = '' }
    if ($dns1 -in $placeholders) { $dns1 = '' }
    if ($dns2 -in $placeholders) { $dns2 = '' }

    # Validate mandatory fields
    if ([string]::IsNullOrWhiteSpace($ip)) {
        return [PSCustomObject]@{ Success = $false; Message = "IP address is required for '$($script:AdapterRoles[$RoleIndex].RoleName)'." }
    }
    if ([string]::IsNullOrWhiteSpace($sub)) {
        return [PSCustomObject]@{ Success = $false; Message = "Subnet mask is required for '$($script:AdapterRoles[$RoleIndex].RoleName)'." }
    }

    return Set-AdapterStaticIP -AdapterName $adapterName `
                               -IPAddress $ip `
                               -SubnetMask $sub `
                               -Gateway $gw `
                               -DNS1 $dns1 `
                               -DNS2 $dns2
}

# ============================================================================
# UI VIEW FUNCTION
# ============================================================================

function New-NetworkView {
    <#
    .SYNOPSIS
        Builds the Network Adapter configuration view inside the given content panel.
    .PARAMETER ContentPanel
        The parent panel that this view populates (provided by the main application shell).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.Panel]$ContentPanel
    )

    $ContentPanel.Controls.Clear()
    $ContentPanel.SuspendLayout()

    # Reset control references
    $script:CardControls = @{}

    # -----------------------------------------------------------------------
    # Layout constants
    # -----------------------------------------------------------------------
    $padding        = 20          # Outer padding from content panel edges
    $cardWidth      = 430         # Width of each adapter card
    $cardHeight     = 295         # Height of each adapter card (compact but room for all fields)
    $cardGapX       = 20          # Horizontal gap between columns
    $cardGapY       = 15          # Vertical gap between rows
    $headerHeight   = 40          # Section header height
    $toolbarY       = 60          # Y position of toolbar
    $toolbarHeight  = 40          # Height of toolbar row
    $gridStartY     = 115         # Y start of the card grid
    $cols           = 2           # Number of columns
    $rows           = 3           # Number of rows

    # Calculate total width needed for the grid
    $gridTotalWidth  = ($cols * $cardWidth) + (($cols - 1) * $cardGapX) + ($padding * 2)
    $gridTotalHeight = $gridStartY + ($rows * $cardHeight) + (($rows - 1) * $cardGapY) + $padding

    # -----------------------------------------------------------------------
    # Scrollable wrapper to contain everything
    # -----------------------------------------------------------------------
    $scrollPanel = New-ScrollPanel -X 0 -Y 0 `
                                   -Width $ContentPanel.ClientSize.Width `
                                   -Height $ContentPanel.ClientSize.Height
    $scrollPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor `
                          [System.Windows.Forms.AnchorStyles]::Bottom -bor `
                          [System.Windows.Forms.AnchorStyles]::Left -bor `
                          [System.Windows.Forms.AnchorStyles]::Right

    # Resize the scroll panel when the content panel resizes
    $ContentPanel.Add_Resize({
        $scrollPanel = $this.Controls[0]
        if ($scrollPanel) {
            $scrollPanel.Size = $this.ClientSize
        }
    })

    # -----------------------------------------------------------------------
    # Section header
    # -----------------------------------------------------------------------
    $sectionHeader = New-SectionHeader -Text 'Network Adapters' `
                                       -X $padding -Y $padding `
                                       -Width ($gridTotalWidth - ($padding * 2))

    $scrollPanel.Controls.Add($sectionHeader)

    # Subtitle
    $subtitle = New-StyledLabel -Text 'Configure IP addresses for 6 network interfaces' `
                                -X ($padding + 2) -Y ($padding + 32) `
                                -FontSize 9 -IsSecondary
    $scrollPanel.Controls.Add($subtitle)

    # -----------------------------------------------------------------------
    # Toolbar row: Detect Adapters, Apply All Changes, Profile selector
    # -----------------------------------------------------------------------
    $btnDetect = New-StyledButton -Text 'Detect Adapters' `
                                  -X $padding -Y $toolbarY `
                                  -Width 140 -Height $toolbarHeight `
                                  -OnClick {
        # Populate adapters into all card combo boxes
        $script:DetectedAdapters = Get-SystemNetworkAdapters

        if ($script:DetectedAdapters.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "No physical network adapters were detected.`n`nEnsure you are running as Administrator on a Windows machine.",
                'DISGUISE BUDDY - Detection',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            return
        }

        # Build display list: "AdapterName (Status)"
        $adapterDisplayItems = @('(none)')
        foreach ($a in $script:DetectedAdapters) {
            $adapterDisplayItems += "$($a.Name)"
        }

        # Update each card's adapter combo
        foreach ($roleIdx in $script:CardControls.Keys) {
            $combo = $script:CardControls[$roleIdx].AdapterCombo
            $previousSelection = $combo.SelectedItem
            $combo.Items.Clear()
            foreach ($item in $adapterDisplayItems) {
                $combo.Items.Add($item) | Out-Null
            }

            # Try to auto-match: look for adapter whose name contains the role short name
            $roleName = $script:AdapterRoles[$roleIdx].ShortName
            $matched = $false

            # First try exact previous selection
            if ($previousSelection -and $combo.Items.Contains($previousSelection)) {
                $combo.SelectedItem = $previousSelection
                $matched = $true
            }

            # Then try name matching against role short name
            if (-not $matched) {
                foreach ($a in $script:DetectedAdapters) {
                    if ($a.Name -like "*$roleName*" -or $a.Name -like "*$($script:AdapterRoles[$roleIdx].RoleName)*") {
                        $combo.SelectedItem = $a.Name
                        $matched = $true
                        break
                    }
                }
            }

            # If no match, try by interface index position (adapter at physical slot = role index)
            if (-not $matched -and $roleIdx -lt $script:DetectedAdapters.Count) {
                $combo.SelectedItem = $script:DetectedAdapters[$roleIdx].Name
                $matched = $true
            }

            # Fallback: select "(none)"
            if (-not $matched) {
                $combo.SelectedIndex = 0
            }

            # Update status badge based on adapter status
            $statusBadge = $script:CardControls[$roleIdx].StatusBadge
            $selectedAdapterName = $combo.SelectedItem
            if ($selectedAdapterName -and $selectedAdapterName -ne '(none)') {
                $adapterObj = $script:DetectedAdapters | Where-Object { $_.Name -eq $selectedAdapterName }
                if ($adapterObj -and $adapterObj.Status -eq 'Up') {
                    $statusBadge.Tag = ' Connected '
                    $statusBadge.AccessibleDescription = "$([System.Drawing.Color]::FromArgb(16,185,129).ToArgb())|$([System.Drawing.Color]::White.ToArgb())"
                    $statusBadge.Invalidate()
                } else {
                    $statusBadge.Tag = ' Disconnected '
                    $statusBadge.AccessibleDescription = "$([System.Drawing.Color]::FromArgb(239,68,68).ToArgb())|$([System.Drawing.Color]::White.ToArgb())"
                    $statusBadge.Invalidate()
                }
            } else {
                $statusBadge.Tag = ' No Adapter '
                $statusBadge.AccessibleDescription = "$($script:Theme.TextMuted.ToArgb())|$([System.Drawing.Color]::White.ToArgb())"
                $statusBadge.Invalidate()
            }
        }

        # Also try to populate current IP config for each matched adapter
        foreach ($roleIdx in $script:CardControls.Keys) {
            $combo = $script:CardControls[$roleIdx].AdapterCombo
            $selectedAdapter = $combo.SelectedItem
            if ($selectedAdapter -and $selectedAdapter -ne '(none)') {
                try {
                    $ipConfig = Get-AdapterIPConfiguration -AdapterName $selectedAdapter
                    $controls = $script:CardControls[$roleIdx]

                    if ($ipConfig.DHCPEnabled) {
                        $controls.DHCPCheckBox.Checked = $true
                    } else {
                        $controls.DHCPCheckBox.Checked = $false
                        if ($ipConfig.IPAddress) {
                            $controls.IPTextBox.Text = $ipConfig.IPAddress
                            $controls.IPTextBox.ForeColor = $script:Theme.Text
                        }
                        if ($ipConfig.SubnetMask) {
                            $controls.SubnetTextBox.Text = $ipConfig.SubnetMask
                            $controls.SubnetTextBox.ForeColor = $script:Theme.Text
                        }
                        if ($ipConfig.Gateway) {
                            $controls.GatewayTextBox.Text = $ipConfig.Gateway
                            $controls.GatewayTextBox.ForeColor = $script:Theme.Text
                        }
                        if ($ipConfig.DNS -and $ipConfig.DNS.Count -ge 1) {
                            $controls.DNS1TextBox.Text = $ipConfig.DNS[0]
                            $controls.DNS1TextBox.ForeColor = $script:Theme.Text
                        }
                        if ($ipConfig.DNS -and $ipConfig.DNS.Count -ge 2) {
                            $controls.DNS2TextBox.Text = $ipConfig.DNS[1]
                            $controls.DNS2TextBox.ForeColor = $script:Theme.Text
                        }
                    }
                }
                catch {
                    # Silently continue if we can't read adapter config
                    Write-AppLog -Message "Could not read IP config for '$selectedAdapter': $($_.Exception.Message)" -Level 'WARN'
                }
            }
        }

        [System.Windows.Forms.MessageBox]::Show(
            "Detected $($script:DetectedAdapters.Count) physical adapter(s).`nAdapter dropdowns have been populated and auto-matched.",
            'DISGUISE BUDDY - Detection Complete',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    $scrollPanel.Controls.Add($btnDetect)

    $btnApplyAll = New-StyledButton -Text 'Apply All Changes' `
                                    -X ($padding + 155) -Y $toolbarY `
                                    -Width 150 -Height $toolbarHeight `
                                    -IsPrimary `
                                    -OnClick {
        # Confirmation dialog
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "This will apply network configuration to all enabled adapters.`n`nAre you sure you want to continue?",
            'DISGUISE BUDDY - Apply All',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        # Show "Applying..." state on the button
        $btn = $this
        $originalText = $btn.Text
        $btn.Text = 'Applying...'
        $btn.Enabled = $false
        $btn.BackColor = $script:Theme.TextMuted
        $btn.Refresh()

        $results = @()
        $successCount = 0
        $failCount = 0
        $skipCount = 0

        for ($i = 0; $i -lt 6; $i++) {
            $roleName = $script:AdapterRoles[$i].RoleName
            $result = Invoke-ApplyAdapterConfig -RoleIndex $i

            if ($result.Message -like '*skipped*' -or $result.Message -like '*disabled*') {
                $skipCount++
                $results += "  SKIP  $roleName : $($result.Message)"
            } elseif ($result.Success) {
                $successCount++
                $results += "  OK    $roleName : $($result.Message)"
            } else {
                $failCount++
                $results += "  FAIL  $roleName : $($result.Message)"
            }
        }

        # Show success/failure feedback on the button
        if ($failCount -gt 0) {
            $btn.Text = "$failCount Failed"
            $btn.BackColor = $script:Theme.Error
            $btn.ForeColor = [System.Drawing.Color]::White
        } else {
            $btn.Text = 'All Applied'
            $btn.BackColor = $script:Theme.Success
            $btn.ForeColor = [System.Drawing.Color]::White
        }
        $btn.Refresh()
        Start-Sleep -Milliseconds 800

        $summary = "Apply All Results:`n" +
                   "----------------------------`n" +
                   "  Success: $successCount`n" +
                   "  Failed:  $failCount`n" +
                   "  Skipped: $skipCount`n" +
                   "----------------------------`n`n" +
                   ($results -join "`n")

        $icon = if ($failCount -gt 0) {
            [System.Windows.Forms.MessageBoxIcon]::Warning
        } else {
            [System.Windows.Forms.MessageBoxIcon]::Information
        }

        [System.Windows.Forms.MessageBox]::Show(
            $summary,
            'DISGUISE BUDDY - Results',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            $icon
        )

        # Restore button to original state
        $btn.Text = $originalText
        $btn.Enabled = $true
        $btn.BackColor = $script:Theme.Primary
        $btn.ForeColor = [System.Drawing.Color]::White
    }
    $scrollPanel.Controls.Add($btnApplyAll)

    # Profile selector
    $profileLabel = New-StyledLabel -Text 'Profile:' `
                                    -X ($padding + 330) -Y ($toolbarY + 8) `
                                    -FontSize 9.5 -IsSecondary
    $scrollPanel.Controls.Add($profileLabel)

    # Scan for saved profiles in the profiles directory
    $profileItems = @('Default d3 Config')
    $profileDir = Join-Path (Get-AppRootPath) 'profiles'
    if (Test-Path $profileDir) {
        $profileFiles = Get-ChildItem -Path $profileDir -Filter '*.json' -ErrorAction SilentlyContinue
        foreach ($pf in $profileFiles) {
            $profileItems += $pf.BaseName
        }
    }

    $profileCombo = New-StyledComboBox -X ($padding + 395) -Y ($toolbarY + 5) `
                                       -Width 200 `
                                       -Items $profileItems
    $profileCombo.SelectedIndex = 0
    $scrollPanel.Controls.Add($profileCombo)

    # -----------------------------------------------------------------------
    # Build the 6 adapter cards (2 columns x 3 rows)
    # -----------------------------------------------------------------------
    for ($roleIdx = 0; $roleIdx -lt 6; $roleIdx++) {
        $role = $script:AdapterRoles[$roleIdx]

        # Grid position: column = roleIdx % 2, row = [Math]::Floor(roleIdx / 2)
        $col = $roleIdx % $cols
        $row = [Math]::Floor($roleIdx / $cols)

        $cardX = $padding + ($col * ($cardWidth + $cardGapX))
        $cardY = $gridStartY + ($row * ($cardHeight + $cardGapY))

        # --- Card panel ---
        $card = New-StyledPanel -X $cardX -Y $cardY -Width $cardWidth -Height $cardHeight -IsCard
        $card.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left

        # --- Colored accent bar on the left edge (4px wide, full height) ---
        $accentBar = New-Object System.Windows.Forms.Panel
        $accentBar.Location = New-Object System.Drawing.Point(0, 0)
        $accentBar.Size = New-Object System.Drawing.Size(4, $cardHeight)
        $accentBar.BackColor = [System.Drawing.ColorTranslator]::FromHtml($role.Color)
        $card.Controls.Add($accentBar)

        # ---- Title row: Role name + status badge ----
        $titleLabel = New-Object System.Windows.Forms.Label
        $titleLabel.Text = $role.RoleName
        $titleLabel.Location = New-Object System.Drawing.Point(14, 10)
        $titleLabel.AutoSize = $true
        $titleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
        $titleLabel.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($role.Color)
        $card.Controls.Add($titleLabel)

        $statusBadge = New-StatusBadge -Text ' No Adapter ' -X 320 -Y 12 -Type 'Info'
        $card.Controls.Add($statusBadge)

        # ---- Row tracking inside card (compact layout) ----
        $innerLeft   = 14         # Left margin for labels
        $inputLeft   = 110        # Left margin for inputs
        $inputWidth  = 180        # Width of text inputs
        $rowH        = 28         # Row height
        $currentY    = 38         # Start Y below title

        # ---- Physical Adapter dropdown ----
        $adapterLabel = New-StyledLabel -Text 'Adapter:' -X $innerLeft -Y ($currentY + 2) -FontSize 9 -IsSecondary
        $card.Controls.Add($adapterLabel)

        $adapterCombo = New-StyledComboBox -X $inputLeft -Y $currentY -Width ($inputWidth + 100) -Items @('(none)')
        $adapterCombo.SelectedIndex = 0

        # When adapter selection changes, update status badge
        $adapterCombo.Tag = $roleIdx
        $adapterCombo.Add_SelectedIndexChanged({
            $rIdx = $this.Tag
            $selectedName = $this.SelectedItem
            $badge = $script:CardControls[$rIdx].StatusBadge

            if ($selectedName -and $selectedName -ne '(none)') {
                $adapterObj = $script:DetectedAdapters | Where-Object { $_.Name -eq $selectedName }
                if ($adapterObj -and $adapterObj.Status -eq 'Up') {
                    $badge.Tag = ' Connected '
                    $badge.AccessibleDescription = "$([System.Drawing.Color]::FromArgb(16,185,129).ToArgb())|$([System.Drawing.Color]::White.ToArgb())"
                    $badge.Invalidate()
                } else {
                    $badge.Tag = ' Disconnected '
                    $badge.AccessibleDescription = "$([System.Drawing.Color]::FromArgb(239,68,68).ToArgb())|$([System.Drawing.Color]::White.ToArgb())"
                    $badge.Invalidate()
                }
            } else {
                $badge.Tag = ' No Adapter '
                $badge.AccessibleDescription = "$([System.Drawing.Color]::FromArgb(6,182,212).ToArgb())|$([System.Drawing.Color]::White.ToArgb())"
                $badge.Invalidate()
            }
        })
        $card.Controls.Add($adapterCombo)
        $currentY += $rowH + 4

        # ---- IP Address ----
        $ipLabel = New-StyledLabel -Text 'IP Address:' -X $innerLeft -Y ($currentY + 2) -FontSize 9 -IsSecondary
        $card.Controls.Add($ipLabel)

        $defaultIP = if ($role.DefaultIP) { $role.DefaultIP } else { '' }
        $ipTextBox = New-StyledTextBox -X $inputLeft -Y $currentY -Width $inputWidth -PlaceholderText $(
            if ($defaultIP) { $defaultIP } else { 'IP Address' }
        )
        $card.Controls.Add($ipTextBox)

        # Inline validation indicator for IP
        $ipValidLabel = New-Object System.Windows.Forms.Label
        $ipValidLabel.Location = New-Object System.Drawing.Point(($inputLeft + $inputWidth + 5), ($currentY + 4))
        $ipValidLabel.Size = New-Object System.Drawing.Size(20, 20)
        $ipValidLabel.Text = ''
        $ipValidLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        $card.Controls.Add($ipValidLabel)

        # Tooltip provider for validation feedback (shared per card)
        $ipToolTip = New-Object System.Windows.Forms.ToolTip
        $ipToolTip.InitialDelay = 200
        $ipToolTip.AutoPopDelay = 5000

        $ipTextBox.Add_TextChanged({
            $tb = $this
            $validLabel = $tb.Parent.Controls | Where-Object {
                $_.Location.X -eq ($tb.Location.X + $tb.Width + 5) -and
                $_.Location.Y -eq ($tb.Location.Y + 4) -and
                $_ -is [System.Windows.Forms.Label]
            } | Select-Object -First 1
            if ($validLabel) {
                $text = $tb.Text.Trim()
                if ([string]::IsNullOrWhiteSpace($text) -or $text -eq $tb.Tag) {
                    $validLabel.Text = ''
                    $tb.BackColor = $script:Theme.InputBackground
                } elseif (Test-IPAddressFormat -IP $text) {
                    $validLabel.Text = [char]0x2713   # checkmark
                    $validLabel.ForeColor = $script:Theme.Success
                    $tb.BackColor = $script:Theme.InputBackground
                } else {
                    $validLabel.Text = [char]0x2717   # X mark
                    $validLabel.ForeColor = $script:Theme.Error
                    # Tint background to indicate error
                    $tb.BackColor = [System.Drawing.Color]::FromArgb(40, 239, 68, 68)

                    # Determine specific error for tooltip
                    $errMsg = 'Invalid IP address format'
                    $octets = $text.Split('.')
                    if ($octets.Count -eq 4) {
                        $allNumeric = $true
                        foreach ($o in $octets) {
                            if ($o -notmatch '^\d{1,3}$') { $allNumeric = $false; break }
                        }
                        if ($allNumeric) {
                            $firstOctet = [int]$octets[0]
                            if ($firstOctet -eq 0) {
                                $errMsg = 'Addresses starting with 0 are reserved (current network)'
                            } elseif ($firstOctet -eq 127) {
                                $errMsg = 'Loopback range (127.x.x.x) is not allowed for adapters'
                            } elseif ($text -eq '255.255.255.255') {
                                $errMsg = 'Broadcast address is not a valid host address'
                            }
                        }
                    }
                    # Set tooltip on the validation label
                    $ttip = $validLabel.Parent.Controls | Where-Object { $_ -is [System.Windows.Forms.ToolTip] }
                    # Use Tag on label to pass tooltip text for hover
                    $validLabel.Tag = $errMsg
                }
            }
        })
        $currentY += $rowH + 2

        # ---- Subnet Mask ----
        $subLabel = New-StyledLabel -Text 'Subnet:' -X $innerLeft -Y ($currentY + 2) -FontSize 9 -IsSecondary
        $card.Controls.Add($subLabel)

        $defaultSub = if ($role.DefaultSub) { $role.DefaultSub } else { '' }
        $subTextBox = New-StyledTextBox -X $inputLeft -Y $currentY -Width $inputWidth -PlaceholderText $(
            if ($defaultSub) { $defaultSub } else { 'Subnet Mask' }
        )
        $card.Controls.Add($subTextBox)

        # Inline validation indicator for subnet
        $subValidLabel = New-Object System.Windows.Forms.Label
        $subValidLabel.Location = New-Object System.Drawing.Point(($inputLeft + $inputWidth + 5), ($currentY + 4))
        $subValidLabel.Size = New-Object System.Drawing.Size(20, 20)
        $subValidLabel.Text = ''
        $subValidLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        $card.Controls.Add($subValidLabel)

        $subTextBox.Add_TextChanged({
            $tb = $this
            $validLabel = $tb.Parent.Controls | Where-Object {
                $_.Location.X -eq ($tb.Location.X + $tb.Width + 5) -and
                $_.Location.Y -eq ($tb.Location.Y + 4) -and
                $_ -is [System.Windows.Forms.Label]
            } | Select-Object -First 1
            if ($validLabel) {
                $text = $tb.Text.Trim()
                if ([string]::IsNullOrWhiteSpace($text) -or $text -eq $tb.Tag) {
                    $validLabel.Text = ''
                    $tb.BackColor = $script:Theme.InputBackground
                } elseif (Test-SubnetMaskFormat -Mask $text) {
                    $validLabel.Text = [char]0x2713
                    $validLabel.ForeColor = $script:Theme.Success
                    $tb.BackColor = $script:Theme.InputBackground
                } else {
                    $validLabel.Text = [char]0x2717
                    $validLabel.ForeColor = $script:Theme.Error
                    # Tint background to indicate error
                    $tb.BackColor = [System.Drawing.Color]::FromArgb(40, 239, 68, 68)

                    # Determine specific error for tooltip
                    $errMsg = 'Invalid subnet mask format'
                    $octets = $text.Split('.')
                    if ($octets.Count -eq 4) {
                        $allNumeric = $true
                        foreach ($o in $octets) {
                            if ($o -notmatch '^\d{1,3}$') { $allNumeric = $false; break }
                        }
                        if ($allNumeric) {
                            # Check if all octets are valid but mask is non-contiguous
                            $allInRange = $true
                            foreach ($o in $octets) {
                                if ([int]$o -gt 255) { $allInRange = $false; break }
                            }
                            if ($allInRange) {
                                $bin = ''
                                foreach ($o in $octets) { $bin += [Convert]::ToString([int]$o, 2).PadLeft(8, '0') }
                                if ($bin -notmatch '^1+0*$') {
                                    $errMsg = 'Subnet mask is not contiguous (bits must be all 1s then all 0s)'
                                }
                            }
                        }
                    }
                    $validLabel.Tag = $errMsg
                }
            }
        })
        $currentY += $rowH + 2

        # ---- Gateway ----
        $gwLabel = New-StyledLabel -Text 'Gateway:' -X $innerLeft -Y ($currentY + 2) -FontSize 9 -IsSecondary
        $card.Controls.Add($gwLabel)

        $gwTextBox = New-StyledTextBox -X $inputLeft -Y $currentY -Width $inputWidth -PlaceholderText 'Gateway'
        $card.Controls.Add($gwTextBox)
        $currentY += $rowH + 2

        # ---- DNS 1 / DNS 2 on the same row ----
        $dns1Label = New-StyledLabel -Text 'DNS 1:' -X $innerLeft -Y ($currentY + 2) -FontSize 9 -IsSecondary
        $card.Controls.Add($dns1Label)

        $dns1TextBox = New-StyledTextBox -X $inputLeft -Y $currentY -Width 100 -PlaceholderText 'DNS 1'
        $card.Controls.Add($dns1TextBox)

        $dns2Label = New-StyledLabel -Text 'DNS 2:' -X ($inputLeft + 110) -Y ($currentY + 2) -FontSize 9 -IsSecondary
        $card.Controls.Add($dns2Label)

        $dns2TextBox = New-StyledTextBox -X ($inputLeft + 155) -Y $currentY -Width 100 -PlaceholderText 'DNS 2'
        $card.Controls.Add($dns2TextBox)
        $currentY += $rowH + 6

        # ---- DHCP checkbox ----
        $dhcpCheck = New-StyledCheckBox -Text 'DHCP' -X $innerLeft -Y $currentY
        $dhcpCheck.Checked = $role.DefaultDHCP

        # Store references to the fields we need to enable/disable
        # We use the Tag property of the checkbox to hold the role index
        $dhcpCheck.Tag = $roleIdx
        $dhcpCheck.Add_CheckedChanged({
            $rIdx = $this.Tag
            $controls = $script:CardControls[$rIdx]
            $disabled = $this.Checked

            $controls.IPTextBox.Enabled      = -not $disabled
            $controls.SubnetTextBox.Enabled   = -not $disabled
            $controls.GatewayTextBox.Enabled  = -not $disabled
            $controls.DNS1TextBox.Enabled     = -not $disabled
            $controls.DNS2TextBox.Enabled     = -not $disabled

            # Visual feedback: dim the text boxes when DHCP is on
            if ($disabled) {
                $controls.IPTextBox.BackColor     = $script:Theme.SurfaceLight
                $controls.SubnetTextBox.BackColor  = $script:Theme.SurfaceLight
                $controls.GatewayTextBox.BackColor = $script:Theme.SurfaceLight
                $controls.DNS1TextBox.BackColor    = $script:Theme.SurfaceLight
                $controls.DNS2TextBox.BackColor    = $script:Theme.SurfaceLight
            } else {
                $controls.IPTextBox.BackColor     = $script:Theme.InputBackground
                $controls.SubnetTextBox.BackColor  = $script:Theme.InputBackground
                $controls.GatewayTextBox.BackColor = $script:Theme.InputBackground
                $controls.DNS1TextBox.BackColor    = $script:Theme.InputBackground
                $controls.DNS2TextBox.BackColor    = $script:Theme.InputBackground
            }
        })
        $card.Controls.Add($dhcpCheck)

        # ---- Enabled checkbox ----
        $enabledCheck = New-StyledCheckBox -Text 'Enabled' -X ($innerLeft + 100) -Y $currentY
        $enabledCheck.Checked = $true
        $card.Controls.Add($enabledCheck)

        # ---- Apply button for this single card ----
        $applyBtn = New-StyledButton -Text 'Apply' `
                                     -X ($cardWidth - 90) -Y ($currentY - 2) `
                                     -Width 70 -Height 28 `
                                     -IsPrimary `
                                     -OnClick {
            # Determine which role this button belongs to by walking up to the card
            # and finding its index in $script:CardControls
            $btn = $this
            $parentCard = $btn.Parent
            $rIdx = -1
            foreach ($key in $script:CardControls.Keys) {
                if ($script:CardControls[$key].Card -eq $parentCard) {
                    $rIdx = $key
                    break
                }
            }

            if ($rIdx -lt 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    'Could not determine which adapter card this button belongs to.',
                    'Error',
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
                return
            }

            # Show "Applying..." state
            $originalText = $btn.Text
            $btn.Text = 'Applying...'
            $btn.Enabled = $false
            $btn.BackColor = $script:Theme.TextMuted
            $btn.Refresh()

            $roleName = $script:AdapterRoles[$rIdx].RoleName
            $result = Invoke-ApplyAdapterConfig -RoleIndex $rIdx

            if ($result.Success) {
                # Brief success feedback on the button itself
                $btn.Text = 'Done'
                $btn.BackColor = $script:Theme.Success
                $btn.ForeColor = [System.Drawing.Color]::White
                $btn.Refresh()
                Start-Sleep -Milliseconds 800

                [System.Windows.Forms.MessageBox]::Show(
                    $result.Message,
                    "DISGUISE BUDDY - $roleName",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            } else {
                # Brief failure feedback on the button itself
                $btn.Text = 'Failed'
                $btn.BackColor = $script:Theme.Error
                $btn.ForeColor = [System.Drawing.Color]::White
                $btn.Refresh()
                Start-Sleep -Milliseconds 800

                [System.Windows.Forms.MessageBox]::Show(
                    $result.Message,
                    "DISGUISE BUDDY - $roleName",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }

            # Restore button to original state
            $btn.Text = $originalText
            $btn.Enabled = $true
            $btn.BackColor = $script:Theme.Primary
            $btn.ForeColor = [System.Drawing.Color]::White
        }
        $card.Controls.Add($applyBtn)

        # ---------------------------------------------------------------
        # If DHCP is the default for this role, disable IP fields now
        # ---------------------------------------------------------------
        if ($role.DefaultDHCP) {
            $ipTextBox.Enabled     = $false
            $subTextBox.Enabled    = $false
            $gwTextBox.Enabled     = $false
            $dns1TextBox.Enabled   = $false
            $dns2TextBox.Enabled   = $false
            $ipTextBox.BackColor   = $script:Theme.SurfaceLight
            $subTextBox.BackColor  = $script:Theme.SurfaceLight
            $gwTextBox.BackColor   = $script:Theme.SurfaceLight
            $dns1TextBox.BackColor = $script:Theme.SurfaceLight
            $dns2TextBox.BackColor = $script:Theme.SurfaceLight
        }

        # ---------------------------------------------------------------
        # Store control references for this role
        # ---------------------------------------------------------------
        $script:CardControls[$roleIdx] = @{
            Card            = $card
            StatusBadge     = $statusBadge
            AdapterCombo    = $adapterCombo
            IPTextBox       = $ipTextBox
            SubnetTextBox   = $subTextBox
            GatewayTextBox  = $gwTextBox
            DNS1TextBox     = $dns1TextBox
            DNS2TextBox     = $dns2TextBox
            DHCPCheckBox    = $dhcpCheck
            EnabledCheckBox = $enabledCheck
            ApplyButton     = $applyBtn
        }

        # Add card to scroll panel
        $scrollPanel.Controls.Add($card)
    }

    # -----------------------------------------------------------------------
    # Add the scroll panel to the content panel
    # -----------------------------------------------------------------------
    $ContentPanel.Controls.Add($scrollPanel)
    $ContentPanel.ResumeLayout()
}
