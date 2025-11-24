<#
.SYNOPSIS
    Standalone IPsec Configuration Script for Windows Server 2016+
    
    Created for Contoso
 
.DESCRIPTION
    This script configures IPsec rules directly on the local server without
    requiring Active Directory or Group Policy. Settings are collected from XML file.
    
    WHAT THIS SCRIPT DOES:
    - Applies IPsec encryption rules directly to the local machine
    - Configures Windows Firewall settings for enhanced security
    - Sets up certificate-based authentication for network communications
    - Configures cryptographic algorithms (AES256, SHA256, etc.)
    - No Active Directory or Group Policy dependencies required
    
    REQUIREMENTS:
    - Windows Server 2016 or later
    - PowerShell 4.0 or later
    - Local Administrator privileges
    - Machine certificates installed (for certificate-based authentication)
 
.PARAMETER ConfigFile
    Path to the XML configuration file containing IPsec rules description.
    This file defines what traffic to encrypt and how to encrypt it.
 
.PARAMETER Mode
    IPsec mode to use:
    - Request: Attempts encryption but allows unencrypted fallback (optional)
    - Require: Mandates encryption, blocks unencrypted traffic (mandatory)
 
.PARAMETER RuleName
    Optional: Specific rule name to apply. If not specified, all rules are applied.
    Use this to apply only one rule from the configuration file.
 
.PARAMETER Confirm
    If true, confirmation is required to execute the script.
    Set to $false for automation/silent execution.
 
.PARAMETER RemoveExisting
    If true, removes all existing IPsec rules before applying new ones.
    Useful for clean slate deployments.
 
.OUTPUTS
    Boolean: Returns $true on success, $false on error.
    Exit code: 0 on success, 1 on error.
 
.EXAMPLE
    Apply IPsec rules with default parameters:
    PS> .\Configure-LocalIPsec.ps1 -ConfigFile ".\IPsecConfig.xml"
 
.EXAMPLE
    Apply IPsec in Require mode (mandatory encryption):
    PS> .\Configure-LocalIPsec.ps1 -ConfigFile ".\IPsecConfig.xml" -Mode Require
 
.EXAMPLE
    Remove existing rules and apply new ones without confirmation:
    PS> .\Configure-LocalIPsec.ps1 -ConfigFile ".\IPsecConfig.xml" -RemoveExisting -Confirm:$false
 
.EXAMPLE
    Apply only a specific rule:
    PS> .\Configure-LocalIPsec.ps1 -ConfigFile ".\IPsecConfig.xml" -RuleName "Contoso-HTTPS-Secure"
 
.NOTES
    Author: Microsoft Consulting Services
    Adapted for Contoso
    Version: 1.0
    Date: November 3, 2025
    
    This script applies IPsec configuration LOCALLY to the server.
    Changes take effect immediately (no reboot required).
    
    To view applied rules: Get-NetIPsecRule -PolicyStore ActiveStore
    To remove rules: Remove-NetIPsecRule -All -PolicyStore ActiveStore
#>

#Requires -Version 4.0
#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [String]$ConfigFile,
 
    [Parameter(Mandatory=$false)]
    [ValidateSet('Request', 'Require')]
    [String]$Mode = 'Request',
 
    [Parameter(Mandatory=$false)]
    [String]$RuleName = $null,
 
    [Parameter(Mandatory=$false)]
    [Switch]$Confirm = $true,
 
    [Parameter(Mandatory=$false)]
    [Switch]$RemoveExisting = $false
)

Set-StrictMode -Version Latest

#region Helper Functions - Logging and Validation

<#
    This section contains utility functions for logging, validation, and user interaction.
    These functions are used throughout the script to provide feedback and ensure prerequisites.
#>

function Write-Log {
    <#
    .SYNOPSIS
        Writes colored log messages to console with timestamps.
    .DESCRIPTION
        Provides consistent, color-coded logging throughout the script execution.
        Each message is prefixed with a timestamp for audit purposes.
    .PARAMETER Message
        The message to display.
    .PARAMETER Type
        Type of message which determines the color:
        - Info: Cyan (informational messages)
        - Warning: Yellow (warnings that don't stop execution)
        - Error: Red (errors that may stop execution)
        - Success: Green (successful operations)
        - Title: Magenta (section headers)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
        [String]$Message = "",
 
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Title')]
        [String]$Type = 'Info'
    )
 
    # Add timestamp to all log messages
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Set color based on message type
    $color = switch ($Type) {
        'Info'    { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
        'Title'   { 'Magenta' }
        default   { 'White' }
    }
    
    # Write timestamp in gray, message in appropriate color
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor DarkGray
    Write-Host $Message -ForegroundColor $color
}

function Test-Administrator {
    <#
    .SYNOPSIS
        Checks if the script is running with Administrator privileges.
    .DESCRIPTION
        IPsec configuration requires Administrator rights. This function verifies
        the current user has the necessary permissions before proceeding.
    .OUTPUTS
        Boolean: $true if running as Administrator, $false otherwise.
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WindowsVersion {
    <#
    .SYNOPSIS
        Gets the current Windows version and build number.
    .DESCRIPTION
        Retrieves Windows version information from the registry to ensure
        the server meets the minimum requirements (Windows Server 2016 or later).
    .OUTPUTS
        Version object representing the Windows version, or 0.0.0.0 on error.
    #>
    try {
        $osInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $build = $osInfo.CurrentBuild
        
        # Build version object from registry data
        $version = [Version]"$($osInfo.CurrentMajorVersionNumber).$($osInfo.CurrentMinorVersionNumber).$build"
        Write-Log "Windows Version: $version (Build $build)" -Type Info
        return $version
    } catch {
        Write-Log "Unable to determine Windows version: $_" -Type Error
        return [Version]"0.0.0.0"
    }
}

function Import-RequiredModules {
    <#
    .SYNOPSIS
        Imports PowerShell modules required for IPsec configuration.
    .DESCRIPTION
        The NetSecurity module provides cmdlets for configuring Windows Firewall
        and IPsec rules. This function ensures the module is available and loaded.
    .OUTPUTS
        Boolean: $true if all modules loaded successfully, $false otherwise.
    #>
    $modules = @('NetSecurity')
    
    foreach ($module in $modules) {
        try {
            Write-Log "Importing module: $module" -Type Info
            Import-Module -Name $module -ErrorAction Stop
        } catch {
            Write-Log "Failed to import module '$module': $_" -Type Error
            Write-Log "NetSecurity module is required for IPsec configuration" -Type Error
            return $false
        }
    }
    return $true
}

function Get-UserConfirmation {
    <#
    .SYNOPSIS
        Prompts user for confirmation before proceeding.
    .DESCRIPTION
        Displays a confirmation prompt and waits for user response.
        Used to prevent accidental execution in production environments.
    .PARAMETER Message
        The confirmation message to display.
    .OUTPUTS
        Boolean: $true if user confirms (Y/Yes), $false otherwise.
    #>
    param (
        [Parameter(Mandatory=$false)]
        [String]$Message = "Do you want to continue? (Y/N)"
    )
    
    $response = Read-Host -Prompt $Message
    return ($response -match '^[Yy]')
}

#endregion

#region Configuration Reading Functions

<#
    This section handles reading and parsing the XML configuration file.
    The XML file contains IPsec rules, cryptographic settings, and firewall configuration.
#>

function Read-IPsecConfig {
    <#
    .SYNOPSIS
        Reads and validates the XML configuration file.
    .DESCRIPTION
        Parses the XML configuration file containing IPsec rules and settings.
        Extracts global IPsec settings (encryption, hashing, key exchange)
        and individual rule definitions (addresses, ports, protocols).
        
        The XML structure supports both ESAEDomain and Domain nodes for flexibility.
    .PARAMETER Path
        Full path to the XML configuration file.
    .OUTPUTS
        Hashtable containing 'Settings' and 'Rules', or $null on error.
        
        Settings hashtable includes:
        - CAPath: Certificate Authority path for authentication
        - CrlCheck: Certificate Revocation List checking mode
        - Exemptions: Firewall exemptions
        - Encapsulation: AH, ESP, or both
        - KeyExchange: Diffie-Hellman group (DH14/19/20/24)
        - QMHash/MMHash: Hash algorithms for Quick/Main Mode
        - QMEncryption/MMEncryption: Encryption algorithms
        - KeyModule: IKE version (IKEv1/IKEv2/AuthIP)
        - MaxSessions: Maximum concurrent IPsec sessions
        
        Rules array includes objects with:
        - Name: Rule display name
        - Inbound/Outbound: Security action (Request/Require/None)
        - LocalAddress/RemoteAddress: IP addresses or subnets
        - LocalPort/RemotePort: Port numbers or "Any"
        - Protocol: TCP/UDP/Any
    #>
    param (
        [Parameter(Mandatory=$true)]
        [String]$Path
    )
    
    try {
        Write-Log "Reading configuration file: $Path" -Type Info
        [xml]$xml = Get-Content -Path $Path -ErrorAction Stop
        
        # Initialize configuration hashtable
        $config = @{
            'Settings' = @{}
            'Rules' = @()
        }
        
        # Determine domain node (supports both ESAEDomain and Domain)
        $domainNode = $null
        if ($xml.Settings.ESAEDomain) {
            $domainNode = $xml.Settings.ESAEDomain
            Write-Log "Using ESAEDomain configuration node" -Type Info
        } elseif ($xml.Settings.Domain) {
            $domainNode = $xml.Settings.Domain
            Write-Log "Using Domain configuration node" -Type Info
        } else {
            Write-Log "No domain configuration found in XML (expected ESAEDomain or Domain node)" -Type Error
            return $null
        }
        
        # Extract global IPsec settings from XML
        $global = $domainNode.IPsec.Global
        $config.Settings = @{
            'CAPath' = $domainNode.CAPath
            'CrlCheck' = $global.IPsecCrlCheck
            'Exemptions' = $global.IPsecExemptions
            'Encapsulation' = $global.IPsecEncapsulation
            'KeyExchange' = $global.IPsecKeyExchange
            'QMHash' = $global.IPsecQMHash
            'MMHash' = $global.IPsecMMHash
            'QMEncryption' = $global.IPsecQMEncryption
            'MMEncryption' = $global.IPsecMMEncryption
            'KeyModule' = $global.IPsecKeyModule
            'MaxSessions' = [int]$global.IPsecMaxSessions
        }
        
        # Log the loaded settings for verification
        Write-Log "IPsec Settings loaded successfully" -Type Success
        Write-Log "  - Encapsulation: $($config.Settings.Encapsulation)" -Type Info
        Write-Log "  - Encryption: $($config.Settings.QMEncryption)" -Type Info
        Write-Log "  - Hash Algorithm: $($config.Settings.QMHash)" -Type Info
        Write-Log "  - Key Exchange: $($config.Settings.KeyExchange)" -Type Info
        Write-Log "  - Key Module: $($config.Settings.KeyModule)" -Type Info
        
        # Extract IPsec rules from XML
        $rules = $domainNode.IPsec.Rules.Rule
        if ($rules) {
            foreach ($rule in $rules) {
                # Parse each rule and add to configuration
                $ruleObj = @{
                    'Name' = $rule.Name
                    'Inbound' = $rule.Inbound
                    'Outbound' = $rule.Outbound
                    'LocalAddress' = @($rule.LocalAddress.Split(',').Trim())
                    'RemoteAddress' = @($rule.RemoteAddress.Split(',').Trim())
                    'LocalPort' = @($rule.LocalPort.Split(',').Trim())
                    'RemotePort' = @($rule.RemotePort.Split(',').Trim())
                    'Protocol' = $rule.Protocol
                }
                $config.Rules += $ruleObj
            }
            Write-Log "Loaded $($config.Rules.Count) IPsec rule(s)" -Type Success
            
            # List all rule names for verification
            foreach ($rule in $config.Rules) {
                Write-Log "  - $($rule.Name)" -Type Info
            }
        } else {
            Write-Log "No IPsec rules found in configuration" -Type Warning
        }
        
        return $config
        
    } catch {
        Write-Log "Failed to read configuration file: $_" -Type Error
        return $null
    }
}

#endregion

#region Firewall and IPsec Management Functions

<#
    This section contains functions for configuring Windows Firewall
    and managing existing IPsec rules.
#>

function Remove-ExistingIPsecRules {
    <#
    .SYNOPSIS
        Removes all existing IPsec rules from the local policy.
    .DESCRIPTION
        Cleans up any existing IPsec configuration on the server including:
        - IPsec rules
        - Phase 1 authentication sets
        - Main Mode cryptographic sets
        - Main Mode rules
        - Quick Mode cryptographic sets
        
        This ensures a clean slate before applying new configuration.
        Uses PolicyStore 'ActiveStore' which represents the currently active policy.
    .OUTPUTS
        Boolean: $true on success, $false on error.
    #>
    try {
        Write-Log "Removing existing IPsec configuration..." -Type Info
        
        # Remove all IPsec components in order
        # SilentlyContinue prevents errors if components don't exist
        Remove-NetIPsecRule -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        Remove-NetIPsecPhase1AuthSet -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        Remove-NetIPsecMainModeCryptoSet -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        Remove-NetIPsecMainModeRule -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        Remove-NetIPsecQuickModeCryptoSet -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        
        Write-Log "Existing IPsec configuration removed" -Type Success
        return $true
        
    } catch {
        Write-Log "Failed to remove existing IPsec rules: $_" -Type Error
        return $false
    }
}

function Set-FirewallConfiguration {
    <#
    .SYNOPSIS
        Configures Windows Firewall settings for IPsec operation.
    .DESCRIPTION
        Applies firewall configuration including:
        
        FIREWALL PROFILES (Domain, Public, Private):
        - Enabled: True (firewall is active)
        - DefaultInboundAction: Block (deny all inbound by default)
        - DefaultOutboundAction: Allow (permit all outbound by default)
        - AllowLocalIPsecRules: True (allows IPsec rules to override blocks)
        - EnableStealthModeForIPsec: True (hides server from port scans)
        
        LOGGING:
        - LogAllowed/LogBlocked: True (logs all connections)
        - LogMaxSizeKilobytes: 32767 (32MB log file)
        - LogFileName: Standard Windows firewall log location
        
        CERTIFICATE VALIDATION:
        - Exemptions: ICMP, DHCP, etc. (from configuration)
        - CertValidationLevel: CRL checking mode (from configuration)
    .PARAMETER Settings
        Hashtable containing IPsec settings from XML configuration.
    .OUTPUTS
        Boolean: $true on success, $false on error.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Settings
    )
    
    try {
        Write-Log "Configuring Windows Firewall..." -Type Info
        
        # Configure all firewall profiles (Domain, Public, Private)
        Set-NetFirewallProfile -Profile Domain, Public, Private `
                               -Enabled True `
                               -DefaultInboundAction Block `
                               -DefaultOutboundAction Allow `
                               -AllowLocalIPsecRules True `
                               -EnableStealthModeForIPsec True `
                               -LogAllowed True `
                               -LogBlocked True `
                               -LogMaxSizeKilobytes 32767 `
                               -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' `
                               -ErrorAction Stop
        
        Write-Log "Firewall profiles configured (Block inbound, Allow outbound)" -Type Success
        
        # Configure firewall-specific settings for IPsec
        $exemptions = if ($Settings.Exemptions -eq 'None') { 'None' } else { $Settings.Exemptions }
        $crlCheck = if ($Settings.CrlCheck -eq 'RequireCrlCheck') { 'RequireCrlCheck' } else { 'None' }
        
        Set-NetFirewallSetting -Exemptions $exemptions `
                               -CertValidationLevel $crlCheck `
                               -ErrorAction Stop
        
        Write-Log "Firewall settings configured (Exemptions: $exemptions, CRL Check: $crlCheck)" -Type Success
        return $true
        
    } catch {
        Write-Log "Failed to configure Windows Firewall: $_" -Type Error
        return $false
    }
}

#endregion
