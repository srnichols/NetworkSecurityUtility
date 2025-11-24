<#
.SYNOPSIS
    IPsec Configuration Utility - Unified Management Tool
    
.DESCRIPTION
    Smart menu-driven utility for managing IPsec configuration on Windows Server.
    Automatically detects environment and adapts functionality:
    - Local Mode: Standalone server IPsec configuration
    - Enterprise Mode: GPO-based Active Directory deployment
    
    FEATURES:
    - Auto-detection of Domain Controller and AD capabilities
    - Interactive menu with context-aware options
    - Double confirmation for destructive operations
    - Comprehensive audit logging to file
    - HTML report generation
    - Partial configuration support with chunk-based validation
    - Just-in-time validation (validate only what each operation needs)
    - Backup and rollback capabilities
    - Real-time status monitoring
    - MDT/Deployment rule generation (optional, if infrastructure IPs present)
    
.PARAMETER ConfigFile
    Path to XML configuration file. If not specified, will prompt during execution.
    
.PARAMETER LogFile
    Path to audit log file. Default: .\IPsec-Utility-Log-YYYYMMDD.txt
    
.PARAMETER Mode
    Force specific mode: 'Auto' (default), 'Local', or 'Enterprise'
    Auto mode detects environment automatically.
    
.PARAMETER NonInteractive
    Run in non-interactive mode (requires additional parameters for automation)
    
.EXAMPLE
    Interactive mode with auto-detection:
    PS> .\IPsec-Configuration-Utility.ps1
    
.EXAMPLE
    Specify configuration file:
    PS> .\IPsec-Configuration-Utility.ps1 -ConfigFile ".\LocalIPsecConfig-Contoso.xml"
    
.EXAMPLE
    Force local mode:
    PS> .\IPsec-Configuration-Utility.ps1 -Mode Local
    
.NOTES
    Author: Microsoft Consulting Services
    Client: Contoso
    Version: 1.0
    Date: November 3, 2025
    
    Requirements:
    - Windows Server 2016 or later
    - PowerShell 4.0 or later
    - Administrator privileges
    - NetSecurity module (always required)
    - ActiveDirectory/GroupPolicy modules (for Enterprise mode)
    
    MDT/Deployment Functionality:
    The script automatically detects infrastructure IP addresses in the XML configuration
    and generates deployment-friendly IPsec rules if present. These rules allow deployment
    servers (DC, WSUS, CA, SQL, SCOM, etc.) to communicate with less strict IPsec during
    MDT/SCCM deployment operations. This feature is optional and only activates when
    infrastructure IP fields (DC1IP, DC2IP, WSUSIP, CAIP, etc.) are present in the XML.
    
    Chunk-Based Validation (New):
    The script now supports partial/incomplete configuration files. Instead of requiring
    all fields upfront, the script loads whatever is available and validates specific
    requirements only when operations need them. For example:
    - "Create Phase1 Auth" validates CAPath is present
    - "Create Main Mode Crypto" validates MM crypto settings are present
    - "Apply IPsec Rules" validates rules array exists
    
    This enables incremental configuration development and clearer error messages when
    specific fields are missing. Operations fail gracefully with detailed guidance on
    what's required. See Chunk-Validation-Quick-Reference.md for details.
#>

#Requires -Version 4.0
#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [String]$ConfigFile = $null,
    
    [Parameter(Mandatory=$false)]
    [String]$LogFile = $null,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Auto', 'Local', 'Enterprise')]
    [String]$Mode = 'Auto',
    
    [Parameter(Mandatory=$false)]
    [Switch]$NonInteractive = $false
)

Set-StrictMode -Version Latest

#region Script Variables

<#
    Global script variables for tracking state and configuration
#>

# Script version and metadata
$Script:Version = "1.0"
$Script:ScriptName = "IPsec Configuration Utility"
$Script:ClientName = "Contoso"

# Environment detection results
$Script:EnvironmentMode = $null  # Will be 'Local' or 'Enterprise'
$Script:IsAdministrator = $false
$Script:IsDomainController = $false
$Script:HasActiveDirectory = $false
$Script:HasGroupPolicy = $false
$Script:HasNetSecurity = $false

# Configuration state
$Script:CurrentConfig = $null
$Script:ConfigFileLoaded = $false
$Script:BackupPath = $null

# Logging
$Script:LogFilePath = $null
$Script:LogBuffer = @()

# Colors for consistent UI
$Script:Colors = @{
    'Title'    = 'Cyan'
    'Menu'     = 'White'
    'Success'  = 'Green'
    'Warning'  = 'Yellow'
    'Error'    = 'Red'
    'Info'     = 'Gray'
    'Prompt'   = 'Yellow'
    'Header'   = 'Magenta'
}

#endregion

#region Logging Functions

<#
    Comprehensive logging system with file output and console display.
    All operations are logged for audit and troubleshooting purposes.
#>

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes the logging system and creates log file.
    .DESCRIPTION
        Creates a timestamped log file in the script directory.
        All subsequent operations will be logged to this file.
    #>
    
    if ([String]::IsNullOrEmpty($Script:LogFilePath)) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $Script:LogFilePath = Join-Path -Path $PSScriptRoot -ChildPath "IPsec-Utility-Log-$timestamp.txt"
    }
    
    try {
        # Create log file with header
        $header = @"
================================================================================
$Script:ScriptName - Audit Log
Client: $Script:ClientName
Version: $Script:Version
Started: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
User: $env:USERNAME
Computer: $env:COMPUTERNAME
================================================================================

"@
        $header | Out-File -FilePath $Script:LogFilePath -Encoding UTF8
        Write-Host "Log file created: $Script:LogFilePath" -ForegroundColor $Script:Colors.Info
        return $true
    } catch {
        Write-Host "WARNING: Unable to create log file: $_" -ForegroundColor $Script:Colors.Warning
        return $false
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log entry to both console and file.
    .DESCRIPTION
        Provides consistent logging with timestamps, colors, and file output.
        All messages are written to the log file for audit purposes.
    .PARAMETER Message
        The message to log.
    .PARAMETER Type
        Message type: Info, Success, Warning, Error, Title, Header
    .PARAMETER NoConsole
        If specified, only writes to file (not console).
    .PARAMETER NoFile
        If specified, only writes to console (not file).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
        [String]$Message = "",
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Title', 'Header', 'Menu', 'Prompt')]
        [String]$Type = 'Info',
        
        [Parameter(Mandatory=$false)]
        [Switch]$NoConsole = $false,
        
        [Parameter(Mandatory=$false)]
        [Switch]$NoFile = $false
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    
    # Write to file
    if (-not $NoFile -and $Script:LogFilePath) {
        try {
            $logEntry | Out-File -FilePath $Script:LogFilePath -Append -Encoding UTF8
        } catch {
            # Silently fail if log file unavailable
        }
    }
    
    # Write to console
    if (-not $NoConsole) {
        $color = $Script:Colors[$Type]
        if (-not $color) { $color = 'White' }
        
        if ($Type -in @('Title', 'Header')) {
            Write-Host ""
            Write-Host $Message -ForegroundColor $color
            Write-Host ("=" * $Message.Length) -ForegroundColor $color
        } else {
            Write-Host "[$timestamp] " -NoNewline -ForegroundColor DarkGray
            Write-Host $Message -ForegroundColor $color
        }
    }
}

function Write-LogSeparator {
    <#
    .SYNOPSIS
        Writes a visual separator to the log.
    #>
    $separator = ("-" * 80)
    Write-Log -Message $separator -Type Info
}

#endregion

#region Environment Detection

<#
    Detects the server environment and available capabilities.
    Determines which features can be enabled based on modules and roles.
#>

function Test-Administrator {
    <#
    .SYNOPSIS
        Checks if script is running with Administrator privileges.
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-DomainController {
    <#
    .SYNOPSIS
        Checks if the current machine is a Domain Controller.
    .DESCRIPTION
        Uses WMI to determine if the server has the Domain Controller role.
    #>
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        # ProductType: 1=Workstation, 2=Domain Controller, 3=Server
        return ($os.ProductType -eq 2)
    } catch {
        Write-Log "Unable to determine if server is Domain Controller: $_" -Type Warning
        return $false
    }
}

function Test-ModuleAvailable {
    <#
    .SYNOPSIS
        Checks if a PowerShell module is available.
    .PARAMETER ModuleName
        Name of the module to check.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [String]$ModuleName
    )
    
    $module = Get-Module -Name $ModuleName -ListAvailable -ErrorAction SilentlyContinue
    return ($null -ne $module)
}

function Initialize-Environment {
    <#
    .SYNOPSIS
        Detects environment capabilities and sets script mode.
    .DESCRIPTION
        Performs comprehensive environment detection:
        - Checks Administrator privileges
        - Detects Domain Controller role
        - Tests for required PowerShell modules
        - Determines if Local or Enterprise mode should be used
        
        Sets global script variables based on detection results.
    #>
    
    Write-Log "Detecting environment capabilities..." -Type Title
    
    # Check Administrator privileges (required)
    $Script:IsAdministrator = Test-Administrator
    Write-Log "Administrator privileges: $Script:IsAdministrator" -Type Info
    
    if (-not $Script:IsAdministrator) {
        Write-Log "ERROR: This utility requires Administrator privileges" -Type Error
        Write-Log "Please restart PowerShell as Administrator" -Type Error
        return $false
    }
    
    # Check if Domain Controller
    $Script:IsDomainController = Test-DomainController
    Write-Log "Domain Controller: $Script:IsDomainController" -Type Info
    
    # Check for required modules
    $Script:HasNetSecurity = Test-ModuleAvailable -ModuleName 'NetSecurity'
    $Script:HasActiveDirectory = Test-ModuleAvailable -ModuleName 'ActiveDirectory'
    $Script:HasGroupPolicy = Test-ModuleAvailable -ModuleName 'GroupPolicy'
    
    Write-Log "NetSecurity module: $Script:HasNetSecurity" -Type Info
    Write-Log "ActiveDirectory module: $Script:HasActiveDirectory" -Type Info
    Write-Log "GroupPolicy module: $Script:HasGroupPolicy" -Type Info
    
    # NetSecurity is required for all operations
    if (-not $Script:HasNetSecurity) {
        Write-Log "ERROR: NetSecurity module is required but not available" -Type Error
        Write-Log "Install with: Install-WindowsFeature RSAT-RemoteAccess-PowerShell" -Type Info
        return $false
    }
    
    # Determine mode
    if ($Mode -eq 'Auto') {
        # Auto-detect based on capabilities
        if ($Script:IsDomainController -and $Script:HasActiveDirectory -and $Script:HasGroupPolicy) {
            $Script:EnvironmentMode = 'Enterprise'
        } else {
            $Script:EnvironmentMode = 'Local'
        }
    } else {
        # Use forced mode
        $Script:EnvironmentMode = $Mode
        
        # Validate forced mode is possible
        if ($Mode -eq 'Enterprise') {
            if (-not ($Script:HasActiveDirectory -and $Script:HasGroupPolicy)) {
                Write-Log "ERROR: Enterprise mode requested but required modules not available" -Type Error
                Write-Log "Active Directory and Group Policy modules are required for Enterprise mode" -Type Error
                return $false
            }
        }
    }
    
    Write-Log "" -NoFile
    Write-Log "Environment Mode: $Script:EnvironmentMode" -Type Success
    Write-Log "" -NoFile
    
    if ($Script:EnvironmentMode -eq 'Local') {
        Write-Log "Running in LOCAL mode - IPsec rules applied directly to this server" -Type Info
    } else {
        Write-Log "Running in ENTERPRISE mode - GPO-based Active Directory deployment" -Type Info
    }
    
    return $true
}

#endregion

#region Helper Functions

function Get-UserConfirmation {
    <#
    .SYNOPSIS
        Prompts user for confirmation.
    .PARAMETER Message
        Confirmation message to display.
    .PARAMETER DefaultYes
        If true, default answer is Yes. Otherwise default is No.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [String]$Message,
        
        [Parameter(Mandatory=$false)]
        [Switch]$DefaultYes = $false
    )
    
    $prompt = if ($DefaultYes) { "(Y/n)" } else { "(y/N)" }
    $response = Read-Host "$Message $prompt"
    
    if ([String]::IsNullOrWhiteSpace($response)) {
        return $DefaultYes
    }
    
    return ($response -match '^[Yy]')
}

function Get-DoubleConfirmation {
    <#
    .SYNOPSIS
        Requires double confirmation for destructive operations.
    .DESCRIPTION
        Implements safety feature requiring two confirmations
        before executing potentially dangerous operations.
    .PARAMETER Operation
        Description of the operation to confirm.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [String]$Operation
    )
    
    Write-Log "" -NoFile
    Write-Log "WARNING: This operation will $Operation" -Type Warning
    Write-Log "This action cannot be easily undone." -Type Warning
    Write-Log "" -NoFile
    
    $confirm1 = Get-UserConfirmation -Message "Are you sure you want to proceed?"
    if (-not $confirm1) {
        Write-Log "Operation cancelled by user" -Type Info
        return $false
    }
    
    Write-Log "" -NoFile
    Write-Log "SECOND CONFIRMATION REQUIRED" -Type Warning
    $confirm2 = Get-UserConfirmation -Message "Please confirm again to proceed"
    
    if ($confirm2) {
        Write-Log "Double confirmation received - proceeding with operation" -Type Info
        return $true
    } else {
        Write-Log "Operation cancelled by user (second confirmation)" -Type Info
        return $false
    }
}

function Pause-ForUser {
    <#
    .SYNOPSIS
        Pauses and waits for user to press a key.
    .NOTES
        Uses unapproved verb 'Pause' but is acceptable for internal helper function.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param()
    
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor $Script:Colors.Prompt
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

#endregion

#region Configuration Management

<#
    Functions for reading, validating, and managing XML configuration files.
    Supports both Local and Enterprise mode configurations.
#>

function Read-IPsecConfiguration {
    <#
    .SYNOPSIS
        Reads and validates the XML configuration file.
    .DESCRIPTION
        Parses XML configuration with strict validation.
        Supports both ESAEDomain and Domain node structures.
        Validates all required fields and data types.
    .PARAMETER Path
        Full path to the XML configuration file.
    .OUTPUTS
        Hashtable with 'Settings' and 'Rules', or $null on error.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [String]$Path
    )
    
    Write-Log "Reading configuration file: $Path" -Type Info
    
    # Validate file exists
    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        Write-Log "ERROR: Configuration file not found: $Path" -Type Error
        return $null
    }
    
    try {
        [xml]$xml = Get-Content -Path $Path -ErrorAction Stop
        
        # Initialize configuration structure
        $config = @{
            'Settings' = @{}
            'Rules' = @()
            'GPOSettings' = @{}  # For Enterprise mode
        }
        
        # Determine domain node
        $domainNode = $null
        if ($xml.Settings.ESAEDomain) {
            $domainNode = $xml.Settings.ESAEDomain
            Write-Log "Using ESAEDomain configuration node" -Type Info
        } elseif ($xml.Settings.Domain) {
            $domainNode = $xml.Settings.Domain
            Write-Log "Using Domain configuration node" -Type Info
        } else {
            Write-Log "ERROR: No domain configuration found (expected ESAEDomain or Domain node)" -Type Error
            return $null
        }
        
        # Extract global IPsec settings (using best-effort/relaxed loading)
        # Missing fields will be caught by Test-ConfigRequirement when operations need them
        $global = $domainNode.IPsec.Global
        
        if (-not $global) {
            Write-Log "WARNING: No Global IPsec settings found - limited operations available" -Type Warning
        }
        
        # Build list of available settings
        $availableSettings = @()
        $missingSettings = @()
        
        $settingsMap = @{
            'IPsecCrlCheck' = 'CrlCheck'
            'IPsecExemptions' = 'Exemptions'
            'IPsecEncapsulation' = 'Encapsulation'
            'IPsecKeyExchange' = 'KeyExchange'
            'IPsecQMHash' = 'QMHash'
            'IPsecMMHash' = 'MMHash'
            'IPsecQMEncryption' = 'QMEncryption'
            'IPsecMMEncryption' = 'MMEncryption'
            'IPsecKeyModule' = 'KeyModule'
            'IPsecMaxSessions' = 'MaxSessions'
        }
        
        # Extract settings using best-effort approach
        $config.Settings = @{
            'CAPath' = if ($domainNode.CAPath) { $domainNode.CAPath.Trim() } else { $null }
        }
        
        foreach ($xmlName in $settingsMap.Keys) {
            $friendlyName = $settingsMap[$xmlName]
            if ($global -and -not [String]::IsNullOrWhiteSpace($global.$xmlName)) {
                if ($xmlName -eq 'IPsecMaxSessions') {
                    $config.Settings[$friendlyName] = [int]$global.$xmlName
                } else {
                    $config.Settings[$friendlyName] = $global.$xmlName.Trim()
                }
                $availableSettings += $xmlName
            } else {
                $config.Settings[$friendlyName] = $null
                $missingSettings += $xmlName
            }
        }
        
        # Log what was loaded
        if ($availableSettings.Count -gt 0) {
            Write-Log "Loaded $($availableSettings.Count)/10 IPsec Global settings" -Type Info
        }
        
        if ($missingSettings.Count -gt 0) {
            Write-Log "WARNING: Missing $($missingSettings.Count) settings: $($missingSettings -join ', ')" -Type Warning
            Write-Log "INFO: Operations requiring these settings will fail with clear error messages" -Type Info
        }
        
        # Extract optional MDT/Deployment fields (for deployment-friendly IPsec rules)
        $config.Settings['MDT'] = @{}
        
        # Check if this is a production XML (production XMLs don't have infrastructure IPs)
        $isProdXml = $true
        try {
            if ($domainNode.CAIP -match '^.+$') {
                $isProdXml = $false
            }
        } catch {
            $isProdXml = $true
        }
        
        if (-not $isProdXml) {
            # Extract deployment infrastructure fields
            # Try MDT-prefixed names first, then fall back to base names
            $mdtFields = @{
                'NetBIOSName' = if ($domainNode.MDTNetBIOSName) { $domainNode.MDTNetBIOSName } else { $domainNode.NetBIOSName }
                'FQDN' = if ($domainNode.MDTFQDN) { $domainNode.MDTFQDN } else { $domainNode.FQDNName }
                'DC1IP' = $domainNode.DC1IP
                'DC2IP' = $domainNode.DC2IP
                'WSUSIP' = $domainNode.WSUSIP
                'CAIP' = $domainNode.CAIP
                'SQLIP' = $domainNode.SQLIP
                'SCOMIP' = $domainNode.SCOMIP
                'WEFIP' = $domainNode.WEFIP
                'HV1IP' = $domainNode.HV1IP
                'HV2IP' = $domainNode.HV2IP
                'DomainJoinIP' = $domainNode.DomainJoinIP
                'DHCPStartIP' = $domainNode.MDTDHCPStartIP
                'DHCPEndIP' = $domainNode.MDTDHCPEndIP
                'WSUS' = $domainNode.MDTWSUS
            }
            
            # Only add non-empty fields
            foreach ($key in $mdtFields.Keys) {
                if (-not [String]::IsNullOrWhiteSpace($mdtFields[$key])) {
                    $config.Settings.MDT[$key] = $mdtFields[$key].ToString().Trim()
                }
            }
            
            if ($config.Settings.MDT.Count -gt 0) {
                Write-Log "MDT/Deployment fields detected: $($config.Settings.MDT.Count) field(s)" -Type Info
            }
        }
        
        # Validate cryptographic settings (only if present - relaxed validation)
        if ($availableSettings.Count -ge 6) {
            if (-not (Test-CryptoSettings -Settings $config.Settings)) {
                Write-Log "WARNING: Some cryptographic settings may be invalid - validation will occur per-operation" -Type Warning
            } else {
                Write-Log "Cryptographic settings validated successfully" -Type Success
            }
        } else {
            Write-Log "INFO: Insufficient crypto settings for validation - will validate per-operation" -Type Info
        }
        
        # Log available settings
        if ($config.Settings.Encapsulation) { Write-Log "  - Encapsulation: $($config.Settings.Encapsulation)" -Type Info }
        if ($config.Settings.QMEncryption) { Write-Log "  - QM Encryption: $($config.Settings.QMEncryption)" -Type Info }
        if ($config.Settings.QMHash) { Write-Log "  - QM Hash: $($config.Settings.QMHash)" -Type Info }
        if ($config.Settings.MMEncryption) { Write-Log "  - MM Encryption: $($config.Settings.MMEncryption)" -Type Info }
        if ($config.Settings.MMHash) { Write-Log "  - MM Hash: $($config.Settings.MMHash)" -Type Info }
        if ($config.Settings.KeyExchange) { Write-Log "  - Key Exchange: $($config.Settings.KeyExchange)" -Type Info }
        if ($config.Settings.KeyModule) { Write-Log "  - Key Module: $($config.Settings.KeyModule)" -Type Info }
        if ($config.Settings.MaxSessions) { Write-Log "  - Max Sessions: $($config.Settings.MaxSessions)" -Type Info }
        if ($config.Settings.CAPath) { Write-Log "  - CA Path: Available" -Type Info }
        
        # Extract IPsec rules
        $rules = $domainNode.IPsec.Rules.Rule
        if ($rules) {
            foreach ($rule in $rules) {
                # Validate rule has required fields
                if ([String]::IsNullOrWhiteSpace($rule.Name)) {
                    Write-Log "WARNING: Skipping rule with missing Name" -Type Warning
                    continue
                }
                
                $ruleObj = @{
                    'Name' = $rule.Name.Trim()
                    'Inbound' = $rule.Inbound.Trim()
                    'Outbound' = $rule.Outbound.Trim()
                    'LocalAddress' = @($rule.LocalAddress.Split(',').Trim())
                    'RemoteAddress' = @($rule.RemoteAddress.Split(',').Trim())
                    'LocalPort' = @($rule.LocalPort.Split(',').Trim())
                    'RemotePort' = @($rule.RemotePort.Split(',').Trim())
                    'Protocol' = $rule.Protocol.Trim()
                }
                
                # Validate rule
                if (-not (Test-IPsecRule -Rule $ruleObj)) {
                    Write-Log "WARNING: Skipping invalid rule: $($ruleObj.Name)" -Type Warning
                    continue
                }
                
                # Add GPO information if in Enterprise mode and available
                if ($Script:EnvironmentMode -eq 'Enterprise' -and $rule.GPO) {
                    $ruleObj['GPO'] = $rule.GPO.Trim()
                    $ruleObj['Location'] = @($rule.Location.Split(',').Trim())
                }
                
                $config.Rules += $ruleObj
            }
            
            Write-Log "Loaded $($config.Rules.Count) IPsec rule(s):" -Type Success
            foreach ($rule in $config.Rules) {
                $gpoInfo = if ($rule.GPO) { " [GPO: $($rule.GPO)]" } else { "" }
                Write-Log "  - $($rule.Name)$gpoInfo" -Type Info
            }
        } else {
            Write-Log "WARNING: No IPsec rules found in configuration" -Type Warning
        }
        
        # Generate deployment rules if MDT fields are present
        if ($config.Settings.MDT.Count -gt 0) {
            Write-Log "MDT/Deployment configuration detected - generating deployment rules" -Type Info
            
            $domainFQDN = $null
            if ($domainNode.FQDNName) {
                $domainFQDN = $domainNode.FQDNName
            } elseif ($config.Settings.MDT.FQDN) {
                $domainFQDN = $config.Settings.MDT.FQDN
            }
            
            $deploymentRules = Get-DeploymentIPsecRules -MDTConfig $config.Settings.MDT -DomainFQDN $domainFQDN
            
            if ($deploymentRules.Count -gt 0) {
                # Append deployment rules to existing rules
                $config.Rules += $deploymentRules
                Write-Log "Total rules after adding deployment rules: $($config.Rules.Count)" -Type Success
            }
        }
        
        # Store configuration in script variable
        $Script:CurrentConfig = $config
        $Script:ConfigFileLoaded = $true
        
        Write-Log "Configuration loaded successfully" -Type Success
        return $config
        
    } catch {
        Write-Log "ERROR: Failed to read configuration file: $_" -Type Error
        return $null
    }
}

function Get-DeploymentIPsecRules {
    <#
    .SYNOPSIS
        Generates deployment-friendly IPsec rules from infrastructure IP addresses.
    .DESCRIPTION
        Creates IPsec rules for MDT/deployment scenarios using infrastructure server IPs.
        Allows deployment servers (DC, WSUS, CA, SQL, SCOM, etc.) to communicate with
        less strict IPsec requirements during OS deployment operations.
        
        Based on Configure-CTMIPsec.ps1 MDT rule generation logic.
    .PARAMETER MDTConfig
        Hashtable containing MDT/deployment configuration fields.
    .PARAMETER DomainFQDN
        Fully qualified domain name (for GPO paths in Enterprise mode).
    .OUTPUTS
        Array of IPsec rule objects, or empty array if insufficient data.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$MDTConfig,
        
        [Parameter(Mandatory=$false)]
        [string]$DomainFQDN
    )
    
    # Check if we have minimum required fields
    if (-not $MDTConfig.NetBIOSName -and -not $MDTConfig.FQDN) {
        Write-Log "No NetBIOS or FQDN name for deployment rules - skipping" -Type Info
        return @()
    }
    
    # Use NetBIOSName if available, otherwise extract from FQDN
    $netbiosName = if ($MDTConfig.NetBIOSName) {
        $MDTConfig.NetBIOSName.ToUpper()
    } elseif ($MDTConfig.FQDN) {
        $MDTConfig.FQDN.Split('.')[0].ToUpper()
    } else {
        "DOMAIN"
    }
    
    $fqdn = if ($MDTConfig.FQDN) {
        $MDTConfig.FQDN
    } elseif ($DomainFQDN) {
        $DomainFQDN
    } else {
        $netbiosName.ToLower() + ".local"
    }
    
    # Collect infrastructure IP addresses
    $deployIPs = @()
    $ipFields = @('DomainJoinIP', 'DC1IP', 'DC2IP', 'WSUSIP', 'CAIP', 'SQLIP', 'SCOMIP', 'WEFIP', 'HV1IP', 'HV2IP')
    
    foreach ($field in $ipFields) {
        if ($MDTConfig[$field]) {
            $ips = $MDTConfig[$field].Split(',').Trim() | Where-Object { 
                -not [String]::IsNullOrWhiteSpace($_) -and $_ -ine 'N/A' 
            }
            $deployIPs += $ips
        }
    }
    
    # Add DHCP range if both start and end are present
    if ($MDTConfig.DHCPStartIP -and $MDTConfig.DHCPEndIP) {
        $deployIPs += ($MDTConfig.DHCPStartIP.Trim() + '-' + $MDTConfig.DHCPEndIP.Trim())
    }
    
    # If no IPs collected, can't create meaningful rules
    if ($deployIPs.Count -eq 0) {
        Write-Log "No infrastructure IPs found in MDT config - skipping deployment rules" -Type Info
        return @()
    }
    
    Write-Log "Generating deployment IPsec rules with $($deployIPs.Count) infrastructure IP(s)" -Type Info
    
    # Build deployment rules array
    $rules = @()
    
    # Rule 1: Forest isolation (baseline Require mode for all traffic)
    $rules += @{
        'Name' = "$netbiosName-Forest-Any-Any-Isolation"
        'Inbound' = 'Require'
        'Outbound' = 'Require'
        'LocalAddress' = @('Any')
        'RemoteAddress' = @('Any')
        'LocalPort' = @('Any')
        'RemotePort' = @('Any')
        'Protocol' = 'Any'
        'GPO' = "$fqdn\$netbiosName Domain IPsec Policy"
        'Location' = @($fqdn)
    }
    
    # Rule 2: Deployment infrastructure (Request mode for infrastructure servers)
    $rules += @{
        'Name' = "$netbiosName-Forest-Deployment-MDT"
        'Inbound' = 'Request'
        'Outbound' = 'Request'
        'LocalAddress' = @('Any')
        'RemoteAddress' = $deployIPs
        'LocalPort' = @('Any')
        'RemotePort' = @('Any')
        'Protocol' = 'Any'
        'GPO' = "$fqdn\$netbiosName Deployment IPsec Policy"
        'Location' = @('Domain Controllers')
    }
    
    # Rule 3: WSUS-specific rule (if WSUS enabled)
    if ($MDTConfig.WSUS -ieq 'Yes') {
        $rules += @{
            'Name' = "$netbiosName-Forest-Deployment-WSUS"
            'Inbound' = 'Request'
            'Outbound' = 'Request'
            'LocalAddress' = @('Any')
            'RemoteAddress' = $deployIPs
            'LocalPort' = @('8530', '8531')
            'RemotePort' = @('Any')
            'Protocol' = 'TCP'
            'GPO' = "$fqdn\$netbiosName WSUS IPsec Policy"
            'Location' = @('Domain Controllers')
        }
        
        $rules += @{
            'Name' = "$netbiosName-Forest-WSUS-WU"
            'Inbound' = 'Require'
            'Outbound' = 'Request'
            'LocalAddress' = @('Any')
            'RemoteAddress' = @('Any')
            'LocalPort' = @('Any')
            'RemotePort' = @('Any')
            'Protocol' = 'TCP'
            'GPO' = "$fqdn\$netbiosName WSUS IPsec Policy"
            'Location' = @('Domain Controllers')
        }
    }
    
    Write-Log "Generated $($rules.Count) deployment IPsec rule(s)" -Type Success
    foreach ($rule in $rules) {
        Write-Log "  - $($rule.Name)" -Type Info
    }
    
    return $rules
}

function Test-CryptoSettings {
    <#
    .SYNOPSIS
        Validates cryptographic settings.
    .DESCRIPTION
        Performs strict validation of encryption, hashing, and key exchange settings.
        Ensures values are from allowed lists.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Settings
    )
    
    $valid = $true
    
    # Validate CRL Check
    if ($Settings.CrlCheck -notin @('None', 'RequireCrlCheck')) {
        Write-Log "ERROR: Invalid IPsecCrlCheck value: $($Settings.CrlCheck)" -Type Error
        $valid = $false
    }
    
    # Validate Encapsulation
    $encapValues = $Settings.Encapsulation.Split(',').Trim()
    foreach ($encap in $encapValues) {
        if ($encap -notin @('AH', 'ESP')) {
            Write-Log "ERROR: Invalid Encapsulation value: $encap" -Type Error
            $valid = $false
        }
    }
    
    # Validate Key Exchange
    if ($Settings.KeyExchange -notin @('DH14', 'DH19', 'DH20', 'DH24')) {
        Write-Log "ERROR: Invalid KeyExchange value: $($Settings.KeyExchange)" -Type Error
        $valid = $false
    }
    
    # Validate Hash algorithms
    $validHashes = @('SHA256', 'SHA384', 'SHA512', 'AESGMAC128', 'AESGMAC192', 'AESGMAC256')
    if ($Settings.QMHash -notin $validHashes) {
        Write-Log "ERROR: Invalid QMHash value: $($Settings.QMHash)" -Type Error
        $valid = $false
    }
    if ($Settings.MMHash -notin @('SHA256', 'SHA384', 'SHA512')) {
        Write-Log "ERROR: Invalid MMHash value: $($Settings.MMHash)" -Type Error
        $valid = $false
    }
    
    # Validate Encryption
    $validEncryption = @('None', 'AES256', 'AESGCM128', 'AESGCM192', 'AESGCM256')
    if ($Settings.QMEncryption -notin $validEncryption) {
        Write-Log "ERROR: Invalid QMEncryption value: $($Settings.QMEncryption)" -Type Error
        $valid = $false
    }
    if ($Settings.MMEncryption -notin @('None', 'AES256')) {
        Write-Log "ERROR: Invalid MMEncryption value: $($Settings.MMEncryption)" -Type Error
        $valid = $false
    }
    
    # Validate Key Module
    if ($Settings.KeyModule -notin @('Default', 'IKEv1', 'AuthIP', 'IKEv2')) {
        Write-Log "ERROR: Invalid KeyModule value: $($Settings.KeyModule)" -Type Error
        $valid = $false
    }
    
    # Validate Max Sessions
    if ($Settings.MaxSessions -lt 1 -or $Settings.MaxSessions -gt 65535) {
        Write-Log "ERROR: MaxSessions must be between 1 and 65535" -Type Error
        $valid = $false
    }
    
    return $valid
}

function Test-IPsecRule {
    <#
    .SYNOPSIS
        Validates an IPsec rule configuration.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Rule
    )
    
    $valid = $true
    
    # Validate Inbound/Outbound actions
    if ($Rule.Inbound -notin @('Request', 'Require', 'None')) {
        Write-Log "ERROR: Invalid Inbound action in rule '$($Rule.Name)': $($Rule.Inbound)" -Type Error
        $valid = $false
    }
    if ($Rule.Outbound -notin @('Request', 'Require', 'None')) {
        Write-Log "ERROR: Invalid Outbound action in rule '$($Rule.Name)': $($Rule.Outbound)" -Type Error
        $valid = $false
    }
    
    # Validate Protocol
    if ($Rule.Protocol -notin @('Any', 'TCP', 'UDP', 'ICMP', 'ICMPv6') -and $Rule.Protocol -notmatch '^\d+$') {
        Write-Log "ERROR: Invalid Protocol in rule '$($Rule.Name)': $($Rule.Protocol)" -Type Error
        $valid = $false
    }
    
    # Basic validation of addresses (more thorough validation could be added)
    if ($Rule.LocalAddress.Count -eq 0 -or [String]::IsNullOrWhiteSpace($Rule.LocalAddress[0])) {
        Write-Log "ERROR: LocalAddress missing in rule '$($Rule.Name)'" -Type Error
        $valid = $false
    }
    if ($Rule.RemoteAddress.Count -eq 0 -or [String]::IsNullOrWhiteSpace($Rule.RemoteAddress[0])) {
        Write-Log "ERROR: RemoteAddress missing in rule '$($Rule.Name)'" -Type Error
        $valid = $false
    }
    
    return $valid
}

function Test-ConfigRequirement {
    <#
    .SYNOPSIS
        Validates specific configuration requirements on-demand (chunk-based validation).
    .DESCRIPTION
        This function allows operations to validate only the config elements they need,
        enabling partial configuration support. Returns $true if requirement is met,
        writes detailed error message and returns $false if not.
    .PARAMETER RequirementType
        The type of requirement to validate:
        - 'CAPath': Certificate Authority path
        - 'CryptoSettings': All cryptographic settings (MM/QM encryption, hashes, key exchange, key module)
        - 'MMCrypto': Main Mode cryptographic settings only
        - 'QMCrypto': Quick Mode cryptographic settings only
        - 'Rules': IPsec rules array
        - 'MDTFields': MDT/Deployment infrastructure fields
        - 'DomainInfo': Basic domain information (NetBIOS, FQDN, DN)
    .PARAMETER Config
        Configuration hashtable from Read-IPsecConfiguration.
    .PARAMETER Operation
        Name of the operation requesting this requirement (for error messages).
    .OUTPUTS
        $true if requirement is met, $false if not (with detailed error logged).
    .EXAMPLE
        if (-not (Test-ConfigRequirement -RequirementType 'CAPath' -Config $script:Config -Operation 'Phase1 Authentication')) {
            return
        }
    #>
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('CAPath', 'CryptoSettings', 'MMCrypto', 'QMCrypto', 'Rules', 'MDTFields', 'DomainInfo')]
        [String]$RequirementType,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$Config,
        
        [Parameter(Mandatory=$true)]
        [String]$Operation
    )
    
    switch ($RequirementType) {
        'CAPath' {
            if ([String]::IsNullOrWhiteSpace($Config.Settings.CAPath)) {
                Write-Log "ERROR: Cannot perform '$Operation': CAPath is required but missing from Config.xml" -Type Error
                Write-Host "`nMISSING REQUIREMENT: CAPath" -ForegroundColor Red
                Write-Host "Operation: $Operation" -ForegroundColor Yellow
                Write-Host "Required Field: <CAPath> element in <ESAEDomain> or <Domain> node" -ForegroundColor Yellow
                Write-Host "Example: <CAPath>DC=contoso,DC=com,CN=Contoso-Root-CA</CAPath>" -ForegroundColor Cyan
                Write-Host ""
                return $false
            }
            return $true
        }
        
        'CryptoSettings' {
            $missing = @()
            if ([String]::IsNullOrWhiteSpace($Config.Settings.MMEncryption)) { $missing += 'IPsecMMEncryption' }
            if ([String]::IsNullOrWhiteSpace($Config.Settings.MMHash)) { $missing += 'IPsecMMHash' }
            if ([String]::IsNullOrWhiteSpace($Config.Settings.QMEncryption)) { $missing += 'IPsecQMEncryption' }
            if ([String]::IsNullOrWhiteSpace($Config.Settings.QMHash)) { $missing += 'IPsecQMHash' }
            if ([String]::IsNullOrWhiteSpace($Config.Settings.KeyExchange)) { $missing += 'IPsecKeyExchange' }
            if ([String]::IsNullOrWhiteSpace($Config.Settings.KeyModule)) { $missing += 'IPsecKeyModule' }
            
            if ($missing.Count -gt 0) {
                Write-Log "ERROR: Cannot perform '$Operation': Missing cryptographic settings: $($missing -join ', ')" -Type Error
                Write-Host "`nMISSING REQUIREMENTS: Cryptographic Settings" -ForegroundColor Red
                Write-Host "Operation: $Operation" -ForegroundColor Yellow
                Write-Host "Missing Fields in <IPsec><Global>:" -ForegroundColor Yellow
                foreach ($field in $missing) {
                    Write-Host "  - $field" -ForegroundColor Red
                }
                Write-Host "`nExample:" -ForegroundColor Cyan
                Write-Host "  <IPsec>" -ForegroundColor Gray
                Write-Host "    <Global>" -ForegroundColor Gray
                Write-Host "      <IPsecMMEncryption>AES256</IPsecMMEncryption>" -ForegroundColor Gray
                Write-Host "      <IPsecMMHash>SHA384</IPsecMMHash>" -ForegroundColor Gray
                Write-Host "      <IPsecQMEncryption>AESGCM256</IPsecQMEncryption>" -ForegroundColor Gray
                Write-Host "      <IPsecQMHash>SHA384</IPsecQMHash>" -ForegroundColor Gray
                Write-Host "      <IPsecKeyExchange>DH20</IPsecKeyExchange>" -ForegroundColor Gray
                Write-Host "      <IPsecKeyModule>Kerberos</IPsecKeyModule>" -ForegroundColor Gray
                Write-Host "    </Global>" -ForegroundColor Gray
                Write-Host "  </IPsec>" -ForegroundColor Gray
                Write-Host ""
                return $false
            }
            return $true
        }
        
        'MMCrypto' {
            $missing = @()
            if ([String]::IsNullOrWhiteSpace($Config.Settings.MMEncryption)) { $missing += 'IPsecMMEncryption' }
            if ([String]::IsNullOrWhiteSpace($Config.Settings.MMHash)) { $missing += 'IPsecMMHash' }
            if ([String]::IsNullOrWhiteSpace($Config.Settings.KeyExchange)) { $missing += 'IPsecKeyExchange' }
            if ([String]::IsNullOrWhiteSpace($Config.Settings.KeyModule)) { $missing += 'IPsecKeyModule' }
            
            if ($missing.Count -gt 0) {
                Write-Log "ERROR: Cannot perform '$Operation': Missing Main Mode crypto settings: $($missing -join ', ')" -Type Error
                Write-Host "`nMISSING REQUIREMENTS: Main Mode Cryptography" -ForegroundColor Red
                Write-Host "Operation: $Operation" -ForegroundColor Yellow
                Write-Host "Missing Fields in <IPsec><Global>:" -ForegroundColor Yellow
                foreach ($field in $missing) {
                    Write-Host "  - $field" -ForegroundColor Red
                }
                Write-Host ""
                return $false
            }
            return $true
        }
        
        'QMCrypto' {
            $missing = @()
            if ([String]::IsNullOrWhiteSpace($Config.Settings.QMEncryption)) { $missing += 'IPsecQMEncryption' }
            if ([String]::IsNullOrWhiteSpace($Config.Settings.QMHash)) { $missing += 'IPsecQMHash' }
            
            if ($missing.Count -gt 0) {
                Write-Log "ERROR: Cannot perform '$Operation': Missing Quick Mode crypto settings: $($missing -join ', ')" -Type Error
                Write-Host "`nMISSING REQUIREMENTS: Quick Mode Cryptography" -ForegroundColor Red
                Write-Host "Operation: $Operation" -ForegroundColor Yellow
                Write-Host "Missing Fields in <IPsec><Global>:" -ForegroundColor Yellow
                foreach ($field in $missing) {
                    Write-Host "  - $field" -ForegroundColor Red
                }
                Write-Host ""
                return $false
            }
            return $true
        }
        
        'Rules' {
            if (-not $Config.Rules -or $Config.Rules.Count -eq 0) {
                Write-Log "ERROR: Cannot perform '$Operation': No IPsec rules found in Config.xml" -Type Error
                Write-Host "`nMISSING REQUIREMENTS: IPsec Rules" -ForegroundColor Red
                Write-Host "Operation: $Operation" -ForegroundColor Yellow
                Write-Host "Required: At least one <Rule> element in <IPsec><Rules>" -ForegroundColor Yellow
                Write-Host "`nExample:" -ForegroundColor Cyan
                Write-Host "  <IPsec>" -ForegroundColor Gray
                Write-Host "    <Rules>" -ForegroundColor Gray
                Write-Host "      <Rule>" -ForegroundColor Gray
                Write-Host "        <Name>My-IPsec-Rule</Name>" -ForegroundColor Gray
                Write-Host "        <Inbound>Require</Inbound>" -ForegroundColor Gray
                Write-Host "        <Outbound>Require</Outbound>" -ForegroundColor Gray
                Write-Host "        <!-- ... other rule fields ... -->" -ForegroundColor Gray
                Write-Host "      </Rule>" -ForegroundColor Gray
                Write-Host "    </Rules>" -ForegroundColor Gray
                Write-Host "  </IPsec>" -ForegroundColor Gray
                Write-Host ""
                return $false
            }
            return $true
        }
        
        'MDTFields' {
            if (-not $Config.Settings.MDT -or $Config.Settings.MDT.Count -eq 0) {
                Write-Log "WARNING: '$Operation' requested but no MDT/Deployment fields found in Config.xml" -Type Warning
                Write-Host "`nOPTIONAL FEATURE NOT AVAILABLE: MDT/Deployment Fields" -ForegroundColor Yellow
                Write-Host "Operation: $Operation" -ForegroundColor Cyan
                Write-Host "Info: MDT fields are optional and used for deployment-friendly IPsec rules" -ForegroundColor Gray
                Write-Host "Required Fields (in <ESAEDomain> or <Domain>):" -ForegroundColor Yellow
                Write-Host "  - NetBIOSName or MDTNetBIOSName" -ForegroundColor Gray
                Write-Host "  - FQDNName or MDTFQDN" -ForegroundColor Gray
                Write-Host "  - DC1IP, DC2IP, WSUSIP, CAIP, etc." -ForegroundColor Gray
                Write-Host ""
                return $false
            }
            return $true
        }
        
        'DomainInfo' {
            # Domain info is always loaded by Read-IPsecConfiguration, so this is just a sanity check
            if (-not $Config.Settings) {
                Write-Log "ERROR: Cannot perform '$Operation': Configuration not loaded" -Type Error
                Write-Host "`nERROR: Configuration Not Loaded" -ForegroundColor Red
                Write-Host "Please load a configuration file first (Menu Option 2/3)" -ForegroundColor Yellow
                Write-Host ""
                return $false
            }
            return $true
        }
    }
    
    return $true
}

function Show-CurrentConfiguration {
    <#
    .SYNOPSIS
        Displays the currently loaded configuration.
    #>
    
    if (-not $Script:ConfigFileLoaded) {
        Write-Log "No configuration file loaded" -Type Warning
        return
    }
    
    Write-Log "Current Configuration Summary" -Type Header
    Write-Log "" -NoFile
    
    Write-Log "Cryptographic Settings:" -Type Title
    Write-Log "  CA Path: $($Script:CurrentConfig.Settings.CAPath)" -Type Info
    Write-Log "  CRL Check: $($Script:CurrentConfig.Settings.CrlCheck)" -Type Info
    Write-Log "  Exemptions: $($Script:CurrentConfig.Settings.Exemptions)" -Type Info
    Write-Log "  Encapsulation: $($Script:CurrentConfig.Settings.Encapsulation)" -Type Info
    Write-Log "  Key Exchange: $($Script:CurrentConfig.Settings.KeyExchange)" -Type Info
    Write-Log "  QM Hash: $($Script:CurrentConfig.Settings.QMHash)" -Type Info
    Write-Log "  MM Hash: $($Script:CurrentConfig.Settings.MMHash)" -Type Info
    Write-Log "  QM Encryption: $($Script:CurrentConfig.Settings.QMEncryption)" -Type Info
    Write-Log "  MM Encryption: $($Script:CurrentConfig.Settings.MMEncryption)" -Type Info
    Write-Log "  Key Module: $($Script:CurrentConfig.Settings.KeyModule)" -Type Info
    Write-Log "  Max Sessions: $($Script:CurrentConfig.Settings.MaxSessions)" -Type Info
    
    Write-Log "" -NoFile
    Write-Log "IPsec Rules ($($Script:CurrentConfig.Rules.Count)):" -Type Title
    foreach ($rule in $Script:CurrentConfig.Rules) {
        Write-Log "  [$($rule.Name)]" -Type Info
        Write-Log "    Protocol: $($rule.Protocol)" -Type Info
        Write-Log "    Inbound: $($rule.Inbound), Outbound: $($rule.Outbound)" -Type Info
        Write-Log "    Local: $($rule.LocalAddress -join ', ')" -Type Info
        Write-Log "    Remote: $($rule.RemoteAddress -join ', ')" -Type Info
        if ($rule.GPO) {
            Write-Log "    GPO: $($rule.GPO)" -Type Info
            Write-Log "    Location: $($rule.Location -join ', ')" -Type Info
        }
    }
}

#endregion

#region Active Directory IPsec Migration

<#
    Functions for reading IPsec settings from Active Directory IP Security container
    and migrating them between domains. This addresses the domain-to-domain IPsec
    configuration migration scenario.
#>

function Export-ADIPsecConfiguration {
    <#
    .SYNOPSIS
        Exports IPsec configuration from Active Directory IP Security container.
    .DESCRIPTION
        Reads IPsec policies, filter lists, and negotiation policies from the
        CN=IP Security container in Active Directory and exports them to XML format.
        This function reads the raw AD objects that define IPsec policies at the
        domain level.
    .PARAMETER SourceDomain
        FQDN of the source domain (e.g., contoso.com). If not specified, uses current domain.
    .PARAMETER OutputPath
        Path where the exported XML file will be saved.
    .PARAMETER Credential
        PSCredential object for accessing the source domain (optional).
    .OUTPUTS
        XML file containing the complete IPsec configuration from AD.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$SourceDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-Log "===========================================================" -Type Header
    Write-Log "EXPORT IPSEC CONFIGURATION FROM ACTIVE DIRECTORY" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Import Active Directory module
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            Write-Log "ERROR: ActiveDirectory module not available" -Type Error
            Write-Log "Install with: Install-WindowsFeature RSAT-AD-PowerShell" -Type Info
            return $null
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Get domain DN
        if ([string]::IsNullOrWhiteSpace($SourceDomain)) {
            $domainDN = (Get-ADDomain).DistinguishedName
            $SourceDomain = (Get-ADDomain).DNSRoot
        } else {
            $domainDN = "DC=" + ($SourceDomain -replace '\.', ',DC=')
        }
        
        Write-Log "Source Domain: $SourceDomain" -Type Info
        Write-Log "Domain DN: $domainDN" -Type Info
        Write-Log "" -NoFile
        
        # Construct IP Security container path
        $ipSecContainerDN = "CN=IP Security,CN=System,$domainDN"
        
        Write-Log "Reading from: $ipSecContainerDN" -Type Info
        Write-Log "" -NoFile
        
        # Build AD query parameters
        $adParams = @{
            'SearchBase' = $ipSecContainerDN
            'SearchScope' = 'OneLevel'
            'Properties' = '*'
            'ErrorAction' = 'Stop'
        }
        
        if ($Credential) {
            $adParams['Credential'] = $Credential
            if ($SourceDomain) {
                $adParams['Server'] = $SourceDomain
            }
        }
        
        # Read all IPsec objects from AD
        Write-Log "Querying IPsec policies..." -Type Info
        $ipsecPolicies = Get-ADObject @adParams -Filter "objectClass -eq 'ipsecPolicy'"
        Write-Log "  Found $($ipsecPolicies.Count) IPsec policies" -Type Success
        
        Write-Log "Querying IPsec filter lists..." -Type Info
        $ipsecFilters = Get-ADObject @adParams -Filter "objectClass -eq 'ipsecFilter'"
        Write-Log "  Found $($ipsecFilters.Count) IPsec filters" -Type Success
        
        Write-Log "Querying IPsec negotiation policies..." -Type Info
        $ipsecNegotiationPolicies = Get-ADObject @adParams -Filter "objectClass -eq 'ipsecNegotiationPolicy'"
        Write-Log "  Found $($ipsecNegotiationPolicies.Count) negotiation policies" -Type Success
        
        Write-Log "Querying IPsec NFA (Network Filter Actions)..." -Type Info
        $ipsecNFAs = Get-ADObject @adParams -Filter "objectClass -eq 'ipsecNFA'"
        Write-Log "  Found $($ipsecNFAs.Count) NFAs" -Type Success
        
        Write-Log "Querying IPsec ISAKMP policies..." -Type Info
        $ipsecISAKMP = Get-ADObject @adParams -Filter "objectClass -eq 'ipsecISAKMPPolicy'"
        Write-Log "  Found $($ipsecISAKMP.Count) ISAKMP policies" -Type Success
        
        Write-Log "" -NoFile
        
        # Build XML structure
        Write-Log "Building XML configuration..." -Type Info
        
        $xmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<IPsecADExport>
    <ExportInfo>
        <ExportDate>$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</ExportDate>
        <SourceDomain>$SourceDomain</SourceDomain>
        <SourceDN>$ipSecContainerDN</SourceDN>
        <ExportedBy>$env:USERNAME</ExportedBy>
        <ExportedFrom>$env:COMPUTERNAME</ExportedFrom>
    </ExportInfo>
    <Policies>
"@
        
        # Add IPsec Policies
        foreach ($policy in $ipsecPolicies) {
            $xmlContent += @"

        <ipsecPolicy>
            <Name>$([System.Security.SecurityElement]::Escape($policy.Name))</Name>
            <DN>$([System.Security.SecurityElement]::Escape($policy.DistinguishedName))</DN>
"@
            # Add all properties
            foreach ($prop in $policy.PSObject.Properties) {
                if ($prop.Value -and $prop.Name -notin @('PropertyNames', 'AddedProperties', 'RemovedProperties', 'ModifiedProperties', 'PropertyCount')) {
                    $escapedValue = [System.Security.SecurityElement]::Escape($prop.Value.ToString())
                    $xmlContent += "            <$($prop.Name)>$escapedValue</$($prop.Name)>`n"
                }
            }
            $xmlContent += "        </ipsecPolicy>`n"
        }
        
        $xmlContent += "    </Policies>`n    <Filters>`n"
        
        # Add IPsec Filters
        foreach ($filter in $ipsecFilters) {
            $xmlContent += @"

        <ipsecFilter>
            <Name>$([System.Security.SecurityElement]::Escape($filter.Name))</Name>
            <DN>$([System.Security.SecurityElement]::Escape($filter.DistinguishedName))</DN>
"@
            foreach ($prop in $filter.PSObject.Properties) {
                if ($prop.Value -and $prop.Name -notin @('PropertyNames', 'AddedProperties', 'RemovedProperties', 'ModifiedProperties', 'PropertyCount')) {
                    $escapedValue = [System.Security.SecurityElement]::Escape($prop.Value.ToString())
                    $xmlContent += "            <$($prop.Name)>$escapedValue</$($prop.Name)>`n"
                }
            }
            $xmlContent += "        </ipsecFilter>`n"
        }
        
        $xmlContent += "    </Filters>`n    <NegotiationPolicies>`n"
        
        # Add Negotiation Policies
        foreach ($negPolicy in $ipsecNegotiationPolicies) {
            $xmlContent += @"

        <ipsecNegotiationPolicy>
            <Name>$([System.Security.SecurityElement]::Escape($negPolicy.Name))</Name>
            <DN>$([System.Security.SecurityElement]::Escape($negPolicy.DistinguishedName))</DN>
"@
            foreach ($prop in $negPolicy.PSObject.Properties) {
                if ($prop.Value -and $prop.Name -notin @('PropertyNames', 'AddedProperties', 'RemovedProperties', 'ModifiedProperties', 'PropertyCount')) {
                    $escapedValue = [System.Security.SecurityElement]::Escape($prop.Value.ToString())
                    $xmlContent += "            <$($prop.Name)>$escapedValue</$($prop.Name)>`n"
                }
            }
            $xmlContent += "        </ipsecNegotiationPolicy>`n"
        }
        
        $xmlContent += "    </NegotiationPolicies>`n    <NFAs>`n"
        
        # Add NFAs
        foreach ($nfa in $ipsecNFAs) {
            $xmlContent += @"

        <ipsecNFA>
            <Name>$([System.Security.SecurityElement]::Escape($nfa.Name))</Name>
            <DN>$([System.Security.SecurityElement]::Escape($nfa.DistinguishedName))</DN>
"@
            foreach ($prop in $nfa.PSObject.Properties) {
                if ($prop.Value -and $prop.Name -notin @('PropertyNames', 'AddedProperties', 'RemovedProperties', 'ModifiedProperties', 'PropertyCount')) {
                    $escapedValue = [System.Security.SecurityElement]::Escape($prop.Value.ToString())
                    $xmlContent += "            <$($prop.Name)>$escapedValue</$($prop.Name)>`n"
                }
            }
            $xmlContent += "        </ipsecNFA>`n"
        }
        
        $xmlContent += "    </NFAs>`n    <ISAKMPPolicies>`n"
        
        # Add ISAKMP Policies
        foreach ($isakmp in $ipsecISAKMP) {
            $xmlContent += @"

        <ipsecISAKMPPolicy>
            <Name>$([System.Security.SecurityElement]::Escape($isakmp.Name))</Name>
            <DN>$([System.Security.SecurityElement]::Escape($isakmp.DistinguishedName))</DN>
"@
            foreach ($prop in $isakmp.PSObject.Properties) {
                if ($prop.Value -and $prop.Name -notin @('PropertyNames', 'AddedProperties', 'RemovedProperties', 'ModifiedProperties', 'PropertyCount')) {
                    $escapedValue = [System.Security.SecurityElement]::Escape($prop.Value.ToString())
                    $xmlContent += "            <$($prop.Name)>$escapedValue</$($prop.Name)>`n"
                }
            }
            $xmlContent += "        </ipsecISAKMPPolicy>`n"
        }
        
        $xmlContent += "    </ISAKMPPolicies>`n</IPsecADExport>"
        
        # Save to file
        Write-Log "Saving to: $OutputPath" -Type Info
        $xmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        
        Write-Log "" -NoFile
        Write-Log "Export completed successfully!" -Type Success
        Write-Log "Total objects exported:" -Type Info
        Write-Log "  - Policies: $($ipsecPolicies.Count)" -Type Info
        Write-Log "  - Filters: $($ipsecFilters.Count)" -Type Info
        Write-Log "  - Negotiation Policies: $($ipsecNegotiationPolicies.Count)" -Type Info
        Write-Log "  - NFAs: $($ipsecNFAs.Count)" -Type Info
        Write-Log "  - ISAKMP Policies: $($ipsecISAKMP.Count)" -Type Info
        Write-Log "" -NoFile
        Write-Log "File: $OutputPath" -Type Success
        
        return $OutputPath
        
    } catch {
        Write-Log "ERROR: Failed to export IPsec configuration: $($_.Exception.Message)" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
        return $null
    }
}

function Import-ADIPsecConfiguration {
    <#
    .SYNOPSIS
        Imports IPsec configuration to Active Directory IP Security container.
    .DESCRIPTION
        Reads exported IPsec configuration XML and creates the corresponding
        objects in the target domain's CN=IP Security container.
        WARNING: This is a complex operation that requires careful validation.
    .PARAMETER SourceXML
        Path to the exported IPsec configuration XML file.
    .PARAMETER TargetDomain
        FQDN of the target domain where configuration will be imported.
    .PARAMETER Credential
        PSCredential object for accessing the target domain (optional).
    .PARAMETER WhatIf
        Preview changes without actually creating objects.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SourceXML,
        
        [Parameter(Mandatory=$false)]
        [string]$TargetDomain,
        
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [switch]$WhatIf
    )
    
    Write-Log "===========================================================" -Type Header
    Write-Log "IMPORT IPSEC CONFIGURATION TO ACTIVE DIRECTORY" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Validate source file
        if (-not (Test-Path -Path $SourceXML)) {
            Write-Log "ERROR: Source XML file not found: $SourceXML" -Type Error
            return $false
        }
        
        # Import Active Directory module
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            Write-Log "ERROR: ActiveDirectory module not available" -Type Error
            return $false
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Load XML
        Write-Log "Loading configuration from: $SourceXML" -Type Info
        [xml]$config = Get-Content -Path $SourceXML -ErrorAction Stop
        
        # Get target domain DN
        if ([string]::IsNullOrWhiteSpace($TargetDomain)) {
            $targetDN = (Get-ADDomain).DistinguishedName
            $TargetDomain = (Get-ADDomain).DNSRoot
        } else {
            $targetDN = "DC=" + ($TargetDomain -replace '\.', ',DC=')
        }
        
        Write-Log "Target Domain: $TargetDomain" -Type Info
        Write-Log "Target DN: $targetDN" -Type Info
        Write-Log "" -NoFile
        
        # Display export info
        if ($config.IPsecADExport.ExportInfo) {
            Write-Log "Source Export Information:" -Type Info
            Write-Log "  Export Date: $($config.IPsecADExport.ExportInfo.ExportDate)" -Type Info
            Write-Log "  Source Domain: $($config.IPsecADExport.ExportInfo.SourceDomain)" -Type Info
            Write-Log "  Exported By: $($config.IPsecADExport.ExportInfo.ExportedBy)" -Type Info
        }
        Write-Log "" -NoFile
        
        # Construct target IP Security container path
        $targetIPSecDN = "CN=IP Security,CN=System,$targetDN"
        
        # Verify target container exists
        try {
            $containerExists = Get-ADObject -Identity $targetIPSecDN -ErrorAction SilentlyContinue
            if (-not $containerExists) {
                Write-Log "WARNING: IP Security container does not exist in target domain" -Type Warning
                Write-Log "Container: $targetIPSecDN" -Type Info
                
                if (-not $WhatIf) {
                    $create = Get-UserConfirmation -Message "Do you want to create the IP Security container?"
                    if ($create) {
                        # Note: Creating the container requires specific attributes
                        Write-Log "ERROR: Automatic container creation not yet implemented" -Type Error
                        Write-Log "Please create the container manually or contact your AD administrator" -Type Error
                        return $false
                    } else {
                        return $false
                    }
                }
            }
        } catch {
            Write-Log "ERROR: Unable to access target domain: $_" -Type Error
            return $false
        }
        
        Write-Log "===========================================================" -Type Header
        Write-Log "IMPORT SUMMARY" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        # Count objects
        $policyCount = if ($config.IPsecADExport.Policies.ipsecPolicy) { $config.IPsecADExport.Policies.ipsecPolicy.Count } else { 0 }
        $filterCount = if ($config.IPsecADExport.Filters.ipsecFilter) { $config.IPsecADExport.Filters.ipsecFilter.Count } else { 0 }
        $negPolCount = if ($config.IPsecADExport.NegotiationPolicies.ipsecNegotiationPolicy) { $config.IPsecADExport.NegotiationPolicies.ipsecNegotiationPolicy.Count } else { 0 }
        $nfaCount = if ($config.IPsecADExport.NFAs.ipsecNFA) { $config.IPsecADExport.NFAs.ipsecNFA.Count } else { 0 }
        $isakmpCount = if ($config.IPsecADExport.ISAKMPPolicies.ipsecISAKMPPolicy) { $config.IPsecADExport.ISAKMPPolicies.ipsecISAKMPPolicy.Count } else { 0 }
        
        Write-Log "Objects to import:" -Type Info
        Write-Log "  - IPsec Policies: $policyCount" -Type Info
        Write-Log "  - IPsec Filters: $filterCount" -Type Info
        Write-Log "  - Negotiation Policies: $negPolCount" -Type Info
        Write-Log "  - NFAs: $nfaCount" -Type Info
        Write-Log "  - ISAKMP Policies: $isakmpCount" -Type Info
        Write-Log "" -NoFile
        
        if ($WhatIf) {
            Write-Log "WhatIf mode - no changes will be made" -Type Warning
            Write-Log "" -NoFile
            return $true
        }
        
        # Confirm import
        Write-Log "WARNING: This will create IPsec objects in Active Directory" -Type Warning
        Write-Log "Target: $targetIPSecDN" -Type Warning
        Write-Log "" -NoFile
        
        $confirm = Get-UserConfirmation -Message "Do you want to proceed with the import?"
        if (-not $confirm) {
            Write-Log "Import cancelled by user" -Type Info
            return $false
        }
        
        Write-Log "" -NoFile
        Write-Log "Starting import..." -Type Info
        Write-Log "" -NoFile
        
        # Note: Actual AD object creation would go here
        # This requires careful mapping of XML properties to AD attributes
        # and proper handling of binary attributes (ipsecData, ipsecNegotiationPolicyAction, etc.)
        
        Write-Log "WARNING: Full AD object creation is not yet implemented" -Type Warning
        Write-Log "This function currently provides export/analysis capability only" -Type Warning
        Write-Log "" -NoFile
        Write-Log "To complete the import, you can:" -Type Info
        Write-Log "  1. Use the exported XML to understand the source configuration" -Type Info
        Write-Log "  2. Manually create matching policies using Group Policy Management" -Type Info
        Write-Log "  3. Use netsh ipsec commands to script the creation" -Type Info
        Write-Log "  4. Contact Microsoft Support for domain migration assistance" -Type Info
        
        return $true
        
    } catch {
        Write-Log "ERROR: Failed to import IPsec configuration: $($_.Exception.Message)" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
        return $false
    }
}

function Compare-ADIPsecConfiguration {
    <#
    .SYNOPSIS
        Compares IPsec configurations between two domains.
    .DESCRIPTION
        Reads IPsec settings from both source and target domains and
        identifies differences in policies, filters, and settings.
    .PARAMETER SourceDomain
        FQDN of source domain.
    .PARAMETER TargetDomain
        FQDN of target domain.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SourceDomain,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain
    )
    
    Write-Log "===========================================================" -Type Header
    Write-Log "COMPARE IPSEC CONFIGURATIONS" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    Write-Log "Source: $SourceDomain" -Type Info
    Write-Log "Target: $TargetDomain" -Type Info
    Write-Log "" -NoFile
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Get source domain objects
        $sourceDN = "DC=" + ($SourceDomain -replace '\.', ',DC=')
        $sourceIPSecDN = "CN=IP Security,CN=System,$sourceDN"
        
        Write-Log "Reading source domain..." -Type Info
        $sourceObjects = Get-ADObject -SearchBase $sourceIPSecDN -SearchScope OneLevel -Filter * -Properties * -Server $SourceDomain
        
        # Get target domain objects
        $targetDN = "DC=" + ($TargetDomain -replace '\.', ',DC=')
        $targetIPSecDN = "CN=IP Security,CN=System,$targetDN"
        
        Write-Log "Reading target domain..." -Type Info
        $targetObjects = Get-ADObject -SearchBase $targetIPSecDN -SearchScope OneLevel -Filter * -Properties * -Server $TargetDomain
        
        # Compare
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "COMPARISON RESULTS" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        # Group by object class
        $sourceByClass = $sourceObjects | Group-Object -Property objectClass
        $targetByClass = $targetObjects | Group-Object -Property objectClass
        
        Write-Log "Object Count by Type:" -Type Info
        Write-Log "" -NoFile
        
        $allClasses = ($sourceByClass.Name + $targetByClass.Name) | Select-Object -Unique
        
        foreach ($class in $allClasses) {
            $sourceCount = ($sourceByClass | Where-Object { $_.Name -eq $class }).Count
            $targetCount = ($targetByClass | Where-Object { $_.Name -eq $class }).Count
            
            if ($sourceCount -ne $targetCount) {
                Write-Host "  $class : " -NoNewline -ForegroundColor Yellow
                Write-Host "Source=$sourceCount, Target=$targetCount " -ForegroundColor Red -NoNewline
                Write-Host "[DIFFERENT]" -ForegroundColor Red
            } else {
                Write-Host "  $class : " -NoNewline -ForegroundColor Gray
                Write-Host "Source=$sourceCount, Target=$targetCount " -ForegroundColor Green -NoNewline
                Write-Host "[MATCH]" -ForegroundColor Green
            }
        }
        
        Write-Log "" -NoFile
        Write-Log "Comparison completed" -Type Success
        
        return $true
        
    } catch {
        Write-Log "ERROR: Comparison failed: $($_.Exception.Message)" -Type Error
        return $false
    }
}

#endregion

#region Menu System

<#
    Interactive menu system that adapts based on environment mode.
    Local mode shows simplified options, Enterprise mode shows full GPO options.
#>

function Show-MainMenu {
    <#
    .SYNOPSIS
        Displays the main menu based on current environment mode.
    #>
    
    Clear-Host
    
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor $Script:Colors.Header
    Write-Host "  $Script:ScriptName v$Script:Version" -ForegroundColor $Script:Colors.Title
    Write-Host "  Client: $Script:ClientName" -ForegroundColor $Script:Colors.Info
    Write-Host "===========================================================" -ForegroundColor $Script:Colors.Header
    Write-Host ""
    Write-Host "  Mode: " -NoNewline -ForegroundColor $Script:Colors.Info
    Write-Host "$Script:EnvironmentMode" -ForegroundColor $Script:Colors.Success
    Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor $Script:Colors.Info
    Write-Host "  User: $env:USERNAME" -ForegroundColor $Script:Colors.Info
    Write-Host "  Log: $Script:LogFilePath" -ForegroundColor $Script:Colors.Info
    Write-Host ""
    
    if ($Script:ConfigFileLoaded) {
        Write-Host "  [OK] Configuration loaded: $($Script:CurrentConfig.Rules.Count) rules" -ForegroundColor $Script:Colors.Success
    } else {
        Write-Host "  [!] No configuration loaded" -ForegroundColor $Script:Colors.Warning
    }
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor $Script:Colors.Header
    Write-Host ""
    
    if ($Script:EnvironmentMode -eq 'Enterprise') {
        Show-EnterpriseMenu
    } else {
        Show-LocalMenu
    }
}

function Show-LocalMenu {
    <#
    .SYNOPSIS
        Displays menu for Local mode (standalone server).
    #>
    
    Write-Host "LOCAL MODE - Standalone Server Configuration" -ForegroundColor $Script:Colors.Title
    Write-Host ""
    Write-Host "INFORMATION and TESTING" -ForegroundColor $Script:Colors.Menu
    Write-Host "  1.  View Current IPsec Configuration" -ForegroundColor $Script:Colors.Menu
    Write-Host "  2.  Load/Test XML Configuration File" -ForegroundColor $Script:Colors.Menu
    Write-Host "  3.  View IPsec Statistics and Status" -ForegroundColor $Script:Colors.Menu
    Write-Host "  4.  Show Loaded Configuration" -ForegroundColor $Script:Colors.Menu
    Write-Host ""
    Write-Host "LOCAL CONFIGURATION" -ForegroundColor $Script:Colors.Menu
    Write-Host "  5.  Remove All IPsec Rules" -ForegroundColor Yellow
    Write-Host "  6.  Configure Windows Firewall" -ForegroundColor $Script:Colors.Menu
    Write-Host "  7.  Create Phase 1 Authentication" -ForegroundColor $Script:Colors.Menu
    Write-Host "  8.  Create Main Mode Crypto Sets" -ForegroundColor $Script:Colors.Menu
    Write-Host "  9.  Create Quick Mode Crypto Sets" -ForegroundColor $Script:Colors.Menu
    Write-Host "  10. Apply IPsec Rules" -ForegroundColor $Script:Colors.Menu
    Write-Host "  11. Apply Complete Configuration (All Steps)" -ForegroundColor Green
    Write-Host ""
    Write-Host "UTILITIES" -ForegroundColor $Script:Colors.Menu
    Write-Host "  12. Export Current Configuration to XML" -ForegroundColor $Script:Colors.Menu
    Write-Host "  13. Generate HTML Report" -ForegroundColor $Script:Colors.Menu
    Write-Host "  14. Backup Current Settings" -ForegroundColor $Script:Colors.Menu
    Write-Host "  15. Restore from Backup" -ForegroundColor $Script:Colors.Menu
    Write-Host "  16. View Firewall Logs" -ForegroundColor $Script:Colors.Menu
    Write-Host ""
    Write-Host "TROUBLESHOOTING" -ForegroundColor $Script:Colors.Menu
    Write-Host "  17. Test IPsec Connectivity to Remote Host" -ForegroundColor $Script:Colors.Menu
    Write-Host "  18. View IPsec Event Logs" -ForegroundColor $Script:Colors.Menu
    Write-Host "  19. View Certificate Information" -ForegroundColor $Script:Colors.Menu
    Write-Host ""
    Write-Host "ANALYSIS" -ForegroundColor $Script:Colors.Menu
    Write-Host "  20. Preview Changes (WhatIf Mode)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  0.  Exit" -ForegroundColor $Script:Colors.Menu
    Write-Host ""
}

function Show-EnterpriseMenu {
    <#
    .SYNOPSIS
        Displays menu for Enterprise mode (GPO/Active Directory).
    #>
    
    Write-Host "ENTERPRISE MODE - GPO/Active Directory Configuration" -ForegroundColor $Script:Colors.Title
    Write-Host ""
    Write-Host "INFORMATION and TESTING" -ForegroundColor $Script:Colors.Menu
    Write-Host "  1.  View Current Local IPsec Configuration" -ForegroundColor $Script:Colors.Menu
    Write-Host "  2.  View GPO IPsec Configuration" -ForegroundColor $Script:Colors.Menu
    Write-Host "  3.  Load/Test XML Configuration File" -ForegroundColor $Script:Colors.Menu
    Write-Host "  4.  View IPsec Statistics and Status" -ForegroundColor $Script:Colors.Menu
    Write-Host "  5.  Show Loaded Configuration" -ForegroundColor $Script:Colors.Menu
    Write-Host ""
    Write-Host "LOCAL CONFIGURATION (This Server Only)" -ForegroundColor $Script:Colors.Menu
    Write-Host "  6.  Remove All Local IPsec Rules" -ForegroundColor Yellow
    Write-Host "  7.  Configure Local Windows Firewall" -ForegroundColor $Script:Colors.Menu
    Write-Host "  8.  Apply Local IPsec Configuration" -ForegroundColor $Script:Colors.Menu
    Write-Host ""
    Write-Host "DOMAIN CONFIGURATION (GPO/Active Directory)" -ForegroundColor $Script:Colors.Menu
    Write-Host "  9.  List Existing IPsec GPOs" -ForegroundColor $Script:Colors.Menu
    Write-Host "  10. Create/Update IPsec GPOs" -ForegroundColor $Script:Colors.Menu
    Write-Host "  11. Link GPOs to OUs" -ForegroundColor $Script:Colors.Menu
    Write-Host "  12. Remove IPsec GPOs" -ForegroundColor Yellow
    Write-Host "  13. Apply Complete GPO Configuration" -ForegroundColor Green
    Write-Host "  14. Test GPO Replication Status" -ForegroundColor $Script:Colors.Menu
    Write-Host ""
    Write-Host "AD IPSEC MIGRATION (Domain-to-Domain)" -ForegroundColor Cyan
    Write-Host "  21. Export IPsec from AD IP Security Container" -ForegroundColor $Script:Colors.Menu
    Write-Host "  22. Import IPsec to AD IP Security Container" -ForegroundColor $Script:Colors.Menu
    Write-Host "  23. Compare IPsec Between Domains" -ForegroundColor $Script:Colors.Menu
    Write-Host ""
    Write-Host "UTILITIES" -ForegroundColor $Script:Colors.Menu
    Write-Host "  15. Export Current Configuration to XML" -ForegroundColor $Script:Colors.Menu
    Write-Host "  16. Generate HTML Report" -ForegroundColor $Script:Colors.Menu
    Write-Host "  17. Backup Current Settings" -ForegroundColor $Script:Colors.Menu
    Write-Host "  18. Restore from Backup" -ForegroundColor $Script:Colors.Menu
    Write-Host "  19. View Firewall Logs" -ForegroundColor $Script:Colors.Menu
    Write-Host ""
    Write-Host "ANALYSIS" -ForegroundColor $Script:Colors.Menu
    Write-Host "  20. Preview Changes (WhatIf Mode)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  0.  Exit" -ForegroundColor $Script:Colors.Menu
    Write-Host ""
}

function Get-MenuItemDescription {
    <#
    .SYNOPSIS
        Returns the descriptive text for a menu item.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [int]$Choice,
        
        [Parameter(Mandatory=$true)]
        [string]$Mode
    )
    
    if ($Mode -eq 'Enterprise') {
        $descriptions = @{
            0 = "Exit"
            1 = "View Current Local IPsec Configuration"
            2 = "View GPO IPsec Configuration"
            3 = "Load/Test XML Configuration File"
            4 = "View IPsec Statistics and Status"
            5 = "Show Loaded Configuration"
            6 = "Remove All Local IPsec Rules"
            7 = "Configure Local Windows Firewall"
            8 = "Apply Local IPsec Configuration"
            9 = "List Existing IPsec GPOs"
            10 = "Create/Update IPsec GPOs"
            11 = "Link GPOs to OUs"
            12 = "Remove IPsec GPOs"
            13 = "Apply Complete GPO Configuration"
            14 = "Test GPO Replication Status"
            15 = "Export Current Configuration to XML"
            16 = "Generate HTML Report"
            17 = "Backup Current Settings"
            18 = "Restore from Backup"
            19 = "View Firewall Logs"
            20 = "Preview Changes (WhatIf Mode)"
            21 = "Export IPsec from AD IP Security Container"
            22 = "Import IPsec to AD IP Security Container"
            23 = "Compare IPsec Between Domains"
        }
    } else {
        $descriptions = @{
            0 = "Exit"
            1 = "View Current IPsec Configuration"
            2 = "Load/Test XML Configuration File"
            3 = "View IPsec Statistics and Status"
            4 = "Show Loaded Configuration"
            5 = "Remove All IPsec Rules"
            6 = "Configure Windows Firewall"
            7 = "Create Phase 1 Authentication"
            8 = "Create Main Mode Crypto Sets"
            9 = "Create Quick Mode Crypto Sets"
            10 = "Apply IPsec Rules"
            11 = "Apply Complete Configuration (All Steps)"
            12 = "Export Current Configuration to XML"
            13 = "Generate HTML Report"
            14 = "Backup Current Settings"
            15 = "Restore from Backup"
            16 = "View Firewall Logs"
            17 = "Test IPsec Connectivity to Remote Host"
            18 = "View IPsec Event Logs"
            19 = "View Certificate Information"
            20 = "Preview Changes (WhatIf Mode)"
        }
    }
    
    if ($descriptions.ContainsKey($Choice)) {
        return $descriptions[$Choice]
    } else {
        return "Unknown Option"
    }
}

function Get-MenuChoice {
    <#
    .SYNOPSIS
        Prompts user for menu selection and validates input.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [int]$MaxChoice
    )
    
    Write-Host ""
    $choice = Read-Host "Select option (0-$MaxChoice)"
    
    # Validate input
    if ($choice -match '^\d+$' -and [int]$choice -ge 0 -and [int]$choice -le $MaxChoice) {
        return [int]$choice
    } else {
        Write-Log "Invalid selection. Please enter a number between 0 and $MaxChoice" -Type Warning
        return -1
    }
}

function Invoke-MenuAction {
    <#
    .SYNOPSIS
        Executes the selected menu action.
    .DESCRIPTION
        Dispatches menu selections to appropriate functions based on mode.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [int]$Choice
    )
    
    Write-LogSeparator
    Write-Log "User selected option: $Choice" -Type Info -NoConsole
    
    if ($Script:EnvironmentMode -eq 'Enterprise') {
        Invoke-EnterpriseAction -Choice $Choice
    } else {
        Invoke-LocalAction -Choice $Choice
    }
}

function Invoke-LocalAction {
    <#
    .SYNOPSIS
        Handles Local mode menu actions.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [int]$Choice
    )
    
    switch ($Choice) {
        0 {
            # Exit
            Write-Log "User selected Exit" -Type Info
            return $false
        }
        1 {
            # View Current IPsec Configuration
            Write-Log "Viewing current IPsec configuration..." -Type Title
            Show-LocalIPsecConfiguration
        }
        2 {
            # Load/Test XML Configuration
            Write-Log "Loading XML configuration..." -Type Title
            Invoke-LoadConfiguration
        }
        3 {
            # View IPsec Statistics
            Write-Log "Viewing IPsec statistics..." -Type Title
            Show-IPsecStatistics
        }
        4 {
            # Show Loaded Configuration
            Show-CurrentConfiguration
        }
        5 {
            # Remove All IPsec Rules
            Invoke-RemoveLocalIPsec
        }
        6 {
            # Configure Windows Firewall
            Invoke-ConfigureFirewall
        }
        7 {
            # Create Phase 1 Authentication
            Invoke-CreatePhase1Auth
        }
        8 {
            # Create Main Mode Crypto
            Invoke-CreateMainModeCrypto
        }
        9 {
            # Create Quick Mode Crypto
            Invoke-CreateQuickModeCrypto
        }
        10 {
            # Apply IPsec Rules
            Invoke-ApplyIPsecRules
        }
        11 {
            # Apply Complete Configuration
            Invoke-ApplyCompleteLocal
        }
        12 {
            # Export Configuration
            Invoke-ExportConfiguration
        }
        13 {
            # Generate HTML Report
            Invoke-GenerateReport
        }
        14 {
            # Backup Settings
            Invoke-BackupSettings
        }
        15 {
            # Restore from Backup
            Invoke-RestoreFromBackup
        }
        16 {
            # View Firewall Logs
            Invoke-ViewFirewallLogs
        }
        17 {
            # Test IPsec Connectivity
            Invoke-TestIPsecConnectivity
        }
        18 {
            # View IPsec Event Logs
            Invoke-ViewIPsecEvents
        }
        19 {
            # View Certificate Information
            Invoke-ViewCertificates
        }
        20 {
            # Preview Changes (WhatIf)
            Invoke-PreviewChanges
        }
        default {
            Write-Log "Invalid menu option: $Choice" -Type Error
        }
    }
    
    return $true
}

function Invoke-EnterpriseAction {
    <#
    .SYNOPSIS
        Handles Enterprise mode menu actions.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [int]$Choice
    )
    
    switch ($Choice) {
        0 {
            # Exit
            Write-Log "User selected Exit" -Type Info
            return $false
        }
        1 {
            # View Local Configuration
            Write-Log "Viewing local IPsec configuration..." -Type Title
            Show-LocalIPsecConfiguration
        }
        2 {
            # View GPO Configuration
            Write-Log "Viewing GPO IPsec configuration..." -Type Title
            Show-GPOIPsecConfiguration
        }
        3 {
            # Load/Test XML
            Write-Log "Loading XML configuration..." -Type Title
            Invoke-LoadConfiguration
        }
        4 {
            # View Statistics
            Write-Log "Viewing IPsec statistics..." -Type Title
            Show-IPsecStatistics
        }
        5 {
            # Show Loaded Config
            Show-CurrentConfiguration
        }
        6 {
            # Remove Local IPsec
            Invoke-RemoveLocalIPsec
        }
        7 {
            # Configure Local Firewall
            Invoke-ConfigureFirewall
        }
        8 {
            # Apply Local Configuration
            Invoke-ApplyCompleteLocal
        }
        9 {
            # List GPOs
            Invoke-ListGPOs
        }
        10 {
            # Create/Update GPOs
            Invoke-CreateUpdateGPOs
        }
        11 {
            # Link GPOs
            Invoke-LinkGPOs
        }
        12 {
            # Remove GPOs
            Invoke-RemoveGPOs
        }
        13 {
            # Apply Complete GPO Config
            Invoke-ApplyCompleteGPO
        }
        14 {
            # Test GPO Replication
            Invoke-TestGPOReplication
        }
        15 {
            # Export Configuration
            Invoke-ExportConfiguration
        }
        16 {
            # Generate Report
            Invoke-GenerateReport
        }
        17 {
            # Backup Settings
            Invoke-BackupSettings
        }
        18 {
            # Restore from Backup
            Invoke-RestoreFromBackup
        }
        19 {
            # View Logs
            Invoke-ViewFirewallLogs
        }
        20 {
            # Preview Changes (WhatIf)
            Invoke-PreviewChanges
        }
        21 {
            # Export IPsec from AD
            Invoke-ExportADIPsec
        }
        22 {
            # Import IPsec to AD
            Invoke-ImportADIPsec
        }
        23 {
            # Compare IPsec Between Domains
            Invoke-CompareADIPsec
        }
        default {
            Write-Log "Invalid menu option: $Choice" -Type Error
        }
    }
    
    return $true
}

#endregion

Write-Host "$Script:ScriptName v$Script:Version" -ForegroundColor Cyan
Write-Host "Initializing..." -ForegroundColor Gray
Write-Host ""

# Initialize logging
if ([String]::IsNullOrEmpty($LogFile)) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Script:LogFilePath = Join-Path -Path $PSScriptRoot -ChildPath "IPsec-Utility-Log-$timestamp.txt"
} else {
    $Script:LogFilePath = $LogFile
}

[void](Initialize-Logging)

# Detect environment
$envReady = Initialize-Environment

if (-not $envReady) {
    Write-Log "Environment initialization failed. Exiting." -Type Error
    Pause-ForUser
    exit 1
}

Write-Log "Initialization complete" -Type Success
Write-Log "Log file: $Script:LogFilePath" -Type Info

# Placeholder for main menu - will be added in next section
#region Menu Action Stubs

<#
    Placeholder functions for menu actions.
    These will be implemented with full functionality in subsequent updates.
#>

function Invoke-LoadConfiguration {
    Write-Log "Loading XML configuration file..." -Type Title
    
    if (-not [String]::IsNullOrEmpty($ConfigFile) -and (Test-Path $ConfigFile)) {
        $config = Read-IPsecConfiguration -Path $ConfigFile
        if ($config) {
            Write-Log "Configuration loaded successfully from: $ConfigFile" -Type Success
        }
    } else {
        Write-Host ""
        $path = Read-Host "Enter path to XML configuration file"
        if (Test-Path $path) {
            $config = Read-IPsecConfiguration -Path $path
            if ($config) {
                $script:ConfigFile = $path
            }
        } else {
            Write-Log "File not found: $path" -Type Error
        }
    }
    
    Pause-ForUser
}

function Show-LocalIPsecConfiguration {
    Write-Log "Retrieving local IPsec configuration..." -Type Info
    try {
        $rules = Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        Write-Log "Local IPsec Rules: $($rules.Count)" -Type Info
        foreach ($rule in $rules) {
            Write-Log "  - $($rule.DisplayName)" -Type Info
        }
    } catch {
        Write-Log "Error retrieving IPsec configuration: $_" -Type Error
    }
    Pause-ForUser
}

function Show-GPOIPsecConfiguration {
    <#
    .SYNOPSIS
        Displays IPsec configuration from Group Policy Objects.
    .DESCRIPTION
        Prompts for GPO name and displays its IPsec/Firewall configuration,
        comparing with local settings to identify differences.
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "VIEW GPO IPSEC CONFIGURATION" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Check if GroupPolicy module is available
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-Log "ERROR: GroupPolicy PowerShell module not installed" -Type Error
            Write-Log "Install with: Add-WindowsFeature GPMC" -Type Info
            Pause-ForUser
            return
        }
        
        Import-Module GroupPolicy -ErrorAction Stop
        
        # Prompt for GPO name
        $gpoName = Read-Host "Enter GPO name (or partial name to search)"
        
        if ([string]::IsNullOrWhiteSpace($gpoName)) {
            Write-Log "ERROR: GPO name cannot be empty" -Type Error
            Pause-ForUser
            return
        }
        
        # Search for GPO
        Write-Log "Searching for GPO: $gpoName" -Type Info
        $matchingGPOs = Get-GPO -All -ErrorAction Stop | Where-Object { $_.DisplayName -like "*$gpoName*" }
        
        if ($matchingGPOs.Count -eq 0) {
            Write-Log "ERROR: No GPOs found matching '$gpoName'" -Type Error
            Pause-ForUser
            return
        } elseif ($matchingGPOs.Count -gt 1) {
            Write-Log "Multiple GPOs found:" -Type Warning
            Write-Log "" -NoFile
            $index = 1
            foreach ($gpo in $matchingGPOs) {
                Write-Host "  [$index] " -NoNewline -ForegroundColor Cyan
                Write-Host $gpo.DisplayName -ForegroundColor White
                $index++
            }
            Write-Log "" -NoFile
            $selection = Read-Host "Select GPO number (1-$($matchingGPOs.Count))"
            
            if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $matchingGPOs.Count) {
                $selectedGPO = $matchingGPOs[[int]$selection - 1]
            } else {
                Write-Log "ERROR: Invalid selection" -Type Error
                Pause-ForUser
                return
            }
        } else {
            $selectedGPO = $matchingGPOs[0]
        }
        
        Show-GPOIPsecDetails -GPOName $selectedGPO.DisplayName -GPOId $selectedGPO.Id
        
    } catch {
        Write-Log "ERROR: Failed to retrieve GPO configuration: $($_.Exception.Message)" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error
    }
    
    Pause-ForUser
}

function Show-GPOIPsecDetails {
    <#
    .SYNOPSIS
        Helper function to display detailed GPO IPsec configuration.
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$GPOName,
        
        [Parameter(Mandatory=$true)]
        [guid]$GPOId
    )
    
    Write-Log "" -NoFile
    Write-Log "===========================================================" -Type Header
    Write-Log "GPO: $GPOName" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Get GPO report in XML format
        $gpoReport = [xml](Get-GPOReport -Guid $GPOId -ReportType Xml -ErrorAction Stop)
        
        # Extract IPsec rules
        $connectionSecurityRules = $gpoReport.SelectNodes("//q1:ConnectionSecurityRules/q1:ConnectionSecurityRule")
        $firewallRules = $gpoReport.SelectNodes("//q1:FirewallRules/q1:FirewallRule")
        $globalSettings = $gpoReport.SelectNodes("//q1:GlobalSettings")
        
        # Display Connection Security (IPsec) Rules
        if ($connectionSecurityRules.Count -gt 0) {
            Write-Log "CONNECTION SECURITY RULES: $($connectionSecurityRules.Count)" -Type Info
            Write-Log "" -NoFile
            
            foreach ($rule in $connectionSecurityRules) {
                Write-Host "  Rule: " -NoNewline -ForegroundColor Cyan
                Write-Host $rule.Name -ForegroundColor White
                Write-Log "    Enabled:        $($rule.Enabled)" -Type Info
                Write-Log "    Direction:      $($rule.Direction)" -Type Info
                Write-Log "    Local Address:  $($rule.LocalAddress)" -Type Info
                Write-Log "    Remote Address: $($rule.RemoteAddress)" -Type Info
                Write-Log "    Protocol:       $($rule.Protocol)" -Type Info
                Write-Log "    Authentication: $($rule.Authentication)" -Type Info
                Write-Log "    Encryption:     $($rule.Encryption)" -Type Info
                Write-Log "" -NoFile
            }
        } else {
            Write-Log "No Connection Security Rules found in this GPO" -Type Warning
            Write-Log "" -NoFile
        }
        
        # Display Firewall Rules
        if ($firewallRules.Count -gt 0) {
            Write-Log "FIREWALL RULES: $($firewallRules.Count)" -Type Info
            Write-Log "" -NoFile
            
            $index = 1
            foreach ($rule in $firewallRules | Select-Object -First 10) {
                Write-Host "  [$index] " -NoNewline -ForegroundColor Cyan
                Write-Host $rule.Name -ForegroundColor White
                Write-Log "    Enabled:   $($rule.Enabled)" -Type Info
                Write-Log "    Direction: $($rule.Direction)" -Type Info
                Write-Log "    Action:    $($rule.Action)" -Type Info
                Write-Log "    Protocol:  $($rule.Protocol)" -Type Info
                Write-Log "" -NoFile
                $index++
            }
            
            if ($firewallRules.Count -gt 10) {
                Write-Log "... and $($firewallRules.Count - 10) more firewall rules" -Type Info
                Write-Log "" -NoFile
            }
        } else {
            Write-Log "No Firewall Rules found in this GPO" -Type Warning
            Write-Log "" -NoFile
        }
        
        # Display Global Settings
        if ($globalSettings.Count -gt 0) {
            Write-Log "GLOBAL IPSEC SETTINGS:" -Type Info
            Write-Log "" -NoFile
            
            foreach ($setting in $globalSettings) {
                if ($setting.HasChildNodes) {
                    foreach ($child in $setting.ChildNodes) {
                        Write-Log "  $($child.Name): $($child.InnerText)" -Type Info
                    }
                }
            }
            Write-Log "" -NoFile
        }
        
        # Compare with local configuration
        Write-Log "===========================================================" -Type Header
        Write-Log "COMPARISON WITH LOCAL CONFIGURATION" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        # Get local IPsec rules
        $localIPsecRules = Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        $localFirewallRules = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        
        Write-Log "Local IPsec Rules:     $($localIPsecRules.Count)" -Type Info
        Write-Log "GPO IPsec Rules:       $($connectionSecurityRules.Count)" -Type Info
        Write-Log "Local Firewall Rules:  $($localFirewallRules.Count)" -Type Info
        Write-Log "GPO Firewall Rules:    $($firewallRules.Count)" -Type Info
        Write-Log "" -NoFile
        
        # Check for effective policy
        Write-Log "To view effective policy applied to this computer, run:" -Type Info
        Write-Log "  Get-NetIPsecRule -PolicyStore RSOP" -Type Info
        Write-Log "" -NoFile
        
    } catch {
        Write-Log "ERROR: Failed to retrieve GPO details: $($_.Exception.Message)" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error
    }
}

function Show-IPsecStatistics {
    Write-Log "IPsec Statistics:" -Type Title
    try {
        $mainMode = Get-NetIPsecMainModeSA -ErrorAction SilentlyContinue
        $quickMode = Get-NetIPsecQuickModeSA -ErrorAction SilentlyContinue
        Write-Log "  Main Mode SAs: $($mainMode.Count)" -Type Info
        Write-Log "  Quick Mode SAs: $($quickMode.Count)" -Type Info
    } catch {
        Write-Log "Error retrieving statistics: $_" -Type Error
    }
    Pause-ForUser
}

function Invoke-RemoveLocalIPsec {
    if (Get-DoubleConfirmation -Operation "REMOVE ALL LOCAL IPSEC RULES AND CONFIGURATION") {
        Write-Log "Removing all local IPsec configuration..." -Type Warning
        try {
            Remove-NetIPsecRule -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue
            Remove-NetIPsecPhase1AuthSet -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue
            Remove-NetIPsecMainModeCryptoSet -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue
            Remove-NetIPsecMainModeRule -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue
            Remove-NetIPsecQuickModeCryptoSet -All -PolicyStore ActiveStore -ErrorAction SilentlyContinue
            Write-Log "Local IPsec configuration removed successfully" -Type Success
        } catch {
            Write-Log "Error removing IPsec configuration: $_" -Type Error
        }
    }
    Pause-ForUser
}

function Invoke-ConfigureFirewall {
    <#
    .SYNOPSIS
        Configures Windows Firewall settings for IPsec operation.
    #>
    Write-Log "Configuring Windows Firewall..." -Type Title
    
    if (-not $Script:ConfigFileLoaded) {
        Write-Log "ERROR: No configuration loaded. Please load a configuration file first." -Type Error
        Pause-ForUser
        return
    }
    
    try {
        $settings = $Script:CurrentConfig.Settings
        
        Write-Log "Applying firewall profile settings..." -Type Info
        
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
        
        Write-Log "Firewall profiles configured successfully" -Type Success
        Write-Log "  - All profiles enabled" -Type Info
        Write-Log "  - Default inbound: Block" -Type Info
        Write-Log "  - Default outbound: Allow" -Type Info
        Write-Log "  - Stealth mode: Enabled" -Type Info
        Write-Log "  - Logging: Enabled (32MB max)" -Type Info
        
        # Configure firewall-specific settings for IPsec
        $exemptions = if ($settings.Exemptions -eq 'None') { 'None' } else { $settings.Exemptions }
        $crlCheck = if ($settings.CrlCheck -eq 'RequireCrlCheck') { 'RequireCrlCheck' } else { 'None' }
        
        Set-NetFirewallSetting -Exemptions $exemptions `
                               -CertValidationLevel $crlCheck `
                               -ErrorAction Stop
        
        Write-Log "Firewall IPsec settings configured" -Type Success
        Write-Log "  - Exemptions: $exemptions" -Type Info
        Write-Log "  - CRL Check: $crlCheck" -Type Info
        
        Write-Log "" -NoFile
        Write-Log "Windows Firewall configuration completed successfully!" -Type Success
        
    } catch {
        Write-Log "ERROR: Failed to configure Windows Firewall: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-CreatePhase1Auth {
    <#
    .SYNOPSIS
        Creates Phase 1 authentication set using computer certificates.
    #>
    Write-Log "Creating Phase 1 Authentication Set..." -Type Title
    
    if (-not $Script:ConfigFileLoaded) {
        Write-Log "ERROR: No configuration loaded. Please load a configuration file first." -Type Error
        Pause-ForUser
        return
    }
    
    # Validate required configuration (chunk-based validation)
    if (-not (Test-ConfigRequirement -RequirementType 'CAPath' -Config $Script:CurrentConfig -Operation 'Create Phase1 Authentication')) {
        Pause-ForUser
        return
    }
    
    try {
        $settings = $Script:CurrentConfig.Settings
        $authSetName = "IPsec Computer Certificate Auth"
        
        # Check if auth set already exists
        $existing = Get-NetIPsecPhase1AuthSet -DisplayName $authSetName `
                                              -PolicyStore ActiveStore `
                                              -ErrorAction SilentlyContinue
        
        if ($existing) {
            Write-Log "Phase 1 authentication set already exists" -Type Info
            $overwrite = Get-UserConfirmation -Message "Do you want to recreate it?"
            
            if ($overwrite) {
                Remove-NetIPsecPhase1AuthSet -DisplayName $authSetName `
                                            -PolicyStore ActiveStore `
                                            -ErrorAction Stop
                Write-Log "Existing authentication set removed" -Type Info
            } else {
                Write-Log "Using existing authentication set" -Type Info
                Pause-ForUser
                return
            }
        }
        
        Write-Log "Creating authentication proposal..." -Type Info
        Write-Log "  - Using computer certificate authentication" -Type Info
        Write-Log "  - CA Path: $($settings.CAPath)" -Type Info
        
        # Create authentication proposal
        $authProposal = New-NetIPsecAuthProposal -Machine `
                                                 -Cert `
                                                 -Authority $settings.CAPath `
                                                 -AuthorityType Root `
                                                 -ErrorAction Stop
        
        # Create authentication set
        [void](New-NetIPsecPhase1AuthSet -DisplayName $authSetName `
                                            -Proposal $authProposal `
                                            -PolicyStore ActiveStore `
                                            -ErrorAction Stop)
        
        Write-Log "" -NoFile
        Write-Log "Phase 1 authentication set created successfully!" -Type Success
        Write-Log "  - Name: $authSetName" -Type Info
        Write-Log "  - Type: Computer Certificate" -Type Info
        Write-Log "  - CA: $($settings.CAPath)" -Type Info
        
    } catch {
        Write-Log "ERROR: Failed to create Phase 1 authentication set: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-CreateMainModeCrypto {
    <#
    .SYNOPSIS
        Creates Main Mode (Phase 1) cryptographic sets.
    #>
    Write-Log "Creating Main Mode Cryptographic Set..." -Type Title
    
    if (-not $Script:ConfigFileLoaded) {
        Write-Log "ERROR: No configuration loaded. Please load a configuration file first." -Type Error
        Pause-ForUser
        return
    }
    
    # Validate required configuration (chunk-based validation)
    if (-not (Test-ConfigRequirement -RequirementType 'MMCrypto' -Config $Script:CurrentConfig -Operation 'Create Main Mode Cryptography')) {
        Pause-ForUser
        return
    }
    
    try {
        $settings = $Script:CurrentConfig.Settings
        $cryptoSetName = "IPsec Main Mode Crypto"
        $mmRuleName = "IPsec Main Mode Rule"
        
        # Check if crypto set already exists
        $existing = Get-NetIPsecMainModeCryptoSet -DisplayName $cryptoSetName `
                                                  -PolicyStore ActiveStore `
                                                  -ErrorAction SilentlyContinue
        
        if ($existing) {
            Write-Log "Main Mode crypto set already exists" -Type Info
            $overwrite = Get-UserConfirmation -Message "Do you want to recreate it?"
            
            if ($overwrite) {
                Remove-NetIPsecMainModeCryptoSet -DisplayName $cryptoSetName `
                                                -PolicyStore ActiveStore `
                                                -ErrorAction Stop
                Write-Log "Existing crypto set removed" -Type Info
            } else {
                Write-Log "Using existing crypto set" -Type Info
                Pause-ForUser
                return
            }
        }
        
        Write-Log "Creating Main Mode cryptographic proposal..." -Type Info
        Write-Log "  - Encryption: $($settings.MMEncryption)" -Type Info
        Write-Log "  - Hash: $($settings.MMHash)" -Type Info
        Write-Log "  - Key Exchange: $($settings.KeyExchange)" -Type Info
        
        # Create cryptographic proposal
        $cryptoProposal = New-NetIPsecMainModeCryptoProposal `
                            -Encryption $settings.MMEncryption `
                            -Hash $settings.MMHash `
                            -KeyExchange $settings.KeyExchange `
                            -ErrorAction Stop
        
        # Create cryptographic set
        $cryptoSet = New-NetIPsecMainModeCryptoSet `
                        -DisplayName $cryptoSetName `
                        -Proposal $cryptoProposal `
                        -MaxSessions $settings.MaxSessions `
                        -ForceDiffieHellman $true `
                        -PolicyStore ActiveStore `
                        -ErrorAction Stop
        
        Write-Log "Main Mode crypto set created successfully" -Type Success
        
        # Check if Phase 1 auth set exists
        $authSet = Get-NetIPsecPhase1AuthSet -PolicyStore ActiveStore `
                                            -ErrorAction SilentlyContinue | 
                   Select-Object -First 1
        
        if (-not $authSet) {
            Write-Log "WARNING: No Phase 1 authentication set found" -Type Warning
            Write-Log "You need to create Phase 1 authentication first (option 7)" -Type Warning
        } else {
            # Create Main Mode rule
            $existingRule = Get-NetIPsecMainModeRule -DisplayName $mmRuleName `
                                                     -PolicyStore ActiveStore `
                                                     -ErrorAction SilentlyContinue
            
            if ($existingRule) {
                Remove-NetIPsecMainModeRule -DisplayName $mmRuleName `
                                           -PolicyStore ActiveStore `
                                           -ErrorAction SilentlyContinue
            }
            
            [void](New-NetIPsecMainModeRule -DisplayName $mmRuleName `
                                              -MainModeCryptoSet $cryptoSet.Name `
                                              -Phase1AuthSet $authSet.Name `
                                              -PolicyStore ActiveStore `
                                              -ErrorAction Stop)
            
            Write-Log "Main Mode rule created successfully" -Type Success
        }
        
        Write-Log "" -NoFile
        Write-Log "Main Mode configuration completed!" -Type Success
        Write-Log "  - Crypto Set: $cryptoSetName" -Type Info
        Write-Log "  - Max Sessions: $($settings.MaxSessions)" -Type Info
        Write-Log "  - Force DH: Yes" -Type Info
        
    } catch {
        Write-Log "ERROR: Failed to create Main Mode crypto: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-CreateQuickModeCrypto {
    <#
    .SYNOPSIS
        Creates Quick Mode (Phase 2) cryptographic sets.
    #>
    Write-Log "Creating Quick Mode Cryptographic Set..." -Type Title
    
    if (-not $Script:ConfigFileLoaded) {
        Write-Log "ERROR: No configuration loaded. Please load a configuration file first." -Type Error
        Pause-ForUser
        return
    }
    
    # Validate required configuration (chunk-based validation)
    if (-not (Test-ConfigRequirement -RequirementType 'QMCrypto' -Config $Script:CurrentConfig -Operation 'Create Quick Mode Cryptography')) {
        Pause-ForUser
        return
    }
    
    try {
        $settings = $Script:CurrentConfig.Settings
        $cryptoSetName = "IPsec Quick Mode Crypto"
        
        # Check if crypto set already exists
        $existing = Get-NetIPsecQuickModeCryptoSet -DisplayName $cryptoSetName `
                                                   -PolicyStore ActiveStore `
                                                   -ErrorAction SilentlyContinue
        
        if ($existing) {
            Write-Log "Quick Mode crypto set already exists" -Type Info
            $overwrite = Get-UserConfirmation -Message "Do you want to recreate it?"
            
            if ($overwrite) {
                Remove-NetIPsecQuickModeCryptoSet -DisplayName $cryptoSetName `
                                                 -PolicyStore ActiveStore `
                                                 -ErrorAction Stop
                Write-Log "Existing crypto set removed" -Type Info
            } else {
                Write-Log "Using existing crypto set" -Type Info
                Pause-ForUser
                return
            }
        }
        
        Write-Log "Creating Quick Mode cryptographic proposal..." -Type Info
        Write-Log "  - Encapsulation: $($settings.Encapsulation)" -Type Info
        Write-Log "  - Encryption: $($settings.QMEncryption)" -Type Info
        Write-Log "  - Hash: $($settings.QMHash)" -Type Info
        
        # Build crypto proposal parameters
        $encapsulation = $settings.Encapsulation.Split(',').Trim()
        $proposalParams = @{
            'Encapsulation' = $encapsulation
            'Encryption' = $settings.QMEncryption
            'ErrorAction' = 'Stop'
        }
        
        # Add hash parameters based on encapsulation
        if ('AH' -in $encapsulation) {
            $proposalParams.Add('AHHash', $settings.QMHash)
            Write-Log "  - AH Hash: $($settings.QMHash)" -Type Info
        }
        if ('ESP' -in $encapsulation) {
            $proposalParams.Add('ESPHash', $settings.QMHash)
            Write-Log "  - ESP Hash: $($settings.QMHash)" -Type Info
        }
        
        # Create cryptographic proposal
        $qmProposal = New-NetIPsecQuickModeCryptoProposal @proposalParams
        
        # Create Quick Mode crypto set
        [void](New-NetIPsecQuickModeCryptoSet `
                          -DisplayName $cryptoSetName `
                          -Proposal $qmProposal `
                          -PerfectForwardSecrecyGroup SameAsMainMode `
                          -PolicyStore ActiveStore `
                          -ErrorAction Stop)
        
        Write-Log "" -NoFile
        Write-Log "Quick Mode crypto set created successfully!" -Type Success
        Write-Log "  - Name: $cryptoSetName" -Type Info
        Write-Log "  - PFS: Same as Main Mode" -Type Info
        Write-Log "  - Ready for rule application" -Type Info
        
    } catch {
        Write-Log "ERROR: Failed to create Quick Mode crypto: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-ApplyIPsecRules {
    <#
    .SYNOPSIS
        Applies IPsec rules from loaded configuration.
    #>
    Write-Log "Applying IPsec Rules..." -Type Title
    
    if (-not $Script:ConfigFileLoaded) {
        Write-Log "ERROR: No configuration loaded. Please load a configuration file first." -Type Error
        Pause-ForUser
        return
    }
    
    # Validate required configuration (chunk-based validation)
    if (-not (Test-ConfigRequirement -RequirementType 'Rules' -Config $Script:CurrentConfig -Operation 'Apply IPsec Rules')) {
        Pause-ForUser
        return
    }
    
    try {
        # Verify required components exist
        $authSet = Get-NetIPsecPhase1AuthSet -PolicyStore ActiveStore `
                                            -ErrorAction SilentlyContinue | 
                   Select-Object -First 1
        
        $qmCryptoSet = Get-NetIPsecQuickModeCryptoSet -PolicyStore ActiveStore `
                                                      -ErrorAction SilentlyContinue | 
                       Select-Object -First 1
        
        if (-not $authSet) {
            Write-Log "ERROR: No Phase 1 authentication set found" -Type Error
            Write-Log "Create Phase 1 authentication first (option 7)" -Type Error
            Pause-ForUser
            return
        }
        
        if (-not $qmCryptoSet) {
            Write-Log "ERROR: No Quick Mode crypto set found" -Type Error
            Write-Log "Create Quick Mode crypto first (option 9)" -Type Error
            Pause-ForUser
            return
        }
        
        Write-Log "Found required components:" -Type Success
        Write-Log "  - Auth Set: $($authSet.DisplayName)" -Type Info
        Write-Log "  - Crypto Set: $($qmCryptoSet.DisplayName)" -Type Info
        Write-Log "" -NoFile
        
        $settings = $Script:CurrentConfig.Settings
        $successCount = 0
        $failCount = 0
        $skippedCount = 0
        
        Write-Log "Applying $($Script:CurrentConfig.Rules.Count) rule(s)..." -Type Info
        Write-Log "" -NoFile
        
        foreach ($rule in $Script:CurrentConfig.Rules) {
            Write-Log "Processing rule: $($rule.Name)" -Type Info
            
            # Check if rule already exists
            $existing = Get-NetIPsecRule -DisplayName $rule.Name `
                                        -PolicyStore ActiveStore `
                                        -ErrorAction SilentlyContinue
            
            if ($existing) {
                Write-Log "  Rule already exists - skipping" -Type Warning
                $skippedCount++
                continue
            }
            
            try {
                # Build rule parameters
                $ruleParams = @{
                    'DisplayName' = $rule.Name
                    'InboundSecurity' = $rule.Inbound
                    'OutboundSecurity' = $rule.Outbound
                    'QuickModeCryptoSet' = $qmCryptoSet.Name
                    'Phase1AuthSet' = $authSet.Name
                    'KeyModule' = $settings.KeyModule
                    'LocalAddress' = $rule.LocalAddress
                    'RemoteAddress' = $rule.RemoteAddress
                    'Protocol' = $rule.Protocol
                    'Mode' = 'Transport'
                    'Profile' = 'Any'
                    'PolicyStore' = 'ActiveStore'
                    'ErrorAction' = 'Stop'
                }
                
                # Add port parameters for TCP/UDP
                if ($rule.Protocol -in @('TCP', 'UDP')) {
                    $ruleParams.Add('LocalPort', $rule.LocalPort)
                    $ruleParams.Add('RemotePort', $rule.RemotePort)
                }
                
                # Create the IPsec rule
                [void](New-NetIPsecRule @ruleParams)
                
                Write-Log "  [OK] Rule created successfully" -Type Success
                Write-Log "    Inbound: $($rule.Inbound), Outbound: $($rule.Outbound)" -Type Info
                Write-Log "    Protocol: $($rule.Protocol)" -Type Info
                
                $successCount++
                
            } catch {
                Write-Log "  [X] Failed to create rule: $_" -Type Error
                $failCount++
            }
        }
        
        Write-Log "" -NoFile
        Write-Log "=======================================" -Type Info
        Write-Log "IPsec Rule Application Summary:" -Type Title
        Write-Log "  Successfully created: $successCount" -Type Success
        Write-Log "  Skipped (already exist): $skippedCount" -Type Warning
        Write-Log "  Failed: $failCount" -Type $(if ($failCount -gt 0) { 'Error' } else { 'Info' })
        Write-Log "=======================================" -Type Info
        
        if ($successCount -gt 0) {
            Write-Log "" -NoFile
            Write-Log "IPsec rules applied successfully!" -Type Success
            Write-Log "Rules are now active and enforcing encryption" -Type Info
        }
        
    } catch {
        Write-Log "ERROR: Failed to apply IPsec rules: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-ApplyCompleteLocal {
    <#
    .SYNOPSIS
        Applies complete local IPsec configuration in proper sequence.
    .DESCRIPTION
        Orchestrates the full IPsec deployment:
        1. Configure Windows Firewall
        2. Create Phase 1 Authentication
        3. Create Main Mode Crypto Sets
        4. Create Quick Mode Crypto Sets
        5. Apply IPsec Rules
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "COMPLETE LOCAL IPSEC CONFIGURATION" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    if (-not $Script:ConfigFileLoaded) {
        Write-Log "ERROR: No configuration loaded. Please load a configuration file first." -Type Error
        Pause-ForUser
        return
    }
    
    # Validate all required configuration (chunk-based validation)
    Write-Log "Validating configuration requirements..." -Type Info
    $validationFailed = $false
    
    if (-not (Test-ConfigRequirement -RequirementType 'CAPath' -Config $Script:CurrentConfig -Operation 'Complete Local Configuration')) {
        $validationFailed = $true
    }
    if (-not (Test-ConfigRequirement -RequirementType 'CryptoSettings' -Config $Script:CurrentConfig -Operation 'Complete Local Configuration')) {
        $validationFailed = $true
    }
    if (-not (Test-ConfigRequirement -RequirementType 'Rules' -Config $Script:CurrentConfig -Operation 'Complete Local Configuration')) {
        $validationFailed = $true
    }
    
    if ($validationFailed) {
        Write-Log "" -NoFile
        Write-Log "ERROR: Configuration validation failed - missing required fields" -Type Error
        Write-Log "Please ensure your Config.xml contains all required elements" -Type Error
        Pause-ForUser
        return
    }
    
    Write-Log "Configuration validation passed!" -Type Success
    Write-Log "" -NoFile
    
    # Show configuration summary
    Write-Log "Configuration Summary:" -Type Title
    Write-Log "  Rules to apply: $($Script:CurrentConfig.Rules.Count)" -Type Info
    Write-Log "  Encryption: $($Script:CurrentConfig.Settings.QMEncryption)" -Type Info
    Write-Log "  Hash: $($Script:CurrentConfig.Settings.QMHash)" -Type Info
    Write-Log "  Key Exchange: $($Script:CurrentConfig.Settings.KeyExchange)" -Type Info
    Write-Log "" -NoFile
    
    # Confirm before proceeding
    Write-Log "This will apply complete IPsec configuration to this server." -Type Warning
    Write-Log "All components will be created and IPsec rules will be enforced." -Type Warning
    Write-Log "" -NoFile
    
    if (-not (Get-UserConfirmation -Message "Do you want to proceed with complete configuration?")) {
        Write-Log "Operation cancelled by user" -Type Info
        Pause-ForUser
        return
    }
    
    $startTime = Get-Date
    $overallSuccess = $true
    
    try {
        # Step 1: Configure Windows Firewall
        Write-Log "" -NoFile
        Write-Log "?????????????????????????????????????????" -Type Info
        Write-Log "STEP 1 of 5: Configuring Windows Firewall" -Type Title
        Write-Log "?????????????????????????????????????????" -Type Info
        
        try {
            $settings = $Script:CurrentConfig.Settings
            
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
            
            $exemptions = if ($settings.Exemptions -eq 'None') { 'None' } else { $settings.Exemptions }
            $crlCheck = if ($settings.CrlCheck -eq 'RequireCrlCheck') { 'RequireCrlCheck' } else { 'None' }
            
            Set-NetFirewallSetting -Exemptions $exemptions `
                                   -CertValidationLevel $crlCheck `
                                   -ErrorAction Stop
            
            Write-Log "[OK] Firewall configured successfully" -Type Success
        } catch {
            Write-Log "[X] Firewall configuration failed: $_" -Type Error
            $overallSuccess = $false
        }
        
        # Step 2: Create Phase 1 Authentication
        Write-Log "" -NoFile
        Write-Log "?????????????????????????????????????????" -Type Info
        Write-Log "STEP 2 of 5: Creating Phase 1 Authentication" -Type Title
        Write-Log "?????????????????????????????????????????" -Type Info
        
        try {
            $authSetName = "IPsec Computer Certificate Auth"
            
            # Remove existing if present
            Remove-NetIPsecPhase1AuthSet -DisplayName $authSetName `
                                        -PolicyStore ActiveStore `
                                        -ErrorAction SilentlyContinue
            
            $authProposal = New-NetIPsecAuthProposal -Machine `
                                                     -Cert `
                                                     -Authority $settings.CAPath `
                                                     -AuthorityType Root `
                                                     -ErrorAction Stop
            
            $authSet = New-NetIPsecPhase1AuthSet -DisplayName $authSetName `
                                                -Proposal $authProposal `
                                                -PolicyStore ActiveStore `
                                                -ErrorAction Stop
            
            Write-Log "[OK] Phase 1 authentication created" -Type Success
        } catch {
            Write-Log "[X] Phase 1 authentication failed: $_" -Type Error
            $overallSuccess = $false
        }
        
        # Step 3: Create Main Mode Crypto
        Write-Log "" -NoFile
        Write-Log "?????????????????????????????????????????" -Type Info
        Write-Log "STEP 3 of 5: Creating Main Mode Crypto Sets" -Type Title
        Write-Log "?????????????????????????????????????????" -Type Info
        
        try {
            $cryptoSetName = "IPsec Main Mode Crypto"
            $mmRuleName = "IPsec Main Mode Rule"
            
            # Remove existing
            Remove-NetIPsecMainModeCryptoSet -DisplayName $cryptoSetName `
                                            -PolicyStore ActiveStore `
                                            -ErrorAction SilentlyContinue
            Remove-NetIPsecMainModeRule -DisplayName $mmRuleName `
                                       -PolicyStore ActiveStore `
                                       -ErrorAction SilentlyContinue
            
            $cryptoProposal = New-NetIPsecMainModeCryptoProposal `
                                -Encryption $settings.MMEncryption `
                                -Hash $settings.MMHash `
                                -KeyExchange $settings.KeyExchange `
                                -ErrorAction Stop
            
            $cryptoSet = New-NetIPsecMainModeCryptoSet `
                            -DisplayName $cryptoSetName `
                            -Proposal $cryptoProposal `
                            -MaxSessions $settings.MaxSessions `
                            -ForceDiffieHellman $true `
                            -PolicyStore ActiveStore `
                            -ErrorAction Stop
            
            [void](New-NetIPsecMainModeRule -DisplayName $mmRuleName `
                                              -MainModeCryptoSet $cryptoSet.Name `
                                              -Phase1AuthSet $authSet.Name `
                                              -PolicyStore ActiveStore `
                                              -ErrorAction Stop)
            
            Write-Log "[OK] Main Mode crypto sets created" -Type Success
        } catch {
            Write-Log "[X] Main Mode crypto creation failed: $_" -Type Error
            $overallSuccess = $false
        }
        
        # Step 4: Create Quick Mode Crypto
        Write-Log "" -NoFile
        Write-Log "?????????????????????????????????????????" -Type Info
        Write-Log "STEP 4 of 5: Creating Quick Mode Crypto Sets" -Type Title
        Write-Log "?????????????????????????????????????????" -Type Info
        
        try {
            $qmCryptoSetName = "IPsec Quick Mode Crypto"
            
            # Remove existing
            Remove-NetIPsecQuickModeCryptoSet -DisplayName $qmCryptoSetName `
                                             -PolicyStore ActiveStore `
                                             -ErrorAction SilentlyContinue
            
            $encapsulation = $settings.Encapsulation.Split(',').Trim()
            $proposalParams = @{
                'Encapsulation' = $encapsulation
                'Encryption' = $settings.QMEncryption
                'ErrorAction' = 'Stop'
            }
            
            if ('AH' -in $encapsulation) {
                $proposalParams.Add('AHHash', $settings.QMHash)
            }
            if ('ESP' -in $encapsulation) {
                $proposalParams.Add('ESPHash', $settings.QMHash)
            }
            
            $qmProposal = New-NetIPsecQuickModeCryptoProposal @proposalParams
            
            $qmCryptoSet = New-NetIPsecQuickModeCryptoSet `
                              -DisplayName $qmCryptoSetName `
                              -Proposal $qmProposal `
                              -PerfectForwardSecrecyGroup SameAsMainMode `
                              -PolicyStore ActiveStore `
                              -ErrorAction Stop
            
            Write-Log "[OK] Quick Mode crypto sets created" -Type Success
        } catch {
            Write-Log "[X] Quick Mode crypto creation failed: $_" -Type Error
            $overallSuccess = $false
        }
        
        # Step 5: Apply IPsec Rules
        Write-Log "" -NoFile
        Write-Log "?????????????????????????????????????????" -Type Info
        Write-Log "STEP 5 of 5: Applying IPsec Rules" -Type Title
        Write-Log "?????????????????????????????????????????" -Type Info
        
        try {
            $successCount = 0
            $failCount = 0
            
            foreach ($rule in $Script:CurrentConfig.Rules) {
                try {
                    # Remove existing rule
                    Remove-NetIPsecRule -DisplayName $rule.Name `
                                       -PolicyStore ActiveStore `
                                       -ErrorAction SilentlyContinue
                    
                    $ruleParams = @{
                        'DisplayName' = $rule.Name
                        'InboundSecurity' = $rule.Inbound
                        'OutboundSecurity' = $rule.Outbound
                        'QuickModeCryptoSet' = $qmCryptoSet.Name
                        'Phase1AuthSet' = $authSet.Name
                        'KeyModule' = $settings.KeyModule
                        'LocalAddress' = $rule.LocalAddress
                        'RemoteAddress' = $rule.RemoteAddress
                        'Protocol' = $rule.Protocol
                        'Mode' = 'Transport'
                        'Profile' = 'Any'
                        'PolicyStore' = 'ActiveStore'
                        'ErrorAction' = 'Stop'
                    }
                    
                    if ($rule.Protocol -in @('TCP', 'UDP')) {
                        $ruleParams.Add('LocalPort', $rule.LocalPort)
                        $ruleParams.Add('RemotePort', $rule.RemotePort)
                    }
                    
                    [void](New-NetIPsecRule @ruleParams)
                    Write-Log "  [OK] $($rule.Name)" -Type Success
                    $successCount++
                    
                } catch {
                    Write-Log "  [X] $($rule.Name): $_" -Type Error
                    $failCount++
                    $overallSuccess = $false
                }
            }
            
            Write-Log "Rules applied: $successCount success, $failCount failed" -Type Info
            
        } catch {
            Write-Log "[X] Rule application failed: $_" -Type Error
            $overallSuccess = $false
        }
        
        # Summary
        $duration = (Get-Date) - $startTime
        
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "CONFIGURATION COMPLETE" -Type Title
        Write-Log "===========================================================" -Type Header
        
        if ($overallSuccess) {
            Write-Log "[OK] All components configured successfully!" -Type Success
        } else {
            Write-Log "[!] Configuration completed with errors" -Type Warning
            Write-Log "Check log file for details: $Script:LogFilePath" -Type Info
        }
        
        Write-Log "" -NoFile
        Write-Log "Duration: $($duration.TotalSeconds) seconds" -Type Info
        Write-Log "IPsec is now active on this server" -Type Success
        Write-Log "" -NoFile
        Write-Log "To verify: Get-NetIPsecRule -PolicyStore ActiveStore" -Type Info
        
    } catch {
        Write-Log "" -NoFile
        Write-Log "CRITICAL ERROR during configuration: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-ListGPOs {
    <#
    .SYNOPSIS
        Lists all GPOs with IPsec or Firewall settings.
    .DESCRIPTION
        Searches Active Directory for GPOs containing IPsec rules or firewall settings,
        displays GPO details including linked OUs, dates, and policy information.
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "LIST IPSEC GROUP POLICY OBJECTS" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Check if GroupPolicy module is available
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-Log "ERROR: GroupPolicy PowerShell module not installed" -Type Error
            Write-Log "Install with: Add-WindowsFeature GPMC" -Type Info
            Pause-ForUser
            return
        }
        
        Import-Module GroupPolicy -ErrorAction Stop
        
        Write-Log "Searching for GPOs with IPsec/Firewall settings..." -Type Info
        Write-Log "" -NoFile
        
        # Get all GPOs
        $allGPOs = Get-GPO -All -ErrorAction Stop
        $ipsecGPOs = @()
        
        foreach ($gpo in $allGPOs) {
            # Check if GPO has IPsec or Firewall settings
            $gpoReport = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue)
            
            if ($gpoReport) {
                $hasIPsec = $gpoReport.SelectNodes("//q1:ConnectionSecurityRules") | Where-Object { $_.HasChildNodes }
                $hasFirewall = $gpoReport.SelectNodes("//q1:FirewallRules") | Where-Object { $_.HasChildNodes }
                $hasSettings = $gpoReport.SelectNodes("//q1:GlobalSettings") | Where-Object { $_.HasChildNodes }
                
                if ($hasIPsec -or $hasFirewall -or $hasSettings) {
                    # Get linked OUs
                    $links = @()
                    try {
                        $gpoLinks = Get-ADOrganizationalUnit -Filter * -Properties gPLink -ErrorAction SilentlyContinue |
                            Where-Object { $_.gPLink -like "*$($gpo.Id)*" }
                        
                        if ($gpoLinks) {
                            $links = $gpoLinks | ForEach-Object { $_.DistinguishedName }
                        }
                    } catch {
                        # AD module may not be available
                        $links = @("Unable to query AD")
                    }
                    
                    $ipsecGPOs += [PSCustomObject]@{
                        Name = $gpo.DisplayName
                        Id = $gpo.Id
                        Status = $gpo.GpoStatus
                        Created = $gpo.CreationTime
                        Modified = $gpo.ModificationTime
                        HasIPsec = [bool]$hasIPsec
                        HasFirewall = [bool]$hasFirewall
                        LinkedOUs = $links
                        Description = $gpo.Description
                    }
                }
            }
        }
        
        if ($ipsecGPOs.Count -eq 0) {
            Write-Log "No GPOs found with IPsec or Firewall settings" -Type Warning
            Pause-ForUser
            return
        }
        
        Write-Log "Found $($ipsecGPOs.Count) GPO(s) with IPsec/Firewall configuration:" -Type Success
        Write-Log "" -NoFile
        
        $index = 1
        foreach ($gpo in $ipsecGPOs | Sort-Object Name) {
            Write-Host "[$index] " -NoNewline -ForegroundColor Cyan
            Write-Host $gpo.Name -ForegroundColor White
            Write-Log "    GUID:        $($gpo.Id)" -Type Info
            Write-Log "    Status:      $($gpo.Status)" -Type Info
            Write-Log "    Created:     $($gpo.Created)" -Type Info
            Write-Log "    Modified:    $($gpo.Modified)" -Type Info
            
            $features = @()
            if ($gpo.HasIPsec) { $features += "IPsec Rules" }
            if ($gpo.HasFirewall) { $features += "Firewall Rules" }
            Write-Log "    Contains:    $($features -join ', ')" -Type Info
            
            if ($gpo.LinkedOUs.Count -eq 0) {
                Write-Log "    Linked OUs:  (Not linked to any OUs)" -Type Warning
            } elseif ($gpo.LinkedOUs[0] -eq "Unable to query AD") {
                Write-Log "    Linked OUs:  (Unable to query - AD module not available)" -Type Warning
            } else {
                Write-Log "    Linked OUs:  $($gpo.LinkedOUs.Count) location(s)" -Type Info
                foreach ($ou in $gpo.LinkedOUs) {
                    Write-Log "                 - $ou" -Type Info
                }
            }
            
            if ($gpo.Description) {
                Write-Log "    Description: $($gpo.Description)" -Type Info
            }
            
            Write-Log "" -NoFile
            $index++
        }
        
        # Show detailed view option
        Write-Log "===========================================================" -Type Header
        Write-Host ""
        $viewDetail = Read-Host "View detailed configuration for a GPO? (Enter number or 0 to skip)"
        
        if ($viewDetail -match '^\d+$' -and [int]$viewDetail -gt 0 -and [int]$viewDetail -le $ipsecGPOs.Count) {
            $selectedGPO = $ipsecGPOs[[int]$viewDetail - 1]
            Show-GPOIPsecDetails -GPOName $selectedGPO.Name -GPOId $selectedGPO.Id
        }
        
    } catch {
        Write-Log "ERROR: Failed to list GPOs: $($_.Exception.Message)" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error
    }
    
    Pause-ForUser
}

function Invoke-CreateUpdateGPOs {
    <#
    .SYNOPSIS
        Creates or updates GPOs with IPsec configuration from XML.
    .DESCRIPTION
        Creates new GPO or updates existing GPO with IPsec rules and settings
        from loaded XML configuration. Supports staging mode.
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "CREATE/UPDATE IPSEC GROUP POLICY OBJECT" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Check if GroupPolicy module is available
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-Log "ERROR: GroupPolicy PowerShell module not installed" -Type Error
            Write-Log "Install with: Add-WindowsFeature GPMC" -Type Info
            Pause-ForUser
            return
        }
        
        Import-Module GroupPolicy -ErrorAction Stop
        
        # Check if configuration is loaded
        if (-not $Script:ConfigFileLoaded) {
            Write-Log "ERROR: No configuration loaded. Please load a configuration file first." -Type Error
            Pause-ForUser
            return
        }
        
        # Prompt for GPO name
        Write-Log "Enter GPO name:" -Type Info
        $gpoName = Read-Host "GPO Name"
        
        if ([string]::IsNullOrWhiteSpace($gpoName)) {
            Write-Log "ERROR: GPO name cannot be empty" -Type Error
            Pause-ForUser
            return
        }
        
        # Check if GPO already exists
        $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        
        if ($existingGPO) {
            Write-Log "" -NoFile
            Write-Log "GPO '$gpoName' already exists" -Type Warning
            Write-Log "  Created:  $($existingGPO.CreationTime)" -Type Info
            Write-Log "  Modified: $($existingGPO.ModificationTime)" -Type Info
            Write-Log "" -NoFile
            
            $updateChoice = Read-Host "Update existing GPO? (Y/N)"
            if ($updateChoice -notmatch '^[Yy]') {
                Write-Log "Operation cancelled" -Type Warning
                Pause-ForUser
                return
            }
            $targetGPO = $existingGPO
        } else {
            # Create new GPO
            Write-Log "Creating new GPO: $gpoName" -Type Info
            
            try {
                $targetGPO = New-GPO -Name $gpoName -Comment "IPsec configuration created by Network Security Utility on $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ErrorAction Stop
                Write-Log "GPO created successfully: $($targetGPO.Id)" -Type Success
            } catch {
                Write-Log "ERROR: Failed to create GPO: $($_.Exception.Message)" -Type Error
                Pause-ForUser
                return
            }
        }
        
        Write-Log "" -NoFile
        Write-Log "Applying IPsec configuration to GPO..." -Type Info
        Write-Log "" -NoFile
        
        # Get domain for GPO path
        $domain = $env:USERDNSDOMAIN
        if ([string]::IsNullOrWhiteSpace($domain)) {
            $domain = (Get-WmiObject Win32_ComputerSystem).Domain
        }
        
        # Apply firewall and IPsec settings using netsh or PowerShell cmdlets
        # Note: Direct GPO manipulation requires either netsh export/import or registry editing
        
        Write-Log "Configuring IPsec settings in GPO..." -Type Info
        
        # Build policy store path
        $policyStore = "$domain\$gpoName"
        
        $successCount = 0
        $errorCount = 0
        
        # Apply Phase 1 Authentication
        Write-Log "  Creating Phase 1 Authentication..." -Type Info
        try {
            $settings = $Script:CurrentConfig.Settings
            $caPath = $settings.CAPath
            
            $authParams = @{
                'DisplayName' = 'IPsec Certificate Authentication'
                'Phase1AuthSet' = (New-NetIPsecAuthProposal -Machine -Cert -Authority $caPath -AuthorityType Root)
                'PolicyStore' = $policyStore
                'ErrorAction' = 'Stop'
            }
            
            New-NetIPsecPhase1AuthSet @authParams | Out-Null
            Write-Log "    Phase 1 Authentication created" -Type Success
            $successCount++
        } catch {
            Write-Log "    WARNING: Phase 1 Auth: $($_.Exception.Message)" -Type Warning
            $errorCount++
        }
        
        # Apply Main Mode Crypto
        Write-Log "  Creating Main Mode Crypto Sets..." -Type Info
        try {
            $settings = $Script:CurrentConfig.Settings
            
            $mmProposal = New-NetIPsecMainModeCryptoProposal `
                -Encryption $settings.MMEncryption `
                -Hash $settings.MMHash `
                -KeyExchange $settings.KeyExchange `
                -ErrorAction Stop
            
            $mmParams = @{
                'DisplayName' = 'IPsec Main Mode Crypto'
                'Proposal' = $mmProposal
                'MaxSessions' = [int]$settings.MaxSessions
                'PolicyStore' = $policyStore
                'ErrorAction' = 'Stop'
            }
            
            New-NetIPsecMainModeCryptoSet @mmParams | Out-Null
            Write-Log "    Main Mode Crypto Set created" -Type Success
            $successCount++
        } catch {
            Write-Log "    WARNING: Main Mode Crypto: $($_.Exception.Message)" -Type Warning
            $errorCount++
        }
        
        # Apply Quick Mode Crypto
        Write-Log "  Creating Quick Mode Crypto Sets..." -Type Info
        try {
            $settings = $Script:CurrentConfig.Settings
            
            # Parse encapsulation
            $encapTypes = $settings.Encapsulation -split ',' | ForEach-Object { $_.Trim() }
            
            $qmProposal = New-NetIPsecQuickModeCryptoProposal `
                -Encryption $settings.QMEncryption `
                -ESPHash $settings.QMHash `
                -Encapsulation $encapTypes[0] `
                -ErrorAction Stop
            
            $qmParams = @{
                'DisplayName' = 'IPsec Quick Mode Crypto'
                'Proposal' = $qmProposal
                'PolicyStore' = $policyStore
                'ErrorAction' = 'Stop'
            }
            
            New-NetIPsecQuickModeCryptoSet @qmParams | Out-Null
            Write-Log "    Quick Mode Crypto Set created" -Type Success
            $successCount++
        } catch {
            Write-Log "    WARNING: Quick Mode Crypto: $($_.Exception.Message)" -Type Warning
            $errorCount++
        }
        
        # Apply IPsec Rules
        Write-Log "  Creating IPsec Rules..." -Type Info
        $ruleCount = 0
        
        foreach ($rule in $Script:CurrentConfig.Rules) {
            try {
                $ruleParams = @{
                    'DisplayName' = $rule.Name
                    'InboundSecurity' = $rule.Inbound
                    'OutboundSecurity' = $rule.Outbound
                    'Phase1AuthSet' = 'IPsec Certificate Authentication'
                    'Phase2AuthSet' = 'None'
                    'MainModeCryptoSet' = 'IPsec Main Mode Crypto'
                    'QuickModeCryptoSet' = 'IPsec Quick Mode Crypto'
                    'LocalAddress' = $rule.LocalAddress
                    'RemoteAddress' = $rule.RemoteAddress
                    'Protocol' = $rule.Protocol
                    'Mode' = 'Transport'
                    'Profile' = 'Any'
                    'PolicyStore' = $policyStore
                    'ErrorAction' = 'Stop'
                }
                
                if ($rule.Protocol -in @('TCP', 'UDP')) {
                    $ruleParams.Add('LocalPort', $rule.LocalPort)
                    $ruleParams.Add('RemotePort', $rule.RemotePort)
                }
                
                New-NetIPsecRule @ruleParams | Out-Null
                $ruleCount++
            } catch {
                Write-Log "    WARNING: Rule '$($rule.Name)': $($_.Exception.Message)" -Type Warning
                $errorCount++
            }
        }
        
        Write-Log "    Created $ruleCount IPsec rules" -Type Success
        $successCount += $ruleCount
        
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        
        if ($errorCount -eq 0) {
            Write-Log "GPO configuration completed successfully!" -Type Success
            Write-Log "  GPO Name:      $gpoName" -Type Info
            Write-Log "  GPO ID:        $($targetGPO.Id)" -Type Info
            Write-Log "  Rules Created: $ruleCount" -Type Info
            Write-Log "  Status:        Ready to link to OUs" -Type Info
        } else {
            Write-Log "GPO configuration completed with warnings" -Type Warning
            Write-Log "  Successful:    $successCount operations" -Type Info
            Write-Log "  Warnings:      $errorCount operations" -Type Warning
            Write-Log "  Review errors above for details" -Type Info
        }
        
        Write-Log "" -NoFile
        Write-Log "Next steps:" -Type Info
        Write-Log "  1. Review GPO in Group Policy Management Console" -Type Info
        Write-Log "  2. Link GPO to target OUs (Option 11)" -Type Info
        Write-Log "  3. Test GPO replication (Option 14)" -Type Info
        
    } catch {
        Write-Log "ERROR: Failed to create/update GPO: $($_.Exception.Message)" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error
    }
    
    Pause-ForUser
}

function Invoke-LinkGPOs {
    <#
    .SYNOPSIS
        Links IPsec GPO to Organizational Units.
    .DESCRIPTION
        Links a GPO to one or more OUs with configurable precedence.
        Allows enabling/disabling links without deletion.
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "LINK GPO TO ORGANIZATIONAL UNITS" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Check if GroupPolicy module is available
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-Log "ERROR: GroupPolicy PowerShell module not installed" -Type Error
            Write-Log "Install with: Add-WindowsFeature GPMC" -Type Info
            Pause-ForUser
            return
        }
        
        Import-Module GroupPolicy -ErrorAction Stop
        
        # Check if ActiveDirectory module is available for OU browsing
        $adAvailable = Get-Module -ListAvailable -Name ActiveDirectory
        if ($adAvailable) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        }
        
        # Prompt for GPO name
        Write-Log "Enter GPO name to link:" -Type Info
        $gpoName = Read-Host "GPO Name"
        
        if ([string]::IsNullOrWhiteSpace($gpoName)) {
            Write-Log "ERROR: GPO name cannot be empty" -Type Error
            Pause-ForUser
            return
        }
        
        # Find GPO
        $targetGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        
        if (-not $targetGPO) {
            Write-Log "ERROR: GPO '$gpoName' not found" -Type Error
            
            # Search for similar names
            $similarGPOs = Get-GPO -All | Where-Object { $_.DisplayName -like "*$gpoName*" }
            if ($similarGPOs.Count -gt 0) {
                Write-Log "" -NoFile
                Write-Log "Did you mean one of these?" -Type Info
                foreach ($gpo in $similarGPOs) {
                    Write-Log "  - $($gpo.DisplayName)" -Type Info
                }
            }
            
            Pause-ForUser
            return
        }
        
        Write-Log "" -NoFile
        Write-Log "Found GPO: $($targetGPO.DisplayName)" -Type Success
        Write-Log "  ID:       $($targetGPO.Id)" -Type Info
        Write-Log "  Created:  $($targetGPO.CreationTime)" -Type Info
        Write-Log "  Modified: $($targetGPO.ModificationTime)" -Type Info
        Write-Log "" -NoFile
        
        # Show existing links
        $existingLinks = @()
        if ($adAvailable) {
            try {
                $existingLinks = Get-ADOrganizationalUnit -Filter * -Properties gPLink -ErrorAction SilentlyContinue |
                    Where-Object { $_.gPLink -like "*$($targetGPO.Id)*" } |
                    Select-Object -ExpandProperty DistinguishedName
                
                if ($existingLinks.Count -gt 0) {
                    Write-Log "Currently linked to:" -Type Info
                    foreach ($link in $existingLinks) {
                        Write-Log "  - $link" -Type Info
                    }
                    Write-Log "" -NoFile
                } else {
                    Write-Log "GPO is not currently linked to any OUs" -Type Warning
                    Write-Log "" -NoFile
                }
            } catch {
                Write-Log "Unable to query existing links (AD module may not be available)" -Type Warning
                Write-Log "" -NoFile
            }
        }
        
        # Prompt for OU
        Write-Log "Enter target Organizational Unit:" -Type Info
        Write-Log "  Examples:" -Type Info
        Write-Log "    OU=Servers,DC=domain,DC=com" -Type Info
        Write-Log "    OU=IPsec-Servers,OU=Production,DC=domain,DC=com" -Type Info
        Write-Log "" -NoFile
        
        # Get domain for default suggestion
        $domain = $env:USERDNSDOMAIN
        if ([string]::IsNullOrWhiteSpace($domain)) {
            $domain = (Get-WmiObject Win32_ComputerSystem).Domain
        }
        
        $ouPath = Read-Host "OU Distinguished Name"
        
        if ([string]::IsNullOrWhiteSpace($ouPath)) {
            Write-Log "ERROR: OU path cannot be empty" -Type Error
            Pause-ForUser
            return
        }
        
        # Validate OU exists
        if ($adAvailable) {
            try {
                $ouExists = Get-ADOrganizationalUnit -Identity $ouPath -ErrorAction Stop
                Write-Log "OU validated: $($ouExists.Name)" -Type Success
            } catch {
                Write-Log "WARNING: Unable to validate OU exists" -Type Warning
                Write-Log "         $($_.Exception.Message)" -Type Warning
                
                $continue = Read-Host "Continue anyway? (Y/N)"
                if ($continue -notmatch '^[Yy]') {
                    Write-Log "Operation cancelled" -Type Warning
                    Pause-ForUser
                    return
                }
            }
        }
        
        # Prompt for link options
        Write-Log "" -NoFile
        Write-Log "Link Options:" -Type Info
        $linkEnabled = Read-Host "Enable link immediately? (Y/N, default=Y)"
        $linkEnabled = if ($linkEnabled -match '^[Nn]') { 'No' } else { 'Yes' }
        
        $enforced = Read-Host "Enforce GPO (override child policies)? (Y/N, default=N)"
        $enforced = if ($enforced -match '^[Yy]') { 'Yes' } else { 'No' }
        
        Write-Log "" -NoFile
        Write-Log "Linking GPO..." -Type Info
        
        try {
            # Link the GPO
            $linkParams = @{
                'Name' = $targetGPO.DisplayName
                'Target' = $ouPath
                'LinkEnabled' = $linkEnabled
                'ErrorAction' = 'Stop'
            }
            
            if ($enforced -eq 'Yes') {
                $linkParams['Enforced'] = 'Yes'
            }
            
            New-GPLink @linkParams | Out-Null
            
            Write-Log "" -NoFile
            Write-Log "===========================================================" -Type Header
            Write-Log "GPO LINKED SUCCESSFULLY" -Type Success
            Write-Log "===========================================================" -Type Header
            Write-Log "" -NoFile
            Write-Log "GPO:      $($targetGPO.DisplayName)" -Type Info
            Write-Log "Linked to: $ouPath" -Type Info
            Write-Log "Enabled:   $linkEnabled" -Type Info
            Write-Log "Enforced:  $enforced" -Type Info
            Write-Log "" -NoFile
            Write-Log "Next steps:" -Type Info
            Write-Log "  1. Run 'gpupdate /force' on target servers" -Type Info
            Write-Log "  2. Test GPO replication (Option 14)" -Type Info
            Write-Log "  3. Verify policy application with 'gpresult /H report.html'" -Type Info
            
        } catch {
            if ($_.Exception.Message -like "*already linked*") {
                Write-Log "GPO is already linked to this OU" -Type Warning
                Write-Log "" -NoFile
                
                $updateLink = Read-Host "Update existing link settings? (Y/N)"
                if ($updateLink -match '^[Yy]') {
                    try {
                        Set-GPLink -Name $targetGPO.DisplayName -Target $ouPath -LinkEnabled $linkEnabled -Enforced $enforced -ErrorAction Stop
                        Write-Log "Link settings updated successfully" -Type Success
                    } catch {
                        Write-Log "ERROR: Failed to update link: $($_.Exception.Message)" -Type Error
                    }
                }
            } else {
                Write-Log "ERROR: Failed to link GPO: $($_.Exception.Message)" -Type Error
            }
        }
        
    } catch {
        Write-Log "ERROR: Failed to link GPO: $($_.Exception.Message)" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error
    }
    
    Pause-ForUser
}

function Invoke-RemoveGPOs {
    <#
    .SYNOPSIS
        Removes IPsec GPOs from Active Directory.
    .DESCRIPTION
        Safely removes GPO after unlink confirmation and backup.
        Prevents accidental deletion of production GPOs.
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "REMOVE IPSEC GROUP POLICY OBJECT" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Check if GroupPolicy module is available
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-Log "ERROR: GroupPolicy PowerShell module not installed" -Type Error
            Write-Log "Install with: Add-WindowsFeature GPMC" -Type Info
            Pause-ForUser
            return
        }
        
        Import-Module GroupPolicy -ErrorAction Stop
        
        # Check if ActiveDirectory module is available
        $adAvailable = Get-Module -ListAvailable -Name ActiveDirectory
        if ($adAvailable) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        }
        
        # Prompt for GPO name
        Write-Log "Enter GPO name to remove:" -Type Info
        $gpoName = Read-Host "GPO Name"
        
        if ([string]::IsNullOrWhiteSpace($gpoName)) {
            Write-Log "ERROR: GPO name cannot be empty" -Type Error
            Pause-ForUser
            return
        }
        
        # Find GPO
        $targetGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        
        if (-not $targetGPO) {
            Write-Log "ERROR: GPO '$gpoName' not found" -Type Error
            
            # Search for similar names
            $similarGPOs = Get-GPO -All | Where-Object { $_.DisplayName -like "*$gpoName*" }
            if ($similarGPOs.Count -gt 0) {
                Write-Log "" -NoFile
                Write-Log "Did you mean one of these?" -Type Info
                foreach ($gpo in $similarGPOs) {
                    Write-Log "  - $($gpo.DisplayName)" -Type Info
                }
            }
            
            Pause-ForUser
            return
        }
        
        Write-Log "" -NoFile
        Write-Log "Found GPO: $($targetGPO.DisplayName)" -Type Warning
        Write-Log "  ID:       $($targetGPO.Id)" -Type Info
        Write-Log "  Created:  $($targetGPO.CreationTime)" -Type Info
        Write-Log "  Modified: $($targetGPO.ModificationTime)" -Type Info
        Write-Log "" -NoFile
        
        # Check for existing links
        $hasLinks = $false
        if ($adAvailable) {
            try {
                $existingLinks = Get-ADOrganizationalUnit -Filter * -Properties gPLink -ErrorAction SilentlyContinue |
                    Where-Object { $_.gPLink -like "*$($targetGPO.Id)*" } |
                    Select-Object -ExpandProperty DistinguishedName
                
                if ($existingLinks.Count -gt 0) {
                    $hasLinks = $true
                    Write-Log "WARNING: GPO is currently linked to $($existingLinks.Count) location(s):" -Type Warning
                    foreach ($link in $existingLinks) {
                        Write-Log "  - $link" -Type Warning
                    }
                    Write-Log "" -NoFile
                }
            } catch {
                Write-Log "Unable to check for existing links" -Type Warning
                Write-Log "" -NoFile
            }
        }
        
        # Offer to backup before removal
        Write-Log "BACKUP RECOMMENDED before removal" -Type Warning
        $createBackup = Read-Host "Create backup before removal? (Y/N, default=Y)"
        
        if ($createBackup -notmatch '^[Nn]') {
            Write-Log "" -NoFile
            Write-Log "Creating GPO backup..." -Type Info
            
            try {
                $backupPath = Join-Path $Script:ScriptDirectory "GPO-Backups"
                
                if (-not (Test-Path $backupPath)) {
                    New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
                }
                
                $backup = Backup-GPO -Guid $targetGPO.Id -Path $backupPath -ErrorAction Stop
                Write-Log "Backup created: $backupPath\$($backup.Id)" -Type Success
                Write-Log "Backup ID: $($backup.BackupId)" -Type Info
                Write-Log "" -NoFile
            } catch {
                Write-Log "ERROR: Failed to create backup: $($_.Exception.Message)" -Type Error
                Write-Log "" -NoFile
                
                $continueWithoutBackup = Read-Host "Continue without backup? (Y/N)"
                if ($continueWithoutBackup -notmatch '^[Yy]') {
                    Write-Log "Operation cancelled" -Type Warning
                    Pause-ForUser
                    return
                }
            }
        }
        
        # Unlink if necessary
        if ($hasLinks) {
            Write-Log "GPO must be unlinked before removal" -Type Warning
            $unlinkFirst = Read-Host "Unlink GPO from all locations? (Y/N)"
            
            if ($unlinkFirst -match '^[Yy]') {
                Write-Log "" -NoFile
                Write-Log "Unlinking GPO..." -Type Info
                
                foreach ($link in $existingLinks) {
                    try {
                        Remove-GPLink -Name $targetGPO.DisplayName -Target $link -ErrorAction Stop
                        Write-Log "  Unlinked from: $link" -Type Success
                    } catch {
                        Write-Log "  Failed to unlink from: $link" -Type Error
                        Write-Log "    Error: $($_.Exception.Message)" -Type Error
                    }
                }
                Write-Log "" -NoFile
            } else {
                Write-Log "Cannot remove GPO while it has active links" -Type Error
                Pause-ForUser
                return
            }
        }
        
        # Final confirmation
        if (Get-DoubleConfirmation -Operation "REMOVE GPO '$($targetGPO.DisplayName)' FROM ACTIVE DIRECTORY") {
            Write-Log "" -NoFile
            Write-Log "Removing GPO..." -Type Warning
            
            try {
                Remove-GPO -Guid $targetGPO.Id -ErrorAction Stop
                
                Write-Log "" -NoFile
                Write-Log "===========================================================" -Type Header
                Write-Log "GPO REMOVED SUCCESSFULLY" -Type Success
                Write-Log "===========================================================" -Type Header
                Write-Log "" -NoFile
                Write-Log "GPO '$($targetGPO.DisplayName)' has been removed from Active Directory" -Type Success
                
                if ($createBackup -notmatch '^[Nn]') {
                    Write-Log "" -NoFile
                    Write-Log "Backup location: $backupPath" -Type Info
                    Write-Log "To restore, use: Restore-GPO -BackupId <ID> -Path $backupPath" -Type Info
                }
                
            } catch {
                Write-Log "ERROR: Failed to remove GPO: $($_.Exception.Message)" -Type Error
            }
        } else {
            Write-Log "GPO removal cancelled" -Type Warning
        }
        
    } catch {
        Write-Log "ERROR: Failed to remove GPO: $($_.Exception.Message)" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error
    }
    
    Pause-ForUser
}

function Invoke-ApplyCompleteGPO {
    <#
    .SYNOPSIS
        Applies complete IPsec configuration via GPO (all steps).
    .DESCRIPTION
        Orchestrates the complete GPO deployment workflow:
        1. Creates/updates GPO with loaded configuration
        2. Links GPO to target OUs
        3. Tests replication across DCs
        4. Verifies deployment success
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "APPLY COMPLETE GPO CONFIGURATION" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Check if GroupPolicy module is available
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-Log "ERROR: GroupPolicy PowerShell module not installed" -Type Error
            Write-Log "Install with: Add-WindowsFeature GPMC" -Type Info
            Pause-ForUser
            return
        }
        
        Import-Module GroupPolicy -ErrorAction Stop
        
        # Check if ActiveDirectory module is available
        $adAvailable = Get-Module -ListAvailable -Name ActiveDirectory
        if ($adAvailable) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        }
        
        # Check if configuration is loaded
        if (-not $Script:ConfigFileLoaded) {
            Write-Log "ERROR: No configuration loaded. Please load a configuration file first." -Type Error
            Pause-ForUser
            return
        }
        
        Write-Log "This wizard will guide you through complete GPO deployment:" -Type Info
        Write-Log "  1. Create/Update GPO with IPsec configuration" -Type Info
        Write-Log "  2. Link GPO to Organizational Units" -Type Info
        Write-Log "  3. Test GPO replication" -Type Info
        Write-Log "  4. Provide deployment verification steps" -Type Info
        Write-Log "" -NoFile
        
        $continue = Read-Host "Continue with complete GPO deployment? (Y/N)"
        if ($continue -notmatch '^[Yy]') {
            Write-Log "Operation cancelled" -Type Warning
            Pause-ForUser
            return
        }
        
        # ===========================================================
        # STEP 1: Create/Update GPO
        # ===========================================================
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "STEP 1: CREATE/UPDATE GPO" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        Write-Log "Enter GPO name:" -Type Info
        $gpoName = Read-Host "GPO Name"
        
        if ([string]::IsNullOrWhiteSpace($gpoName)) {
            Write-Log "ERROR: GPO name cannot be empty" -Type Error
            Pause-ForUser
            return
        }
        
        # Check if GPO exists
        $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        
        if ($existingGPO) {
            Write-Log "" -NoFile
            Write-Log "GPO '$gpoName' already exists" -Type Warning
            Write-Log "  Created:  $($existingGPO.CreationTime)" -Type Info
            Write-Log "  Modified: $($existingGPO.ModificationTime)" -Type Info
            Write-Log "" -NoFile
            
            $updateChoice = Read-Host "Update existing GPO? (Y/N)"
            if ($updateChoice -notmatch '^[Yy]') {
                Write-Log "Operation cancelled" -Type Warning
                Pause-ForUser
                return
            }
            $targetGPO = $existingGPO
        } else {
            # Create new GPO
            Write-Log "Creating new GPO: $gpoName" -Type Info
            
            try {
                $targetGPO = New-GPO -Name $gpoName -Comment "IPsec configuration created by Network Security Utility on $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ErrorAction Stop
                Write-Log "GPO created successfully: $($targetGPO.Id)" -Type Success
            } catch {
                Write-Log "ERROR: Failed to create GPO: $($_.Exception.Message)" -Type Error
                Pause-ForUser
                return
            }
        }
        
        Write-Log "" -NoFile
        Write-Log "Applying IPsec configuration to GPO..." -Type Info
        
        # Get domain for policy store
        $domain = $env:USERDNSDOMAIN
        if ([string]::IsNullOrWhiteSpace($domain)) {
            $domain = (Get-WmiObject Win32_ComputerSystem).Domain
        }
        $policyStore = "$domain\$gpoName"
        
        # Apply configuration components
        $settings = $Script:CurrentConfig.Settings
        $successCount = 0
        $errorCount = 0
        
        # Phase 1 Auth
        Write-Log "  Creating Phase 1 Authentication..." -Type Info
        try {
            $authParams = @{
                'DisplayName' = 'IPsec Certificate Authentication'
                'Phase1AuthSet' = (New-NetIPsecAuthProposal -Machine -Cert -Authority $settings.CAPath -AuthorityType Root)
                'PolicyStore' = $policyStore
                'ErrorAction' = 'Stop'
            }
            New-NetIPsecPhase1AuthSet @authParams | Out-Null
            Write-Log "    Phase 1 Authentication created" -Type Success
            $successCount++
        } catch {
            Write-Log "    WARNING: $($_.Exception.Message)" -Type Warning
            $errorCount++
        }
        
        # Main Mode Crypto
        Write-Log "  Creating Main Mode Crypto..." -Type Info
        try {
            $mmProposal = New-NetIPsecMainModeCryptoProposal `
                -Encryption $settings.MMEncryption `
                -Hash $settings.MMHash `
                -KeyExchange $settings.KeyExchange
            
            $mmParams = @{
                'DisplayName' = 'IPsec Main Mode Crypto'
                'Proposal' = $mmProposal
                'MaxSessions' = [int]$settings.MaxSessions
                'PolicyStore' = $policyStore
                'ErrorAction' = 'Stop'
            }
            New-NetIPsecMainModeCryptoSet @mmParams | Out-Null
            Write-Log "    Main Mode Crypto created" -Type Success
            $successCount++
        } catch {
            Write-Log "    WARNING: $($_.Exception.Message)" -Type Warning
            $errorCount++
        }
        
        # Quick Mode Crypto
        Write-Log "  Creating Quick Mode Crypto..." -Type Info
        try {
            $encapTypes = $settings.Encapsulation -split ',' | ForEach-Object { $_.Trim() }
            $qmProposal = New-NetIPsecQuickModeCryptoProposal `
                -Encryption $settings.QMEncryption `
                -ESPHash $settings.QMHash `
                -Encapsulation $encapTypes[0]
            
            $qmParams = @{
                'DisplayName' = 'IPsec Quick Mode Crypto'
                'Proposal' = $qmProposal
                'PolicyStore' = $policyStore
                'ErrorAction' = 'Stop'
            }
            New-NetIPsecQuickModeCryptoSet @qmParams | Out-Null
            Write-Log "    Quick Mode Crypto created" -Type Success
            $successCount++
        } catch {
            Write-Log "    WARNING: $($_.Exception.Message)" -Type Warning
            $errorCount++
        }
        
        # IPsec Rules
        Write-Log "  Creating IPsec Rules..." -Type Info
        $ruleCount = 0
        foreach ($rule in $Script:CurrentConfig.Rules) {
            try {
                $ruleParams = @{
                    'DisplayName' = $rule.Name
                    'InboundSecurity' = $rule.Inbound
                    'OutboundSecurity' = $rule.Outbound
                    'Phase1AuthSet' = 'IPsec Certificate Authentication'
                    'Phase2AuthSet' = 'None'
                    'MainModeCryptoSet' = 'IPsec Main Mode Crypto'
                    'QuickModeCryptoSet' = 'IPsec Quick Mode Crypto'
                    'LocalAddress' = $rule.LocalAddress
                    'RemoteAddress' = $rule.RemoteAddress
                    'Protocol' = $rule.Protocol
                    'Mode' = 'Transport'
                    'Profile' = 'Any'
                    'PolicyStore' = $policyStore
                    'ErrorAction' = 'Stop'
                }
                
                if ($rule.Protocol -in @('TCP', 'UDP')) {
                    $ruleParams.Add('LocalPort', $rule.LocalPort)
                    $ruleParams.Add('RemotePort', $rule.RemotePort)
                }
                
                New-NetIPsecRule @ruleParams | Out-Null
                $ruleCount++
            } catch {
                Write-Log "    WARNING: Rule '$($rule.Name)': $($_.Exception.Message)" -Type Warning
                $errorCount++
            }
        }
        Write-Log "    Created $ruleCount IPsec rules" -Type Success
        
        Write-Log "" -NoFile
        Write-Log "Step 1 completed: GPO configured" -Type Success
        Write-Log "" -NoFile
        
        # ===========================================================
        # STEP 2: Link GPO to OUs
        # ===========================================================
        Write-Log "===========================================================" -Type Header
        Write-Log "STEP 2: LINK GPO TO ORGANIZATIONAL UNITS" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        $linkAnother = 'Y'
        $linkedOUs = @()
        
        while ($linkAnother -match '^[Yy]') {
            Write-Log "Enter target Organizational Unit:" -Type Info
            Write-Log "  Example: OU=Servers,DC=domain,DC=com" -Type Info
            Write-Log "" -NoFile
            
            $ouPath = Read-Host "OU Distinguished Name"
            
            if ([string]::IsNullOrWhiteSpace($ouPath)) {
                break
            }
            
            # Validate OU if possible
            if ($adAvailable) {
                try {
                    $ouExists = Get-ADOrganizationalUnit -Identity $ouPath -ErrorAction Stop
                    Write-Log "OU validated: $($ouExists.Name)" -Type Success
                } catch {
                    Write-Log "WARNING: Unable to validate OU" -Type Warning
                }
            }
            
            # Link options
            $linkEnabled = Read-Host "Enable link immediately? (Y/N, default=Y)"
            $linkEnabled = if ($linkEnabled -match '^[Nn]') { 'No' } else { 'Yes' }
            
            $enforced = Read-Host "Enforce GPO? (Y/N, default=N)"
            $enforced = if ($enforced -match '^[Yy]') { 'Yes' } else { 'No' }
            
            Write-Log "" -NoFile
            Write-Log "Linking GPO..." -Type Info
            
            try {
                $linkParams = @{
                    'Name' = $targetGPO.DisplayName
                    'Target' = $ouPath
                    'LinkEnabled' = $linkEnabled
                    'ErrorAction' = 'Stop'
                }
                
                if ($enforced -eq 'Yes') {
                    $linkParams['Enforced'] = 'Yes'
                }
                
                New-GPLink @linkParams | Out-Null
                Write-Log "Successfully linked to: $ouPath" -Type Success
                $linkedOUs += $ouPath
                
            } catch {
                if ($_.Exception.Message -like "*already linked*") {
                    Write-Log "Already linked - updating settings" -Type Warning
                    try {
                        Set-GPLink -Name $targetGPO.DisplayName -Target $ouPath -LinkEnabled $linkEnabled -Enforced $enforced -ErrorAction Stop
                        Write-Log "Link settings updated" -Type Success
                        $linkedOUs += $ouPath
                    } catch {
                        Write-Log "ERROR: Failed to update link" -Type Error
                    }
                } else {
                    Write-Log "ERROR: Failed to link: $($_.Exception.Message)" -Type Error
                }
            }
            
            Write-Log "" -NoFile
            $linkAnother = Read-Host "Link to another OU? (Y/N)"
        }
        
        if ($linkedOUs.Count -eq 0) {
            Write-Log "WARNING: GPO was not linked to any OUs" -Type Warning
            Write-Log "You can link it later using Option 11" -Type Info
        } else {
            Write-Log "Step 2 completed: GPO linked to $($linkedOUs.Count) OU(s)" -Type Success
        }
        
        Write-Log "" -NoFile
        
        # ===========================================================
        # STEP 3: Test Replication
        # ===========================================================
        Write-Log "===========================================================" -Type Header
        Write-Log "STEP 3: VERIFY GPO REPLICATION" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        $testReplication = Read-Host "Test GPO replication now? (Y/N, recommended)"
        
        if ($testReplication -match '^[Yy]') {
            Write-Log "" -NoFile
            Write-Log "Waiting 10 seconds for initial replication..." -Type Info
            Start-Sleep -Seconds 10
            
            Write-Log "Checking replication status..." -Type Info
            Write-Log "" -NoFile
            
            # Quick replication check
            try {
                $domainControllers = @()
                if ($adAvailable) {
                    $domainControllers = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty HostName -First 3
                }
                
                if ($domainControllers.Count -gt 0) {
                    $versions = @()
                    foreach ($dc in $domainControllers) {
                        try {
                            $gpoOnDC = Get-GPO -Name $targetGPO.DisplayName -Server $dc -ErrorAction Stop
                            $versions += $gpoOnDC.Computer.DSVersion
                            Write-Log "  $dc : Version $($gpoOnDC.Computer.DSVersion)" -Type Info
                        } catch {
                            Write-Log "  $dc : Unable to query" -Type Warning
                        }
                    }
                    
                    $uniqueVersions = $versions | Select-Object -Unique
                    if ($uniqueVersions.Count -eq 1) {
                        Write-Log "" -NoFile
                        Write-Log "Replication appears synchronized" -Type Success
                    } else {
                        Write-Log "" -NoFile
                        Write-Log "Version mismatch detected - run full test (Option 14)" -Type Warning
                    }
                } else {
                    Write-Log "Unable to test replication automatically" -Type Warning
                    Write-Log "Run Option 14 to test manually" -Type Info
                }
            } catch {
                Write-Log "Unable to test replication: $($_.Exception.Message)" -Type Warning
            }
        }
        
        Write-Log "" -NoFile
        
        # ===========================================================
        # FINAL SUMMARY
        # ===========================================================
        Write-Log "===========================================================" -Type Header
        Write-Log "COMPLETE GPO DEPLOYMENT FINISHED" -Type Success
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        Write-Log "Summary:" -Type Info
        Write-Log "  GPO Name:          $($targetGPO.DisplayName)" -Type Info
        Write-Log "  GPO ID:            $($targetGPO.Id)" -Type Info
        Write-Log "  IPsec Rules:       $ruleCount" -Type Info
        Write-Log "  Linked to OUs:     $($linkedOUs.Count)" -Type Info
        Write-Log "" -NoFile
        
        Write-Log "Next Steps:" -Type Info
        Write-Log "  1. Run 'gpupdate /force' on target servers" -Type Info
        Write-Log "  2. Verify with 'gpresult /H report.html'" -Type Info
        Write-Log "  3. Check IPsec status: Get-NetIPsecRule -PolicyStore RSOP" -Type Info
        Write-Log "  4. Test connectivity between servers" -Type Info
        Write-Log "  5. Monitor Security event log for IPsec events" -Type Info
        
    } catch {
        Write-Log "ERROR: Complete GPO deployment failed: $($_.Exception.Message)" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error
    }
    
    Pause-ForUser
}

function Invoke-TestGPOReplication {
    <#
    .SYNOPSIS
        Tests GPO replication status across Domain Controllers.
    .DESCRIPTION
        Checks GPO version numbers on all DCs, identifies replication lag,
        and provides option to force replication if needed.
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "TEST GPO REPLICATION STATUS" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Check if GroupPolicy module is available
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-Log "ERROR: GroupPolicy PowerShell module not installed" -Type Error
            Write-Log "Install with: Add-WindowsFeature GPMC" -Type Info
            Pause-ForUser
            return
        }
        
        Import-Module GroupPolicy -ErrorAction Stop
        
        # Check if ActiveDirectory module is available
        $adAvailable = Get-Module -ListAvailable -Name ActiveDirectory
        if (-not $adAvailable) {
            Write-Log "WARNING: ActiveDirectory module not available" -Type Warning
            Write-Log "Install with: Add-WindowsFeature RSAT-AD-PowerShell" -Type Info
            Write-Log "" -NoFile
        } else {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        
        # Prompt for GPO name
        Write-Log "Enter GPO name to check:" -Type Info
        $gpoName = Read-Host "GPO Name (or partial name)"
        
        if ([string]::IsNullOrWhiteSpace($gpoName)) {
            Write-Log "ERROR: GPO name cannot be empty" -Type Error
            Pause-ForUser
            return
        }
        
        # Find GPO
        $matchingGPOs = Get-GPO -All -ErrorAction Stop | Where-Object { $_.DisplayName -like "*$gpoName*" }
        
        if ($matchingGPOs.Count -eq 0) {
            Write-Log "ERROR: No GPOs found matching '$gpoName'" -Type Error
            Pause-ForUser
            return
        } elseif ($matchingGPOs.Count -gt 1) {
            Write-Log "Multiple GPOs found:" -Type Warning
            Write-Log "" -NoFile
            $index = 1
            foreach ($gpo in $matchingGPOs) {
                Write-Host "  [$index] " -NoNewline -ForegroundColor Cyan
                Write-Host $gpo.DisplayName -ForegroundColor White
                $index++
            }
            Write-Log "" -NoFile
            $selection = Read-Host "Select GPO number (1-$($matchingGPOs.Count))"
            
            if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $matchingGPOs.Count) {
                $targetGPO = $matchingGPOs[[int]$selection - 1]
            } else {
                Write-Log "ERROR: Invalid selection" -Type Error
                Pause-ForUser
                return
            }
        } else {
            $targetGPO = $matchingGPOs[0]
        }
        
        Write-Log "" -NoFile
        Write-Log "Testing replication for: $($targetGPO.DisplayName)" -Type Info
        Write-Log "  GPO ID: $($targetGPO.Id)" -Type Info
        Write-Log "" -NoFile
        
        # Get all domain controllers
        Write-Log "Discovering Domain Controllers..." -Type Info
        $domainControllers = @()
        
        if ($adAvailable) {
            try {
                $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop |
                    Select-Object -ExpandProperty HostName |
                    Sort-Object
            } catch {
                Write-Log "WARNING: Unable to query DCs via AD module" -Type Warning
            }
        }
        
        if ($domainControllers.Count -eq 0) {
            # Fallback to nltest
            try {
                $nltest = nltest /dclist:$env:USERDNSDOMAIN 2>&1
                $domainControllers = $nltest | Where-Object { $_ -match '^\s+\S+\s+(\S+)' } |
                    ForEach-Object { $matches[1] }
            } catch {
                Write-Log "ERROR: Unable to discover domain controllers" -Type Error
                Pause-ForUser
                return
            }
        }
        
        if ($domainControllers.Count -eq 0) {
            Write-Log "ERROR: No domain controllers found" -Type Error
            Pause-ForUser
            return
        }
        
        Write-Log "Found $($domainControllers.Count) Domain Controller(s)" -Type Success
        Write-Log "" -NoFile
        
        # Check GPO version on each DC
        $replicationResults = @()
        
        foreach ($dc in $domainControllers) {
            Write-Host "Checking DC: " -NoNewline -ForegroundColor Cyan
            Write-Host $dc -ForegroundColor White
            
            try {
                # Query GPO version from this DC
                $gpoOnDC = Get-GPO -Name $targetGPO.DisplayName -Server $dc -ErrorAction Stop
                
                $result = [PSCustomObject]@{
                    DomainController = $dc
                    UserVersion = $gpoOnDC.User.DSVersion
                    ComputerVersion = $gpoOnDC.Computer.DSVersion
                    ModificationTime = $gpoOnDC.ModificationTime
                    Status = 'Success'
                    Error = $null
                }
                
                Write-Log "  User Version:     $($gpoOnDC.User.DSVersion)" -Type Info
                Write-Log "  Computer Version: $($gpoOnDC.Computer.DSVersion)" -Type Info
                Write-Log "  Modified:         $($gpoOnDC.ModificationTime)" -Type Info
                
            } catch {
                $result = [PSCustomObject]@{
                    DomainController = $dc
                    UserVersion = 'N/A'
                    ComputerVersion = 'N/A'
                    ModificationTime = $null
                    Status = 'Error'
                    Error = $_.Exception.Message
                }
                
                Write-Log "  ERROR: $($_.Exception.Message)" -Type Error
            }
            
            $replicationResults += $result
            Write-Log "" -NoFile
        }
        
        # Analyze replication status
        Write-Log "===========================================================" -Type Header
        Write-Log "REPLICATION ANALYSIS" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        $successfulDCs = $replicationResults | Where-Object { $_.Status -eq 'Success' }
        
        if ($successfulDCs.Count -eq 0) {
            Write-Log "ERROR: Could not retrieve GPO from any domain controller" -Type Error
            Pause-ForUser
            return
        }
        
        # Check for version consistency
        $uniqueUserVersions = $successfulDCs | Select-Object -ExpandProperty UserVersion -Unique
        $uniqueComputerVersions = $successfulDCs | Select-Object -ExpandProperty ComputerVersion -Unique
        
        if ($uniqueUserVersions.Count -eq 1 -and $uniqueComputerVersions.Count -eq 1) {
            Write-Log "REPLICATION STATUS: All DCs are synchronized" -Type Success
            Write-Log "  User Version:     $($uniqueUserVersions[0]) (consistent)" -Type Info
            Write-Log "  Computer Version: $($uniqueComputerVersions[0]) (consistent)" -Type Info
        } else {
            Write-Log "REPLICATION STATUS: Version mismatch detected!" -Type Warning
            Write-Log "" -NoFile
            
            Write-Log "User Versions:" -Type Warning
            $successfulDCs | Group-Object UserVersion | ForEach-Object {
                Write-Log "  Version $($_.Name): $($_.Count) DC(s)" -Type Info
                $_.Group | ForEach-Object { Write-Log "    - $($_.DomainController)" -Type Info }
            }
            
            Write-Log "" -NoFile
            Write-Log "Computer Versions:" -Type Warning
            $successfulDCs | Group-Object ComputerVersion | ForEach-Object {
                Write-Log "  Version $($_.Name): $($_.Count) DC(s)" -Type Info
                $_.Group | ForEach-Object { Write-Log "    - $($_.DomainController)" -Type Info }
            }
        }
        
        # Check for failed DCs
        $failedDCs = $replicationResults | Where-Object { $_.Status -eq 'Error' }
        if ($failedDCs.Count -gt 0) {
            Write-Log "" -NoFile
            Write-Log "Failed to query $($failedDCs.Count) DC(s):" -Type Warning
            foreach ($failed in $failedDCs) {
                Write-Log "  - $($failed.DomainController): $($failed.Error)" -Type Warning
            }
        }
        
        # Offer to force replication
        if ($uniqueUserVersions.Count -gt 1 -or $uniqueComputerVersions.Count -gt 1) {
            Write-Log "" -NoFile
            Write-Log "===========================================================" -Type Header
            $forceRepl = Read-Host "Force GPO replication now? (Y/N)"
            
            if ($forceRepl -match '^[Yy]') {
                Write-Log "" -NoFile
                Write-Log "Forcing replication..." -Type Info
                
                try {
                    # Force AD replication
                    Write-Log "Running repadmin to sync all DCs..." -Type Info
                    repadmin /syncall /AdeP 2>&1 | Out-Null
                    
                    Write-Log "Replication command completed" -Type Success
                    Write-Log "Wait 60 seconds for replication to propagate..." -Type Info
                    Start-Sleep -Seconds 5
                    Write-Log "Re-check replication status in a few minutes" -Type Info
                    
                } catch {
                    Write-Log "ERROR: Failed to force replication: $($_.Exception.Message)" -Type Error
                    Write-Log "You may need to run 'repadmin /syncall' manually" -Type Info
                }
            }
        }
        
        Write-Log "" -NoFile
        Write-Log "Replication check completed" -Type Success
        
    } catch {
        Write-Log "ERROR: Failed to test GPO replication: $($_.Exception.Message)" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error
    }
    
    Pause-ForUser
}

function Invoke-ExportConfiguration {
    <#
    .SYNOPSIS
        Exports current local IPsec configuration to XML file.
    .DESCRIPTION
        Reads all IPsec components from ActiveStore and creates XML configuration:
        - Firewall settings
        - Phase 1 authentication
        - Main Mode crypto sets
        - Quick Mode crypto sets
        - IPsec rules
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "EXPORT IPSEC CONFIGURATION" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Get export filename
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $defaultName = "IPsecConfig-Export-$timestamp.xml"
        $exportPath = Read-Host "Enter export filename (default: $defaultName)"
        
        if ([string]::IsNullOrWhiteSpace($exportPath)) {
            $exportPath = Join-Path $Script:ScriptDirectory $defaultName
        } elseif (-not [System.IO.Path]::IsPathRooted($exportPath)) {
            $exportPath = Join-Path $Script:ScriptDirectory $exportPath
        }
        
        if (-not $exportPath.EndsWith('.xml')) {
            $exportPath += '.xml'
        }
        
        Write-Log "Exporting to: $exportPath" -Type Info
        Write-Log "" -NoFile
        
        # Get current configuration
        Write-Log "Reading current IPsec configuration..." -Type Info
        
        # Get firewall settings
        $fwSettings = Get-NetFirewallSetting -PolicyStore ActiveStore -ErrorAction Stop
        
        # Get Phase 1 auth
        $authSets = Get-NetIPsecPhase1AuthSet -PolicyStore ActiveStore -ErrorAction Stop
        
        # Get Main Mode crypto
        $mmCrypto = Get-NetIPsecMainModeCryptoSet -PolicyStore ActiveStore -ErrorAction Stop
        
        # Get Quick Mode crypto
        $qmCrypto = Get-NetIPsecQuickModeCryptoSet -PolicyStore ActiveStore -ErrorAction Stop
        
        # Get IPsec rules
        $ipsecRules = Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop
        
        Write-Log "Found $($ipsecRules.Count) IPsec rules" -Type Info
        Write-Log "Found $($authSets.Count) Phase 1 auth sets" -Type Info
        Write-Log "Found $($mmCrypto.Count) Main Mode crypto sets" -Type Info
        Write-Log "Found $($qmCrypto.Count) Quick Mode crypto sets" -Type Info
        Write-Log "" -NoFile
        
        # Build XML structure
        $xmlDoc = New-Object System.Xml.XmlDocument
        $declaration = $xmlDoc.CreateXmlDeclaration("1.0", "UTF-8", $null)
        $xmlDoc.AppendChild($declaration) | Out-Null
        
        # Root element
        $root = $xmlDoc.CreateElement("IPsecConfiguration")
        $xmlDoc.AppendChild($root) | Out-Null
        
        # Add comment
        $comment = $xmlDoc.CreateComment(" Exported from $env:COMPUTERNAME on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ")
        $root.AppendChild($comment) | Out-Null
        
        # Domain element
        $domainNode = $xmlDoc.CreateElement("Domain")
        $domainNode.SetAttribute("name", $env:USERDNSDOMAIN)
        $root.AppendChild($domainNode) | Out-Null
        
        # Settings element
        $settingsNode = $xmlDoc.CreateElement("Settings")
        $domainNode.AppendChild($settingsNode) | Out-Null
        
        # Extract settings from first crypto set if available
        if ($mmCrypto.Count -gt 0) {
            $firstMM = $mmCrypto[0]
            $mmProposal = $firstMM.Proposal[0]
            
            $settingsNode.AppendChild($xmlDoc.CreateElement("MMEncryption")).InnerText = $mmProposal.Encryption
            $settingsNode.AppendChild($xmlDoc.CreateElement("MMHash")).InnerText = $mmProposal.Hash
            $settingsNode.AppendChild($xmlDoc.CreateElement("KeyExchange")).InnerText = $mmProposal.KeyExchange
            $settingsNode.AppendChild($xmlDoc.CreateElement("MaxSessions")).InnerText = $firstMM.MaxSessions
        } else {
            $settingsNode.AppendChild($xmlDoc.CreateElement("MMEncryption")).InnerText = "AES256"
            $settingsNode.AppendChild($xmlDoc.CreateElement("MMHash")).InnerText = "SHA256"
            $settingsNode.AppendChild($xmlDoc.CreateElement("KeyExchange")).InnerText = "DH19"
            $settingsNode.AppendChild($xmlDoc.CreateElement("MaxSessions")).InnerText = "2048"
        }
        
        if ($qmCrypto.Count -gt 0) {
            $firstQM = $qmCrypto[0]
            $qmProposal = $firstQM.Proposal[0]
            
            $settingsNode.AppendChild($xmlDoc.CreateElement("QMEncryption")).InnerText = $qmProposal.Encryption
            $settingsNode.AppendChild($xmlDoc.CreateElement("QMHash")).InnerText = if ($qmProposal.AHHash) { $qmProposal.AHHash } else { $qmProposal.ESPHash }
            $settingsNode.AppendChild($xmlDoc.CreateElement("Encapsulation")).InnerText = ($qmProposal.Encapsulation -join ',')
        } else {
            $settingsNode.AppendChild($xmlDoc.CreateElement("QMEncryption")).InnerText = "AES256"
            $settingsNode.AppendChild($xmlDoc.CreateElement("QMHash")).InnerText = "SHA256"
            $settingsNode.AppendChild($xmlDoc.CreateElement("Encapsulation")).InnerText = "ESP"
        }
        
        # Extract CA path from auth set
        if ($authSets.Count -gt 0) {
            $authProposal = $authSets[0].Proposal[0]
            $caPath = if ($authProposal.Authority) { $authProposal.Authority } else { "CN=YourCA" }
            $settingsNode.AppendChild($xmlDoc.CreateElement("CAPath")).InnerText = $caPath
        } else {
            $settingsNode.AppendChild($xmlDoc.CreateElement("CAPath")).InnerText = "CN=YourCA"
        }
        
        $settingsNode.AppendChild($xmlDoc.CreateElement("KeyModule")).InnerText = "AuthIP"
        $settingsNode.AppendChild($xmlDoc.CreateElement("Exemptions")).InnerText = $fwSettings.Exemptions
        $settingsNode.AppendChild($xmlDoc.CreateElement("CrlCheck")).InnerText = $fwSettings.CertValidationLevel
        
        # Rules element
        $rulesNode = $xmlDoc.CreateElement("Rules")
        $domainNode.AppendChild($rulesNode) | Out-Null
        
        # Add each IPsec rule
        foreach ($rule in $ipsecRules) {
            $ruleNode = $xmlDoc.CreateElement("Rule")
            
            $ruleNode.AppendChild($xmlDoc.CreateElement("Name")).InnerText = $rule.DisplayName
            $ruleNode.AppendChild($xmlDoc.CreateElement("LocalAddress")).InnerText = $rule.LocalAddress -join ','
            $ruleNode.AppendChild($xmlDoc.CreateElement("RemoteAddress")).InnerText = $rule.RemoteAddress -join ','
            $ruleNode.AppendChild($xmlDoc.CreateElement("Protocol")).InnerText = $rule.Protocol
            $ruleNode.AppendChild($xmlDoc.CreateElement("LocalPort")).InnerText = $rule.LocalPort -join ','
            $ruleNode.AppendChild($xmlDoc.CreateElement("RemotePort")).InnerText = $rule.RemotePort -join ','
            $ruleNode.AppendChild($xmlDoc.CreateElement("Inbound")).InnerText = $rule.InboundSecurity
            $ruleNode.AppendChild($xmlDoc.CreateElement("Outbound")).InnerText = $rule.OutboundSecurity
            
            $rulesNode.AppendChild($ruleNode) | Out-Null
        }
        
        # Save XML
        $xmlSettings = New-Object System.Xml.XmlWriterSettings
        $xmlSettings.Indent = $true
        $xmlSettings.IndentChars = "  "
        $xmlSettings.NewLineChars = "`r`n"
        $xmlSettings.NewLineHandling = [System.Xml.NewLineHandling]::Replace
        
        $writer = [System.Xml.XmlWriter]::Create($exportPath, $xmlSettings)
        $xmlDoc.Save($writer)
        $writer.Close()
        
        Write-Log "" -NoFile
        Write-Log "[OK] Configuration exported successfully!" -Type Success
        Write-Log "  File: $exportPath" -Type Info
        Write-Log "  Size: $([math]::Round((Get-Item $exportPath).Length / 1KB, 2)) KB" -Type Info
        Write-Log "  Rules: $($ipsecRules.Count)" -Type Info
        
    } catch {
        Write-Log "" -NoFile
        Write-Log "ERROR exporting configuration: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-GenerateReport {
    <#
    .SYNOPSIS
        Generates HTML report of current IPsec configuration.
    .DESCRIPTION
        Creates comprehensive HTML report including:
        - Server information
        - Firewall configuration
        - IPsec authentication settings
        - Crypto sets (Main Mode and Quick Mode)
        - IPsec rules
        - Security associations
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "GENERATE IPSEC REPORT" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Get report filename
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $defaultName = "IPsec-Report-$env:COMPUTERNAME-$timestamp.html"
        $reportPath = Read-Host "Enter report filename (default: $defaultName)"
        
        if ([string]::IsNullOrWhiteSpace($reportPath)) {
            $reportPath = Join-Path $Script:ScriptDirectory $defaultName
        } elseif (-not [System.IO.Path]::IsPathRooted($reportPath)) {
            $reportPath = Join-Path $Script:ScriptDirectory $reportPath
        }
        
        if (-not $reportPath.EndsWith('.html')) {
            $reportPath += '.html'
        }
        
        Write-Log "Generating report: $reportPath" -Type Info
        Write-Log "" -NoFile
        
        # Collect data
        Write-Log "Collecting IPsec configuration data..." -Type Info
        
        $fwSettings = Get-NetFirewallSetting -PolicyStore ActiveStore -ErrorAction Stop
        $fwProfiles = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop
        $authSets = Get-NetIPsecPhase1AuthSet -PolicyStore ActiveStore -ErrorAction Stop
        $mmCrypto = Get-NetIPsecMainModeCryptoSet -PolicyStore ActiveStore -ErrorAction Stop
        $qmCrypto = Get-NetIPsecQuickModeCryptoSet -PolicyStore ActiveStore -ErrorAction Stop
        $ipsecRules = Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop
        $mainModeSAs = Get-NetIPsecMainModeSA -ErrorAction SilentlyContinue
        $quickModeSAs = Get-NetIPsecQuickModeSA -ErrorAction SilentlyContinue
        
        # Build HTML
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>IPsec Configuration Report - $env:COMPUTERNAME</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
        }
        h1 { 
            color: #0066cc; 
            border-bottom: 3px solid #0066cc; 
            padding-bottom: 10px;
        }
        h2 { 
            color: #0078d4; 
            border-bottom: 2px solid #e1e1e1; 
            padding-bottom: 8px;
            margin-top: 30px;
        }
        h3 { 
            color: #0091ea;
            margin-top: 20px;
        }
        .info-box { 
            background-color: #e7f3ff; 
            border-left: 4px solid #0066cc; 
            padding: 15px; 
            margin: 15px 0;
            border-radius: 4px;
        }
        .success { 
            background-color: #d4edda; 
            border-left: 4px solid #28a745; 
            color: #155724;
        }
        .warning { 
            background-color: #fff3cd; 
            border-left: 4px solid #ffc107; 
            color: #856404;
        }
        .error { 
            background-color: #f8d7da; 
            border-left: 4px solid #dc3545; 
            color: #721c24;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            background-color: white;
            margin: 15px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th { 
            background-color: #0066cc; 
            color: white; 
            padding: 12px; 
            text-align: left;
            font-weight: 600;
        }
        td { 
            padding: 10px; 
            border-bottom: 1px solid #ddd;
        }
        tr:hover { 
            background-color: #f5f5f5; 
        }
        .metric { 
            display: inline-block; 
            margin: 10px 20px 10px 0; 
            padding: 15px 25px;
            background-color: white;
            border-left: 4px solid #0066cc;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric-value { 
            font-size: 32px; 
            font-weight: bold; 
            color: #0066cc;
        }
        .metric-label { 
            font-size: 14px; 
            color: #666;
            margin-top: 5px;
        }
        .timestamp {
            color: #666;
            font-size: 14px;
            margin-top: 10px;
        }
        code {
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Consolas', 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <h1>IPsec Configuration Report</h1>
    <div class="info-box">
        <strong>Server:</strong> $env:COMPUTERNAME<br>
        <strong>Domain:</strong> $env:USERDNSDOMAIN<br>
        <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>
        <strong>OS:</strong> $((Get-CimInstance Win32_OperatingSystem).Caption)
    </div>

    <h2>Summary Metrics</h2>
    <div class="metric">
        <div class="metric-value">$($ipsecRules.Count)</div>
        <div class="metric-label">IPsec Rules</div>
    </div>
    <div class="metric">
        <div class="metric-value">$($mainModeSAs.Count)</div>
        <div class="metric-label">Main Mode SAs</div>
    </div>
    <div class="metric">
        <div class="metric-value">$($quickModeSAs.Count)</div>
        <div class="metric-label">Quick Mode SAs</div>
    </div>
    <div class="metric">
        <div class="metric-value">$($authSets.Count)</div>
        <div class="metric-label">Auth Sets</div>
    </div>

    <h2>Firewall Configuration</h2>
"@

        # Firewall profiles table
        $html += "<table><tr><th>Profile</th><th>Enabled</th><th>Default Inbound</th><th>Default Outbound</th><th>Logging</th></tr>"
        foreach ($fwProfile in $fwProfiles) {
            $html += "<tr>"
            $html += "<td><strong>$($fwProfile.Name)</strong></td>"
            $html += "<td>$($fwProfile.Enabled)</td>"
            $html += "<td>$($fwProfile.DefaultInboundAction)</td>"
            $html += "<td>$($fwProfile.DefaultOutboundAction)</td>"
            $html += "<td>Allowed: $($fwProfile.LogAllowed), Blocked: $($fwProfile.LogBlocked)</td>"
            $html += "</tr>"
        }
        $html += "</table>"
        
        $html += "<div class='info-box'>"
        $html += "<strong>IPsec Exemptions:</strong> $($fwSettings.Exemptions)<br>"
        $html += "<strong>CRL Check:</strong> $($fwSettings.CertValidationLevel)"
        $html += "</div>"

        # Phase 1 Authentication
        $html += "<h2>Phase 1 Authentication</h2>"
        if ($authSets.Count -gt 0) {
            $html += "<table><tr><th>Display Name</th><th>Type</th><th>Authority</th></tr>"
            foreach ($authSet in $authSets) {
                $proposal = $authSet.Proposal[0]
                $html += "<tr>"
                $html += "<td>$($authSet.DisplayName)</td>"
                $html += "<td>Computer Certificate</td>"
                $html += "<td><code>$($proposal.Authority)</code></td>"
                $html += "</tr>"
            }
            $html += "</table>"
        } else {
            $html += "<div class='info-box warning'>No Phase 1 authentication sets configured</div>"
        }

        # Main Mode Crypto
        $html += "<h2>Main Mode Cryptographic Sets</h2>"
        if ($mmCrypto.Count -gt 0) {
            $html += "<table><tr><th>Display Name</th><th>Encryption</th><th>Hash</th><th>Key Exchange</th><th>Max Sessions</th></tr>"
            foreach ($crypto in $mmCrypto) {
                $proposal = $crypto.Proposal[0]
                $html += "<tr>"
                $html += "<td>$($crypto.DisplayName)</td>"
                $html += "<td>$($proposal.Encryption)</td>"
                $html += "<td>$($proposal.Hash)</td>"
                $html += "<td>$($proposal.KeyExchange)</td>"
                $html += "<td>$($crypto.MaxSessions)</td>"
                $html += "</tr>"
            }
            $html += "</table>"
        } else {
            $html += "<div class='info-box warning'>No Main Mode crypto sets configured</div>"
        }

        # Quick Mode Crypto
        $html += "<h2>Quick Mode Cryptographic Sets</h2>"
        if ($qmCrypto.Count -gt 0) {
            $html += "<table><tr><th>Display Name</th><th>Encapsulation</th><th>Encryption</th><th>Hash</th><th>PFS</th></tr>"
            foreach ($crypto in $qmCrypto) {
                $proposal = $crypto.Proposal[0]
                $hashValue = if ($proposal.AHHash) { $proposal.AHHash } else { $proposal.ESPHash }
                $html += "<tr>"
                $html += "<td>$($crypto.DisplayName)</td>"
                $html += "<td>$($proposal.Encapsulation -join ', ')</td>"
                $html += "<td>$($proposal.Encryption)</td>"
                $html += "<td>$hashValue</td>"
                $html += "<td>$($crypto.PerfectForwardSecrecyGroup)</td>"
                $html += "</tr>"
            }
            $html += "</table>"
        } else {
            $html += "<div class='info-box warning'>No Quick Mode crypto sets configured</div>"
        }

        # IPsec Rules
        $html += "<h2>IPsec Rules</h2>"
        if ($ipsecRules.Count -gt 0) {
            $html += "<table><tr><th>Rule Name</th><th>Local Address</th><th>Remote Address</th><th>Protocol</th><th>Ports</th><th>Inbound</th><th>Outbound</th></tr>"
            foreach ($rule in $ipsecRules) {
                $ports = ""
                if ($rule.Protocol -in @('TCP', 'UDP')) {
                    $ports = "L:$($rule.LocalPort -join ',') R:$($rule.RemotePort -join ',')"
                }
                $html += "<tr>"
                $html += "<td><strong>$($rule.DisplayName)</strong></td>"
                $html += "<td><code>$($rule.LocalAddress -join ', ')</code></td>"
                $html += "<td><code>$($rule.RemoteAddress -join ', ')</code></td>"
                $html += "<td>$($rule.Protocol)</td>"
                $html += "<td>$ports</td>"
                $html += "<td>$($rule.InboundSecurity)</td>"
                $html += "<td>$($rule.OutboundSecurity)</td>"
                $html += "</tr>"
            }
            $html += "</table>"
        } else {
            $html += "<div class='info-box error'>No IPsec rules configured</div>"
        }

        # Security Associations
        $html += "<h2>Active Security Associations</h2>"
        
        $html += "<h3>Main Mode SAs</h3>"
        if ($mainModeSAs.Count -gt 0) {
            $html += "<table><tr><th>Local Endpoint</th><th>Remote Endpoint</th><th>Authentication</th><th>Cipher</th></tr>"
            foreach ($sa in $mainModeSAs | Select-Object -First 20) {
                $html += "<tr>"
                $html += "<td><code>$($sa.LocalEndpoint)</code></td>"
                $html += "<td><code>$($sa.RemoteEndpoint)</code></td>"
                $html += "<td>$($sa.AuthenticationMethod)</td>"
                $html += "<td>$($sa.CipherAlgorithm)</td>"
                $html += "</tr>"
            }
            $html += "</table>"
            if ($mainModeSAs.Count -gt 20) {
                $html += "<div class='info-box'>Showing first 20 of $($mainModeSAs.Count) Main Mode SAs</div>"
            }
        } else {
            $html += "<div class='info-box'>No active Main Mode security associations</div>"
        }

        $html += "<h3>Quick Mode SAs</h3>"
        if ($quickModeSAs.Count -gt 0) {
            $html += "<table><tr><th>Local Endpoint</th><th>Remote Endpoint</th><th>Encapsulation</th><th>Cipher</th></tr>"
            foreach ($sa in $quickModeSAs | Select-Object -First 20) {
                $html += "<tr>"
                $html += "<td><code>$($sa.LocalEndpoint)</code></td>"
                $html += "<td><code>$($sa.RemoteEndpoint)</code></td>"
                $html += "<td>$($sa.EncapsulationMode)</td>"
                $html += "<td>$($sa.CipherAlgorithm)</td>"
                $html += "</tr>"
            }
            $html += "</table>"
            if ($quickModeSAs.Count -gt 20) {
                $html += "<div class='info-box'>Showing first 20 of $($quickModeSAs.Count) Quick Mode SAs</div>"
            }
        } else {
            $html += "<div class='info-box'>No active Quick Mode security associations</div>"
        }

        $html += @"
    <div class="timestamp">
        <p>Report generated by IPsec Configuration Utility v$Script:ScriptVersion</p>
        <p>Log file: $Script:LogFilePath</p>
    </div>
</body>
</html>
"@

        # Save report
        $html | Out-File -FilePath $reportPath -Encoding UTF8 -ErrorAction Stop
        
        Write-Log "" -NoFile
        Write-Log "[OK] Report generated successfully!" -Type Success
        Write-Log "  File: $reportPath" -Type Info
        Write-Log "  Size: $([math]::Round((Get-Item $reportPath).Length / 1KB, 2)) KB" -Type Info
        Write-Log "" -NoFile
        
        # Ask to open
        $openReport = Read-Host "Open report in browser? (Y/N)"
        if ($openReport -eq 'Y' -or $openReport -eq 'y') {
            Start-Process $reportPath
            Write-Log "Report opened in default browser" -Type Info
        }
        
    } catch {
        Write-Log "" -NoFile
        Write-Log "ERROR generating report: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-BackupSettings {
    <#
    .SYNOPSIS
        Creates backup of current IPsec configuration.
    .DESCRIPTION
        Backs up all IPsec components using netsh commands:
        - IPsec static configuration
        - Windows Firewall settings
        - Stores backup with timestamp for restore capability
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "BACKUP IPSEC SETTINGS" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Create backup filename
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backupName = "IPsec-Backup-$env:COMPUTERNAME-$timestamp"
        $backupPath = Join-Path $Script:ScriptDirectory $backupName
        
        # Create backup directory
        if (-not (Test-Path $backupPath)) {
            New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        }
        
        Write-Log "Backup location: $backupPath" -Type Info
        Write-Log "" -NoFile
        
        # Backup IPsec static configuration
        Write-Log "Backing up IPsec static configuration..." -Type Info
        $ipsecFile = Join-Path $backupPath "ipsec-static.conf"
        $result = netsh ipsec static exportpolicy file="$ipsecFile" 2>&1
        
        if ($LASTEXITCODE -eq 0 -or (Test-Path $ipsecFile)) {
            Write-Log "  [OK] IPsec static configuration backed up" -Type Success
        } else {
            Write-Log "  [!] IPsec static export returned: $result" -Type Warning
        }
        
        # Backup Windows Firewall with Advanced Security
        Write-Log "Backing up Windows Firewall configuration..." -Type Info
        $firewallFile = Join-Path $backupPath "firewall.wfw"
        $result = netsh advfirewall export "$firewallFile" 2>&1
        
        if ($LASTEXITCODE -eq 0 -and (Test-Path $firewallFile)) {
            Write-Log "  [OK] Firewall configuration backed up" -Type Success
        } else {
            Write-Log "  [!] Firewall export warning: $result" -Type Warning
        }
        
        # Export current configuration to XML for reference
        Write-Log "Exporting configuration to XML..." -Type Info
        
        try {
            $ipsecRules = Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop
            $authSets = Get-NetIPsecPhase1AuthSet -PolicyStore ActiveStore -ErrorAction Stop
            $mmCrypto = Get-NetIPsecMainModeCryptoSet -PolicyStore ActiveStore -ErrorAction Stop
            $qmCrypto = Get-NetIPsecQuickModeCryptoSet -PolicyStore ActiveStore -ErrorAction Stop
            
            $xmlFile = Join-Path $backupPath "configuration.xml"
            
            # Build simple XML representation
            $xmlDoc = New-Object System.Xml.XmlDocument
            $root = $xmlDoc.CreateElement("IPsecBackup")
            $root.SetAttribute("Computer", $env:COMPUTERNAME)
            $root.SetAttribute("Timestamp", (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
            $xmlDoc.AppendChild($root) | Out-Null
            
            # Add statistics
            $statsNode = $xmlDoc.CreateElement("Statistics")
            $statsNode.AppendChild($xmlDoc.CreateElement("Rules")).InnerText = $ipsecRules.Count
            $statsNode.AppendChild($xmlDoc.CreateElement("AuthSets")).InnerText = $authSets.Count
            $statsNode.AppendChild($xmlDoc.CreateElement("MainModeCrypto")).InnerText = $mmCrypto.Count
            $statsNode.AppendChild($xmlDoc.CreateElement("QuickModeCrypto")).InnerText = $qmCrypto.Count
            $root.AppendChild($statsNode) | Out-Null
            
            # Add rules summary
            $rulesNode = $xmlDoc.CreateElement("Rules")
            foreach ($rule in $ipsecRules) {
                $ruleNode = $xmlDoc.CreateElement("Rule")
                $ruleNode.SetAttribute("Name", $rule.DisplayName)
                $ruleNode.SetAttribute("Inbound", $rule.InboundSecurity)
                $ruleNode.SetAttribute("Outbound", $rule.OutboundSecurity)
                $rulesNode.AppendChild($ruleNode) | Out-Null
            }
            $root.AppendChild($rulesNode) | Out-Null
            
            $xmlDoc.Save($xmlFile)
            Write-Log "  [OK] Configuration XML created" -Type Success
            
        } catch {
            Write-Log "  [!] XML export failed: $_" -Type Warning
        }
        
        # Create backup manifest
        $manifestFile = Join-Path $backupPath "BACKUP-MANIFEST.txt"
        $manifest = @"
IPsec Configuration Backup
===========================
Computer: $env:COMPUTERNAME
Domain: $env:USERDNSDOMAIN
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Created By: $env:USERNAME

Backup Contents:
- ipsec-static.conf     : IPsec static policy (netsh format)
- firewall.wfw          : Windows Firewall with Advanced Security
- configuration.xml     : Current configuration summary

Statistics:
- IPsec Rules: $($ipsecRules.Count)
- Auth Sets: $($authSets.Count)
- Main Mode Crypto: $($mmCrypto.Count)
- Quick Mode Crypto: $($qmCrypto.Count)

Restore Instructions:
---------------------
1. To restore firewall:
   netsh advfirewall import "$firewallFile"

2. To restore IPsec static:
   netsh ipsec static importpolicy file="$ipsecFile"

3. To restore using utility:
   - Load configuration.xml
   - Apply complete configuration

CAUTION: Always review configuration before restoring!
"@
        
        $manifest | Out-File -FilePath $manifestFile -Encoding UTF8
        Write-Log "  [OK] Backup manifest created" -Type Success
        
        # Calculate backup size
        $backupSize = (Get-ChildItem -Path $backupPath -Recurse | Measure-Object -Property Length -Sum).Sum
        $backupSizeMB = [math]::Round($backupSize / 1MB, 2)
        
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "BACKUP COMPLETE" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        Write-Log "[OK] Backup created successfully!" -Type Success
        Write-Log "  Location: $backupPath" -Type Info
        Write-Log "  Size: $backupSizeMB MB" -Type Info
        Write-Log "  Files: $($(Get-ChildItem -Path $backupPath).Count)" -Type Info
        Write-Log "" -NoFile
        Write-Log "See BACKUP-MANIFEST.txt for restore instructions" -Type Info
        
    } catch {
        Write-Log "" -NoFile
        Write-Log "ERROR creating backup: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-RestoreFromBackup {
    <#
    .SYNOPSIS
        Restores IPsec configuration from a backup.
    .DESCRIPTION
        Lists available backups and allows user to:
        - Select a backup to restore
        - Review backup contents
        - Restore firewall and IPsec settings
        - Optionally apply configuration using utility
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "RESTORE FROM BACKUP" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Find all backup directories
        $backupDirs = Get-ChildItem -Path $Script:ScriptDirectory -Directory | 
                      Where-Object { $_.Name -like "IPsec-Backup-*" } |
                      Sort-Object LastWriteTime -Descending
        
        if ($backupDirs.Count -eq 0) {
            Write-Log "No backups found in: $Script:ScriptDirectory" -Type Warning
            Write-Log "" -NoFile
            Write-Log "Backups should be in format: IPsec-Backup-COMPUTERNAME-TIMESTAMP" -Type Info
            Pause-ForUser
            return
        }
        
        Write-Log "Found $($backupDirs.Count) backup(s):" -Type Info
        Write-Log "" -NoFile
        
        # Display available backups
        for ($i = 0; $i -lt $backupDirs.Count; $i++) {
            $backup = $backupDirs[$i]
            $manifestFile = Join-Path $backup.FullName "BACKUP-MANIFEST.txt"
            
            Write-Host "[$($i+1)] " -NoNewline -ForegroundColor Cyan
            Write-Host $backup.Name -ForegroundColor White
            Write-Host "    Created: " -NoNewline -ForegroundColor Gray
            Write-Host $backup.LastWriteTime -ForegroundColor White
            
            # Try to read manifest for details
            if (Test-Path $manifestFile) {
                $manifest = Get-Content $manifestFile -Raw
                
                # Extract statistics from manifest
                if ($manifest -match "Computer: ([^\r\n]+)") {
                    Write-Host "    Computer: " -NoNewline -ForegroundColor Gray
                    Write-Host $matches[1] -ForegroundColor White
                }
                if ($manifest -match "IPsec Rules: (\d+)") {
                    Write-Host "    Rules: " -NoNewline -ForegroundColor Gray
                    Write-Host "$($matches[1]) IPsec rules" -ForegroundColor White
                }
            }
            
            Write-Host ""
        }
        
        Write-Host "[0] " -NoNewline -ForegroundColor Cyan
        Write-Host "Cancel" -ForegroundColor Yellow
        Write-Host ""
        
        # Get user selection
        $selection = Read-Host "Select backup to restore (0-$($backupDirs.Count))"
        
        if ($selection -eq "0" -or [string]::IsNullOrWhiteSpace($selection)) {
            Write-Log "Restore cancelled by user" -Type Info
            Pause-ForUser
            return
        }
        
        $selectionNum = [int]$selection
        if ($selectionNum -lt 1 -or $selectionNum -gt $backupDirs.Count) {
            Write-Log "Invalid selection: $selection" -Type Error
            Pause-ForUser
            return
        }
        
        $selectedBackup = $backupDirs[$selectionNum - 1]
        $backupPath = $selectedBackup.FullName
        
        Write-Log "" -NoFile
        Write-Log "Selected backup: $($selectedBackup.Name)" -Type Info
        Write-Log "Location: $backupPath" -Type Info
        Write-Log "" -NoFile
        
        # Check for backup files
        $firewallFile = Join-Path $backupPath "firewall.wfw"
        $ipsecFile = Join-Path $backupPath "ipsec-static.conf"
        $configFile = Join-Path $backupPath "configuration.xml"
        
        $hasFirewall = Test-Path $firewallFile
        $hasIPsec = Test-Path $ipsecFile
        $hasConfig = Test-Path $configFile
        
        Write-Log "Backup contents:" -Type Info
        Write-Log "  Firewall config: $(if ($hasFirewall) { '[OK] Found' } else { '[X] Not found' })" -Type Info
        Write-Log "  IPsec static config: $(if ($hasIPsec) { '[OK] Found' } else { '[X] Not found' })" -Type Info
        Write-Log "  Configuration XML: $(if ($hasConfig) { '[OK] Found' } else { '[X] Not found' })" -Type Info
        Write-Log "" -NoFile
        
        if (-not $hasFirewall -and -not $hasIPsec -and -not $hasConfig) {
            Write-Log "ERROR: Backup appears to be empty or corrupted" -Type Error
            Pause-ForUser
            return
        }
        
        # Warning message
        Write-Log "[!] WARNING: This will replace your current configuration!" -Type Warning
        Write-Log "" -NoFile
        Write-Host "Are you sure you want to restore from this backup? (yes/no): " -NoNewline -ForegroundColor Yellow
        $confirm = Read-Host
        
        if ($confirm -ne "yes") {
            Write-Log "Restore cancelled by user" -Type Info
            Pause-ForUser
            return
        }
        
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "STARTING RESTORE" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        # Restore Windows Firewall
        if ($hasFirewall) {
            Write-Log "Restoring Windows Firewall configuration..." -Type Info
            try {
                $result = netsh advfirewall import "$firewallFile" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "  [OK] Firewall configuration restored" -Type Success
                } else {
                    Write-Log "  [!] Firewall restore warning: $result" -Type Warning
                }
            } catch {
                Write-Log "  [X] Firewall restore failed: $_" -Type Error
            }
        }
        
        # Restore IPsec static configuration
        if ($hasIPsec) {
            Write-Log "Restoring IPsec static configuration..." -Type Info
            try {
                $result = netsh ipsec static importpolicy file="$ipsecFile" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "  [OK] IPsec static configuration restored" -Type Success
                } else {
                    Write-Log "  [!] IPsec restore warning: $result" -Type Warning
                }
            } catch {
                Write-Log "  [X] IPsec restore failed: $_" -Type Error
            }
        }
        
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "RESTORE COMPLETE" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        # Offer to load XML configuration
        if ($hasConfig) {
            Write-Log "Configuration XML file is available: $configFile" -Type Info
            Write-Log "" -NoFile
            Write-Host "Would you like to load this XML configuration? (yes/no): " -NoNewline -ForegroundColor Cyan
            $loadXml = Read-Host
            
            if ($loadXml -eq "yes") {
                Write-Log "" -NoFile
                Write-Log "Loading configuration from backup..." -Type Info
                
                # Set the XML file path and load it
                $Script:XmlFilePath = $configFile
                
                # Note: The actual XML format from backup is different from input XML
                # This is informational only
                Write-Log "  [i] Note: The backup XML is for reference only" -Type Info
                Write-Log "  [i] To apply new settings, use a configuration XML file" -Type Info
                Write-Log "  [i] The netsh restore has already applied the backed-up settings" -Type Info
            }
        }
        
        Write-Log "" -NoFile
        Write-Log "[OK] Configuration has been restored from backup" -Type Success
        Write-Log "" -NoFile
        Write-Log "Recommended next steps:" -Type Info
        Write-Log "  1. View current configuration (Menu Option 1)" -Type Info
        Write-Log "  2. View IPsec statistics (Menu Option 3)" -Type Info
        Write-Log "  3. Test connectivity (Menu Option 17)" -Type Info
        
    } catch {
        Write-Log "" -NoFile
        Write-Log "ERROR during restore: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-ViewFirewallLogs {
    $logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    Write-Log "Firewall Log Location: $logPath" -Type Info
    if (Test-Path $logPath) {
        Write-Log "Opening log file..." -Type Info
        notepad.exe $logPath
    } else {
        Write-Log "Log file not found. Logging may not be enabled." -Type Warning
    }
    Pause-ForUser
}

function Invoke-TestIPsecConnectivity {
    <#
    .SYNOPSIS
        Tests IPsec connectivity to a remote host.
    .DESCRIPTION
        Attempts to establish IPsec connection to remote host and reports:
        - Security Association formation
        - Encryption status
        - Connection success/failure
        - Troubleshooting information
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "TEST IPSEC CONNECTIVITY" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        # Get remote host
        $remoteHost = Read-Host "Enter remote IP address or hostname"
        
        if ([string]::IsNullOrWhiteSpace($remoteHost)) {
            Write-Log "No host specified" -Type Warning
            Pause-ForUser
            return
        }
        
        Write-Log "Testing IPsec connectivity to: $remoteHost" -Type Info
        Write-Log "" -NoFile
        
        # Get baseline SA count
        $initialMainModeSAs = (Get-NetIPsecMainModeSA -ErrorAction SilentlyContinue).Count
        $initialQuickModeSAs = (Get-NetIPsecQuickModeSA -ErrorAction SilentlyContinue).Count
        
        Write-Log "Initial Security Associations:" -Type Info
        Write-Log "  Main Mode SAs: $initialMainModeSAs" -Type Info
        Write-Log "  Quick Mode SAs: $initialQuickModeSAs" -Type Info
        Write-Log "" -NoFile
        
        # Test basic connectivity
        Write-Log "Step 1: Testing basic connectivity (ping)..." -Type Info
        $pingResult = Test-Connection -ComputerName $remoteHost -Count 2 -Quiet -ErrorAction SilentlyContinue
        
        if ($pingResult) {
            Write-Log "  [OK] Host is reachable" -Type Success
        } else {
            Write-Log "  [X] Host is not responding to ping" -Type Warning
            Write-Log "    Note: Host may block ICMP but still accept IPsec" -Type Info
        }
        Write-Log "" -NoFile
        
        # Wait a moment for SAs to establish
        Write-Log "Step 2: Waiting for Security Associations to form..." -Type Info
        Start-Sleep -Seconds 3
        
        # Check for new SAs
        $currentMainModeSAs = (Get-NetIPsecMainModeSA -ErrorAction SilentlyContinue).Count
        $currentQuickModeSAs = (Get-NetIPsecQuickModeSA -ErrorAction SilentlyContinue).Count
        
        Write-Log "Current Security Associations:" -Type Info
        Write-Log "  Main Mode SAs: $currentMainModeSAs" -Type Info
        Write-Log "  Quick Mode SAs: $currentQuickModeSAs" -Type Info
        Write-Log "" -NoFile
        
        # Check if new SAs formed
        $mainModeChange = $currentMainModeSAs - $initialMainModeSAs
        $quickModeChange = $currentQuickModeSAs - $initialQuickModeSAs
        
        if ($mainModeChange -gt 0 -or $quickModeChange -gt 0) {
            Write-Log "[OK] New Security Associations formed!" -Type Success
            Write-Log "  Main Mode change: +$mainModeChange" -Type Success
            Write-Log "  Quick Mode change: +$quickModeChange" -Type Success
            Write-Log "" -NoFile
            Write-Log "IPsec appears to be working correctly" -Type Success
        } else {
            Write-Log "[!] No new Security Associations formed" -Type Warning
            Write-Log "" -NoFile
        }
        
        # Look for specific SA to this host
        Write-Log "Step 3: Checking for Security Association to target host..." -Type Info
        
        $mainModeSA = Get-NetIPsecMainModeSA -ErrorAction SilentlyContinue | 
                      Where-Object { $_.RemoteEndpoint -like "*$remoteHost*" }
        
        $quickModeSA = Get-NetIPsecQuickModeSA -ErrorAction SilentlyContinue | 
                       Where-Object { $_.RemoteEndpoint -like "*$remoteHost*" }
        
        if ($mainModeSA) {
            Write-Log "[OK] Main Mode SA found to $remoteHost" -Type Success
            Write-Log "  Local: $($mainModeSA.LocalEndpoint)" -Type Info
            Write-Log "  Remote: $($mainModeSA.RemoteEndpoint)" -Type Info
            Write-Log "  Auth Method: $($mainModeSA.AuthenticationMethod)" -Type Info
            Write-Log "  Cipher: $($mainModeSA.CipherAlgorithm)" -Type Info
            Write-Log "" -NoFile
        }
        
        if ($quickModeSA) {
            Write-Log "[OK] Quick Mode SA found to $remoteHost" -Type Success
            Write-Log "  Local: $($quickModeSA.LocalEndpoint)" -Type Info
            Write-Log "  Remote: $($quickModeSA.RemoteEndpoint)" -Type Info
            Write-Log "  Encapsulation: $($quickModeSA.EncapsulationMode)" -Type Info
            Write-Log "  Cipher: $($quickModeSA.CipherAlgorithm)" -Type Info
            Write-Log "" -NoFile
            Write-Log "[OK] IPsec encryption is ACTIVE to this host!" -Type Success
        } else {
            Write-Log "[!] No Quick Mode SA found to this host" -Type Warning
            Write-Log "" -NoFile
            Write-Log "Possible reasons:" -Type Info
            Write-Log "  - Remote host doesn't have IPsec configured" -Type Info
            Write-Log "  - IPsec rules don't match this traffic" -Type Info
            Write-Log "  - Certificate authentication failed" -Type Info
            Write-Log "  - Firewall blocking IPsec (UDP 500, 4500, ESP)" -Type Info
        }
        
        # Check for IPsec rules that might apply
        Write-Log "" -NoFile
        Write-Log "Step 4: Checking IPsec rules..." -Type Info
        $rules = Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        
        if ($rules) {
            Write-Log "Found $($rules.Count) IPsec rule(s) configured" -Type Info
            
            # Try to find matching rule
            foreach ($rule in $rules) {
                if ($rule.RemoteAddress -contains 'Any' -or $rule.RemoteAddress -contains $remoteHost) {
                    Write-Log "  [OK] Rule '$($rule.DisplayName)' may apply" -Type Info
                    Write-Log "    Inbound: $($rule.InboundSecurity)" -Type Info
                    Write-Log "    Outbound: $($rule.OutboundSecurity)" -Type Info
                }
            }
        } else {
            Write-Log "[!] No IPsec rules configured!" -Type Warning
            Write-Log "  IPsec cannot work without rules" -Type Error
        }
        
        # Summary
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "CONNECTIVITY TEST SUMMARY" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        if ($quickModeSA) {
            Write-Log "[OK] SUCCESS: IPsec is encrypting traffic to $remoteHost" -Type Success
        } elseif ($mainModeSA) {
            Write-Log "[!] PARTIAL: Main Mode established but no Quick Mode SA" -Type Warning
            Write-Log "  Check: Quick Mode crypto sets and IPsec rules" -Type Info
        } else {
            Write-Log "[X] FAILURE: No IPsec encryption to $remoteHost" -Type Error
            Write-Log "  Review IPsec Event Logs (Option 17) for details" -Type Info
        }
        
    } catch {
        Write-Log "" -NoFile
        Write-Log "ERROR testing connectivity: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-ViewIPsecEvents {
    <#
    .SYNOPSIS
        Views IPsec-related events from Security log.
    .DESCRIPTION
        Filters Windows Security log for IPsec events including:
        - IKE negotiations (Event IDs 4650-4655)
        - IPsec Main Mode (Event IDs 4646-4651)
        - IPsec Quick Mode (Event IDs 4652-4656)
        - Authentication failures
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "IPSEC EVENT LOGS" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        Write-Log "Querying Security event log for IPsec events..." -Type Info
        Write-Log "(This may take a moment...)" -Type Info
        Write-Log "" -NoFile
        
        # IPsec-related event IDs
        $ipsecEventIds = @(
            4646, 4647, 4648, 4649, 4650,  # IKE/Main Mode
            4651, 4652, 4653, 4654, 4655,  # Quick Mode
            4656, 4657, 4658, 4659, 4660,  # Other IPsec events
            5451, 5452, 5453, 5456, 5457, 5458  # IPsec failures
        )
        
        # Get recent IPsec events (last 100)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = $ipsecEventIds
        } -MaxEvents 100 -ErrorAction SilentlyContinue
        
        if ($events) {
            Write-Log "Found $($events.Count) recent IPsec event(s)" -Type Success
            Write-Log "" -NoFile
            
            # Group by Event ID
            $grouped = $events | Group-Object -Property Id | Sort-Object Count -Descending
            
            Write-Log "Event Summary:" -Type Title
            foreach ($group in $grouped) {
                $eventId = $group.Name
                $count = $group.Count
                
                $description = switch ($eventId) {
                    4646 { "IKE SA deleted" }
                    4647 { "IKE Quick Mode deleted" }
                    4648 { "IKE negotiation failed" }
                    4649 { "Failed SA" }
                    4650 { "IKE Main Mode SA established" }
                    4651 { "IKE Main Mode SA established" }
                    4652 { "IKE Quick Mode failed" }
                    4653 { "IKE negotiation failed" }
                    4654 { "IKE negotiation failed (no certificate)" }
                    4655 { "IKE ended" }
                    5451 { "IPsec DoS protection event" }
                    5452 { "IPsec invalid packet" }
                    5453 { "IPsec negotiation failed" }
                    5456 { "PAStore Engine applied local policy" }
                    5457 { "PAStore Engine failed to apply policy" }
                    5458 { "PAStore Engine loaded local policy" }
                    default { "IPsec event" }
                }
                
                $color = if ($eventId -in @(4648, 4649, 4652, 4653, 4654, 5452, 5453, 5457)) { 'Warning' } else { 'Info' }
                Write-Log "  Event $eventId ($count): $description" -Type $color
            }
            
            Write-Log "" -NoFile
            Write-Log "Most Recent Events:" -Type Title
            
            foreach ($logEvent in $events | Select-Object -First 10) {
                $timeColor = if ((Get-Date).Subtract($logEvent.TimeCreated).TotalMinutes -lt 5) { 'Success' } else { 'Info' }
                Write-Log "[$($logEvent.TimeCreated)] Event $($logEvent.Id)" -Type $timeColor
                
                # Extract key info from message
                $message = $logEvent.Message
                if ($message -match "Remote Address:\s+(\S+)") {
                    Write-Log "  Remote: $($matches[1])" -Type Info
                }
                if ($message -match "Failure Point:\s+(.+)") {
                    Write-Log "  Failure: $($matches[1])" -Type Warning
                }
                Write-Log "" -NoFile
            }
            
            Write-Log "To view all details, use: Get-WinEvent -FilterHashtable @{LogName='Security';ID=$($ipsecEventIds -join ',')} | Format-List *" -Type Info
            
        } else {
            Write-Log "No IPsec events found in Security log" -Type Warning
            Write-Log "" -NoFile
            Write-Log "This could mean:" -Type Info
            Write-Log "  - IPsec has not been used recently" -Type Info
            Write-Log "  - Audit logging not enabled for IPsec" -Type Info
            Write-Log "  - Security log was cleared" -Type Info
        }
        
    } catch {
        Write-Log "" -NoFile
        Write-Log "ERROR querying event log: $_" -Type Error
        Write-Log "Ensure you have permission to read Security event log" -Type Warning
    }
    
    Pause-ForUser
}

function Invoke-ViewCertificates {
    <#
    .SYNOPSIS
        Displays machine certificate information.
    .DESCRIPTION
        Shows computer certificates used for IPsec authentication:
        - Certificate subject and issuer
        - Expiration dates
        - Trust chain validation
        - Private key availability
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "MACHINE CERTIFICATE INFORMATION" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    try {
        Write-Log "Querying Local Machine certificate store..." -Type Info
        Write-Log "" -NoFile
        
        # Get computer certificates from Personal store
        $certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop
        
        if ($certs.Count -gt 0) {
            Write-Log "Found $($certs.Count) certificate(s) in Local Machine\Personal store" -Type Success
            Write-Log "" -NoFile
            
            foreach ($cert in $certs) {
                $expired = $cert.NotAfter -lt (Get-Date)
                $expiringSoon = $cert.NotAfter -lt (Get-Date).AddDays(30) -and -not $expired
                $hasPrivateKey = $cert.HasPrivateKey
                
                # Determine color based on status
                $statusColor = if ($expired) { 'Error' } 
                              elseif ($expiringSoon) { 'Warning' }
                              elseif ($hasPrivateKey) { 'Success' }
                              else { 'Info' }
                
                Write-Log "Certificate:" -Type Title
                Write-Log "  Subject: $($cert.Subject)" -Type Info
                Write-Log "  Issuer: $($cert.Issuer)" -Type Info
                Write-Log "  Serial: $($cert.SerialNumber)" -Type Info
                Write-Log "  Valid From: $($cert.NotBefore)" -Type Info
                Write-Log "  Valid To: $($cert.NotAfter)" -Type $statusColor
                Write-Log "  Thumbprint: $($cert.Thumbprint)" -Type Info
                Write-Log "  Has Private Key: $hasPrivateKey" -Type $(if ($hasPrivateKey) { 'Success' } else { 'Warning' })
                
                if ($expired) {
                    Write-Log "  [X] EXPIRED!" -Type Error
                } elseif ($expiringSoon) {
                    Write-Log "  [!] Expires in $([math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)) days" -Type Warning
                } else {
                    Write-Log "  [OK] Valid for $([math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)) days" -Type Success
                }
                
                # Check if suitable for IPsec
                if ($hasPrivateKey) {
                    $enhancedKeyUsage = $cert.EnhancedKeyUsageList
                    if ($enhancedKeyUsage -match "IP security|1\.3\.6\.1\.5\.5\.7\.3\.5") {
                        Write-Log "  [OK] Suitable for IPsec (IP Security EKU present)" -Type Success
                    } elseif ($enhancedKeyUsage -match "Client Authentication|1\.3\.6\.1\.5\.5\.7\.3\.2") {
                        Write-Log "  [OK] Suitable for IPsec (Client Auth present)" -Type Success
                    } else {
                        Write-Log "  [!] May not be suitable for IPsec (check Enhanced Key Usage)" -Type Warning
                    }
                }
                
                Write-Log "" -NoFile
            }
            
            # Check trusted root CAs
            Write-Log "Trusted Root Certification Authorities:" -Type Title
            $rootCerts = Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction Stop
            Write-Log "  Found $($rootCerts.Count) trusted root CA(s)" -Type Info
            
            # List root CAs (first 10)
            foreach ($rootCert in $rootCerts | Select-Object -First 10) {
                Write-Log "  - $($rootCert.Subject)" -Type Info
            }
            
            if ($rootCerts.Count -gt 10) {
                Write-Log "  ... and $($rootCerts.Count - 10) more" -Type Info
            }
            
            Write-Log "" -NoFile
            Write-Log "To open Certificate Manager: certlm.msc" -Type Info
            
        } else {
            Write-Log "[!] No certificates found in Local Machine\Personal store" -Type Warning
            Write-Log "" -NoFile
            Write-Log "IPsec certificate authentication requires computer certificates!" -Type Warning
            Write-Log "" -NoFile
            Write-Log "To install certificates:" -Type Info
            Write-Log "  1. Open Certificate Manager: certlm.msc" -Type Info
            Write-Log "  2. Right-click Personal > All Tasks > Request New Certificate" -Type Info
            Write-Log "  3. Select appropriate certificate template" -Type Info
        }
        
    } catch {
        Write-Log "" -NoFile
        Write-Log "ERROR querying certificates: $_" -Type Error
    }
    
    Pause-ForUser
}

function Invoke-PreviewChanges {
    <#
    .SYNOPSIS
        Preview changes that would be made (WhatIf/Dry-Run mode).
    .DESCRIPTION
        Compares current IPsec configuration with loaded XML configuration and shows:
        - What would be added
        - What would be modified
        - What would be removed
        - No actual changes are made to the system
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "PREVIEW CHANGES (WHATIF MODE)" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    # Check if configuration is loaded
    if ($null -eq $Script:IPsecConfig) {
        Write-Log "ERROR: No configuration loaded!" -Type Error
        Write-Log "" -NoFile
        Write-Log "Please load an XML configuration file first:" -Type Info
        Write-Log "  - Use Menu Option 2/3: Load/Test XML Configuration" -Type Info
        Pause-ForUser
        return
    }
    
    Write-Log "Analyzing differences between current and proposed configurations..." -Type Info
    Write-Log "" -NoFile
    Write-Log "XML Configuration Source: $Script:XmlFilePath" -Type Info
    Write-Log "" -NoFile
    
    try {
        # Get current configuration
        $currentRules = @()
        $currentAuthSets = @()
        $currentMMCrypto = @()
        $currentQMCrypto = @()
        $currentMMRules = @()
        
        try {
            $currentRules = @(Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
            $currentAuthSets = @(Get-NetIPsecPhase1AuthSet -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
            $currentMMCrypto = @(Get-NetIPsecMainModeCryptoSet -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
            $currentQMCrypto = @(Get-NetIPsecQuickModeCryptoSet -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
            $currentMMRules = @(Get-NetIPsecMainModeRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        } catch {
            Write-Log "Warning: Could not retrieve some current settings: $_" -Type Warning
        }
        
        Write-Log "===========================================================" -Type Header
        Write-Log "CURRENT CONFIGURATION" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        Write-Log "  IPsec Rules: $($currentRules.Count)" -Type Info
        Write-Log "  Phase 1 Auth Sets: $($currentAuthSets.Count)" -Type Info
        Write-Log "  Main Mode Crypto Sets: $($currentMMCrypto.Count)" -Type Info
        Write-Log "  Quick Mode Crypto Sets: $($currentQMCrypto.Count)" -Type Info
        Write-Log "  Main Mode Rules: $($currentMMRules.Count)" -Type Info
        
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "PROPOSED CONFIGURATION FROM XML" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        # Count proposed items from XML
        $proposedAuthCount = 0
        $proposedMMCryptoCount = 0
        $proposedQMCryptoCount = 0
        $proposedRulesCount = 0
        
        if ($Script:IPsecConfig.Configuration.Phase1Authentication) {
            $proposedAuthCount = @($Script:IPsecConfig.Configuration.Phase1Authentication.AuthSet).Count
        }
        if ($Script:IPsecConfig.Configuration.MainModeCrypto) {
            $proposedMMCryptoCount = @($Script:IPsecConfig.Configuration.MainModeCrypto.CryptoSet).Count
        }
        if ($Script:IPsecConfig.Configuration.QuickModeCrypto) {
            $proposedQMCryptoCount = @($Script:IPsecConfig.Configuration.QuickModeCrypto.CryptoSet).Count
        }
        if ($Script:IPsecConfig.Configuration.IPsecRules) {
            $proposedRulesCount = @($Script:IPsecConfig.Configuration.IPsecRules.Rule).Count
        }
        
        Write-Log "  Phase 1 Auth Sets: $proposedAuthCount" -Type Info
        Write-Log "  Main Mode Crypto Sets: $proposedMMCryptoCount" -Type Info
        Write-Log "  Quick Mode Crypto Sets: $proposedQMCryptoCount" -Type Info
        Write-Log "  IPsec Rules: $proposedRulesCount" -Type Info
        
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "CHANGE ANALYSIS" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        # Analyze Phase 1 Authentication
        Write-Log "[PHASE 1 AUTHENTICATION]" -Type Title
        if ($proposedAuthCount -gt 0) {
            foreach ($authSetNode in $Script:IPsecConfig.Configuration.Phase1Authentication.AuthSet) {
                $authName = $authSetNode.Name
                $exists = $currentAuthSets | Where-Object { $_.DisplayName -eq $authName }
                
                if ($exists) {
                    Write-Log "  ~ MODIFY: $authName" -Type Warning
                    Write-Log "    Current: Exists in system" -Type Info
                    Write-Log "    Action: Will be updated/recreated" -Type Info
                } else {
                    Write-Log "  + ADD: $authName" -Type Success
                    Write-Log "    Type: $($authSetNode.Method)" -Type Info
                    if ($authSetNode.Certificate) {
                        Write-Log "    Certificate: $($authSetNode.Certificate.Issuer)" -Type Info
                    }
                }
            }
        } else {
            Write-Log "  (No Phase 1 auth sets in XML)" -Type Info
        }
        
        Write-Log "" -NoFile
        
        # Analyze Main Mode Crypto
        Write-Log "[MAIN MODE CRYPTO SETS]" -Type Title
        if ($proposedMMCryptoCount -gt 0) {
            foreach ($cryptoNode in $Script:IPsecConfig.Configuration.MainModeCrypto.CryptoSet) {
                $cryptoName = $cryptoNode.Name
                $exists = $currentMMCrypto | Where-Object { $_.DisplayName -eq $cryptoName }
                
                if ($exists) {
                    Write-Log "  ~ MODIFY: $cryptoName" -Type Warning
                    Write-Log "    Current: Exists in system" -Type Info
                    Write-Log "    Action: Will be updated/recreated" -Type Info
                } else {
                    Write-Log "  + ADD: $cryptoName" -Type Success
                    Write-Log "    Proposals: $(@($cryptoNode.Proposal).Count)" -Type Info
                }
            }
        } else {
            Write-Log "  (No Main Mode crypto sets in XML)" -Type Info
        }
        
        Write-Log "" -NoFile
        
        # Analyze Quick Mode Crypto
        Write-Log "[QUICK MODE CRYPTO SETS]" -Type Title
        if ($proposedQMCryptoCount -gt 0) {
            foreach ($cryptoNode in $Script:IPsecConfig.Configuration.QuickModeCrypto.CryptoSet) {
                $cryptoName = $cryptoNode.Name
                $exists = $currentQMCrypto | Where-Object { $_.DisplayName -eq $cryptoName }
                
                if ($exists) {
                    Write-Log "  ~ MODIFY: $cryptoName" -Type Warning
                    Write-Log "    Current: Exists in system" -Type Info
                    Write-Log "    Action: Will be updated/recreated" -Type Info
                } else {
                    Write-Log "  + ADD: $cryptoName" -Type Success
                    Write-Log "    Proposals: $(@($cryptoNode.Proposal).Count)" -Type Info
                    Write-Log "    PFS: $($cryptoNode.PerfectForwardSecrecy)" -Type Info
                }
            }
        } else {
            Write-Log "  (No Quick Mode crypto sets in XML)" -Type Info
        }
        
        Write-Log "" -NoFile
        
        # Analyze IPsec Rules
        Write-Log "[IPSEC RULES]" -Type Title
        if ($proposedRulesCount -gt 0) {
            foreach ($ruleNode in $Script:IPsecConfig.Configuration.IPsecRules.Rule) {
                $ruleName = $ruleNode.Name
                $exists = $currentRules | Where-Object { $_.DisplayName -eq $ruleName }
                
                if ($exists) {
                    Write-Log "  ~ MODIFY: $ruleName" -Type Warning
                    Write-Log "    Current: $($exists.InboundSecurity)/$($exists.OutboundSecurity)" -Type Info
                    Write-Log "    Proposed: $($ruleNode.InboundSecurity)/$($ruleNode.OutboundSecurity)" -Type Info
                } else {
                    Write-Log "  + ADD: $ruleName" -Type Success
                    Write-Log "    Inbound: $($ruleNode.InboundSecurity)" -Type Info
                    Write-Log "    Outbound: $($ruleNode.OutboundSecurity)" -Type Info
                    Write-Log "    Endpoints: $($ruleNode.LocalAddress) ? $($ruleNode.RemoteAddress)" -Type Info
                }
            }
        } else {
            Write-Log "  (No IPsec rules in XML)" -Type Info
        }
        
        Write-Log "" -NoFile
        
        # Check for items that would be removed (if Option 5/6 is used)
        Write-Log "[ITEMS NOT IN XML - WOULD REMAIN IF APPLIED]" -Type Title
        
        $extraRules = $currentRules | Where-Object {
            $ruleName = $_.DisplayName
            $inXml = $false
            foreach ($xmlRule in $Script:IPsecConfig.Configuration.IPsecRules.Rule) {
                if ($xmlRule.Name -eq $ruleName) {
                    $inXml = $true
                    break
                }
            }
            -not $inXml
        }
        
        if ($extraRules.Count -gt 0) {
            Write-Log "  Current rules not in XML: $($extraRules.Count)" -Type Warning
            foreach ($extraRule in $extraRules) {
                Write-Log "    - $($extraRule.DisplayName)" -Type Info
            }
            Write-Log "" -NoFile
            Write-Log "  [i] Note: These rules would remain unless you use 'Remove All IPsec Rules' first" -Type Info
        } else {
            Write-Log "  (All current rules are in XML)" -Type Success
        }
        
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "WHATIF SUMMARY" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        # Calculate totals
        $totalChanges = 0
        $totalAdds = 0
        $totalModifies = 0
        
        # Count new items
        foreach ($authSetNode in $Script:IPsecConfig.Configuration.Phase1Authentication.AuthSet) {
            $exists = $currentAuthSets | Where-Object { $_.DisplayName -eq $authSetNode.Name }
            if ($exists) { $totalModifies++ } else { $totalAdds++ }
            $totalChanges++
        }
        
        foreach ($cryptoNode in $Script:IPsecConfig.Configuration.MainModeCrypto.CryptoSet) {
            $exists = $currentMMCrypto | Where-Object { $_.DisplayName -eq $cryptoNode.Name }
            if ($exists) { $totalModifies++ } else { $totalAdds++ }
            $totalChanges++
        }
        
        foreach ($cryptoNode in $Script:IPsecConfig.Configuration.QuickModeCrypto.CryptoSet) {
            $exists = $currentQMCrypto | Where-Object { $_.DisplayName -eq $cryptoNode.Name }
            if ($exists) { $totalModifies++ } else { $totalAdds++ }
            $totalChanges++
        }
        
        foreach ($ruleNode in $Script:IPsecConfig.Configuration.IPsecRules.Rule) {
            $exists = $currentRules | Where-Object { $_.DisplayName -eq $ruleNode.Name }
            if ($exists) { $totalModifies++ } else { $totalAdds++ }
            $totalChanges++
        }
        
        if ($totalChanges -eq 0) {
            Write-Log "[OK] No changes would be made" -Type Success
            Write-Log "  Current configuration matches XML" -Type Info
        } else {
            Write-Log "Total changes that would be made: $totalChanges" -Type Warning
            Write-Log "  + New items: $totalAdds" -Type Success
            Write-Log "  ~ Modified items: $totalModifies" -Type Warning
            if ($extraRules.Count -gt 0) {
                Write-Log "  ! Existing rules not in XML: $($extraRules.Count)" -Type Warning
            }
        }
        
        Write-Log "" -NoFile
        Write-Log "===========================================================" -Type Header
        Write-Log "TO APPLY THESE CHANGES:" -Type Title
        Write-Log "===========================================================" -Type Header
        Write-Log "" -NoFile
        
        if ($Script:EnvironmentMode -eq 'Enterprise') {
            Write-Log "ENTERPRISE MODE - GPO Deployment:" -Type Info
            Write-Log "  Option 8: Apply Local Configuration (this server only)" -Type Info
            Write-Log "  Option 13: Apply Complete GPO Configuration (domain-wide)" -Type Info
        } else {
            Write-Log "LOCAL MODE - Standalone Deployment:" -Type Info
            Write-Log "  Option 11: Apply Complete Configuration (all steps)" -Type Info
            Write-Log "  OR apply individual steps (Options 5-10)" -Type Info
        }
        
        Write-Log "" -NoFile
        Write-Log "RECOMMENDED WORKFLOW:" -Type Info
        Write-Log "  1. Review the changes above" -Type Info
        Write-Log "  2. Backup current settings (Option 14/17)" -Type Info
        Write-Log "  3. Optionally remove existing rules (Option 5/6)" -Type Info
        Write-Log "  4. Apply the new configuration (Option 11 or 13)" -Type Info
        Write-Log "  5. Test connectivity (Option 17)" -Type Info
        
        Write-Log "" -NoFile
        Write-Log "[!] REMEMBER: This was a preview only - NO changes were made!" -Type Warning
        
    } catch {
        Write-Log "" -NoFile
        Write-Log "ERROR during change analysis: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
    }
    
    Pause-ForUser
}

function Invoke-ExportADIPsec {
    <#
    .SYNOPSIS
        Wrapper for Export-ADIPsecConfiguration with user prompts.
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "EXPORT IPSEC FROM ACTIVE DIRECTORY" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    Write-Log "This function exports IPsec configuration from the AD IP Security container" -Type Info
    Write-Log "to an XML file that can be analyzed or imported to another domain." -Type Info
    Write-Log "" -NoFile
    
    # Prompt for source domain (optional, can use current domain)
    Write-Host "Source Domain Configuration:" -ForegroundColor Cyan
    Write-Host ""
    $sourceDomain = Read-Host "Enter source domain FQDN (or press Enter for current domain)"
    
    if ([string]::IsNullOrWhiteSpace($sourceDomain)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $sourceDomain = (Get-ADDomain).DNSRoot
            Write-Log "Using current domain: $sourceDomain" -Type Info
        } catch {
            Write-Log "ERROR: Cannot determine current domain" -Type Error
            Pause-ForUser
            return
        }
    }
    
    # Prompt for output path
    Write-Host ""
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $defaultPath = Join-Path -Path $PSScriptRoot -ChildPath "ADIPsec-Export-$sourceDomain-$timestamp.xml"
    Write-Host "Default output: $defaultPath" -ForegroundColor Gray
    $outputPath = Read-Host "Enter output file path (or press Enter for default)"
    
    if ([string]::IsNullOrWhiteSpace($outputPath)) {
        $outputPath = $defaultPath
    }
    
    Write-Log "" -NoFile
    Write-Log "Configuration:" -Type Info
    Write-Log "  Source Domain: $sourceDomain" -Type Info
    Write-Log "  Output File: $outputPath" -Type Info
    Write-Log "" -NoFile
    
    $confirm = Get-UserConfirmation -Message "Proceed with export?"
    if (-not $confirm) {
        Write-Log "Export cancelled by user" -Type Info
        Pause-ForUser
        return
    }
    
    # Call the export function
    $result = Export-ADIPsecConfiguration -SourceDomain $sourceDomain -OutputPath $outputPath
    
    if ($result) {
        Write-Log "" -NoFile
        Write-Log "Export successful!" -Type Success
        Write-Log "File saved to: $result" -Type Success
        Write-Log "" -NoFile
        Write-Log "You can now:" -Type Info
        Write-Log "  - Review the exported XML file" -Type Info
        Write-Log "  - Import it to a target domain (Option 22)" -Type Info
        Write-Log "  - Compare it with another domain (Option 23)" -Type Info
    }
    
    Pause-ForUser
}

function Invoke-ImportADIPsec {
    <#
    .SYNOPSIS
        Wrapper for Import-ADIPsecConfiguration with user prompts.
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "IMPORT IPSEC TO ACTIVE DIRECTORY" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    Write-Log "[!] WARNING: This operation is currently in PREVIEW mode" -Type Warning
    Write-Log "" -NoFile
    Write-Log "This function reads exported IPsec configuration and attempts to" -Type Info
    Write-Log "recreate the objects in the target domain's IP Security container." -Type Info
    Write-Log "" -NoFile
    Write-Log "CURRENT STATUS: Analysis and planning only - full object creation pending" -Type Warning
    Write-Log "" -NoFile
    
    # Prompt for source XML file
    Write-Host "Source XML File:" -ForegroundColor Cyan
    $sourceXML = Read-Host "Enter path to exported IPsec XML file"
    
    if ([string]::IsNullOrWhiteSpace($sourceXML) -or -not (Test-Path $sourceXML)) {
        Write-Log "ERROR: Invalid or missing XML file: $sourceXML" -Type Error
        Pause-ForUser
        return
    }
    
    # Prompt for target domain
    Write-Host ""
    Write-Host "Target Domain Configuration:" -ForegroundColor Cyan
    $targetDomain = Read-Host "Enter target domain FQDN (or press Enter for current domain)"
    
    if ([string]::IsNullOrWhiteSpace($targetDomain)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $targetDomain = (Get-ADDomain).DNSRoot
            Write-Log "Using current domain: $targetDomain" -Type Info
        } catch {
            Write-Log "ERROR: Cannot determine current domain" -Type Error
            Pause-ForUser
            return
        }
    }
    
    Write-Log "" -NoFile
    Write-Log "Configuration:" -Type Info
    Write-Log "  Source XML: $sourceXML" -Type Info
    Write-Log "  Target Domain: $targetDomain" -Type Info
    Write-Log "" -NoFile
    
    # WhatIf mode first
    Write-Log "Running in WhatIf mode (preview only)..." -Type Info
    Write-Log "" -NoFile
    
    Import-ADIPsecConfiguration -SourceXML $sourceXML -TargetDomain $targetDomain -WhatIf
    
    Pause-ForUser
}

function Invoke-CompareADIPsec {
    <#
    .SYNOPSIS
        Wrapper for Compare-ADIPsecConfiguration with user prompts.
    #>
    Write-Log "===========================================================" -Type Header
    Write-Log "COMPARE IPSEC BETWEEN DOMAINS" -Type Title
    Write-Log "===========================================================" -Type Header
    Write-Log "" -NoFile
    
    Write-Log "This function compares IPsec objects in the IP Security containers" -Type Info
    Write-Log "of two Active Directory domains to identify differences." -Type Info
    Write-Log "" -NoFile
    
    # Prompt for source domain
    Write-Host "Source Domain (working/reference domain):" -ForegroundColor Cyan
    $sourceDomain = Read-Host "Enter source domain FQDN"
    
    if ([string]::IsNullOrWhiteSpace($sourceDomain)) {
        Write-Log "ERROR: Source domain is required" -Type Error
        Pause-ForUser
        return
    }
    
    # Prompt for target domain
    Write-Host ""
    Write-Host "Target Domain (domain to compare against):" -ForegroundColor Cyan
    $targetDomain = Read-Host "Enter target domain FQDN"
    
    if ([string]::IsNullOrWhiteSpace($targetDomain)) {
        Write-Log "ERROR: Target domain is required" -Type Error
        Pause-ForUser
        return
    }
    
    Write-Log "" -NoFile
    Write-Log "Comparison Configuration:" -Type Info
    Write-Log "  Source (Reference): $sourceDomain" -Type Info
    Write-Log "  Target (Compare): $targetDomain" -Type Info
    Write-Log "" -NoFile
    
    $confirm = Get-UserConfirmation -Message "Proceed with comparison?"
    if (-not $confirm) {
        Write-Log "Comparison cancelled by user" -Type Info
        Pause-ForUser
        return
    }
    
    # Call the comparison function
    Compare-ADIPsecConfiguration -SourceDomain $sourceDomain -TargetDomain $targetDomain
    
    Write-Log "" -NoFile
    Write-Log "Comparison complete!" -Type Success
    Write-Log "" -NoFile
    Write-Log "Next steps:" -Type Info
    Write-Log "  - If differences found, export from source (Option 21)" -Type Info
    Write-Log "  - Review the exported configuration" -Type Info
    Write-Log "  - Import to target domain (Option 22)" -Type Info
    
    Pause-ForUser
}

#endregion

#region Main Execution

<#
    Main program loop - displays menu and processes user selections.
#>

Write-Log "Starting main program loop..." -Type Info

$running = $true
while ($running) {
    try {
        Show-MainMenu
        
        # Get max menu choice based on mode
        $maxChoice = if ($Script:EnvironmentMode -eq 'Enterprise') { 20 } else { 20 }
        
        $choice = Get-MenuChoice -MaxChoice $maxChoice
        
        if ($choice -ge 0) {
            $continue = Invoke-MenuAction -Choice $choice
            if ($continue -eq $false) {
                $running = $false
            }
        }
        
    } catch {
        Write-Log "Error in main loop: $_" -Type Error
        Write-Log $_.ScriptStackTrace -Type Error -NoConsole
        Pause-ForUser
    }
}

Write-Log "" -NoFile
Write-Log "Exiting $Script:ScriptName" -Type Title
Write-Log "Log file saved to: $Script:LogFilePath" -Type Info
Write-Log "" -NoFile

#endregion

