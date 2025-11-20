<#
.SYNOPSIS
    This file is part of Security Modernization Suite.
 
    This script configures IPsec rules.
 
.DESCRIPTION
    This script configures IPsec rules. Settings are collected from XML file.
 
.PARAMETER ConfigFile
    Path to the XML configuration file containing IPsec rules description.
 
.PARAMETER Mode
    IPsec mode to use.
 
.PARAMETER Domain
    FQDN of the targeted Active Directory. If not specified, the current
    Active Directory domain is used.
 
.PARAMETER Server
    Domain Controller to use for write operations. If not specified, PDC
    Emulator will be used.
 
.PARAMETER Confirm
    If true, confirmation is required to execute the script.
 
.PARAMETER UseCache
    If true (default value) GPO are cached, settings are changed locally,
    then the GPO is saved and finally updated on the DC.
 
.OUTPUTS
    False if an error occurs, true otherwise.
 
.EXAMPLE
    Configures IPsec rules with default parameters:
 
    PS> .\Configure-CTMIPsec.ps1
 
.EXAMPLE
    Configures IPsec rules in Require mode with a specific XML file:
 
    PS> .\Configure-CTMIPsec.ps1 -ConfigFile '..\Config.xml' -Mode Require
 
.EXAMPLE
    Configures IPsec rules from a specific Xml file, in Request Mode and
    targeting a specific Domain Controller:
 
    PS> .\Configure-CTMIPsec.ps1 -ConfigFile '..\Config.xml' `
                                 -Server 'dc01.contoso.com' `
                                 -Mode Request
 
.NOTES
    Authors
        [GS] Gregory Schiro gregory.schiro@microsoft.com
 
    2020-07-17, version 1.1
        [GS] Added WEF support.
    
    2020-03-25, version 1.0
        [GS] First release.
 
    The sample scripts provided here are not supported under any Microsoft
    standard support program or service. All scripts are provided AS IS without
    warranty of any kind. Microsoft further disclaims all implied warranties
    including, without limitation, any implied warranties of merchantability or
    of fitness for a particular purpose. The entire risk arising out of the use
    or performance of the sample scripts and documentation remains with you. In
    no event shall Microsoft, its authors, or anyone else involved in the
    creation, production, or delivery of the scripts be liable for any damages
    whatsoever (including, without limitation, damages for loss of business
    profits, business interruption, loss of business information, or other
    pecuniary loss) arising out of the use of or inability to use the sample
    scripts or documentation, even if Microsoft has been advised of the
    possibility of such damages.
#>
 
#Requires -Version 4.0
 
[CmdletBinding(DefaultParametersetname='All')]
param (
    [Parameter(Mandatory=$false)]
    [ValidateScript({ (![String]::IsNullOrEmpty($_) -and (Test-Path -Path $_ -IsValid)) })]
    [String]$ConfigFile = (Join-Path -Path $PSScriptRoot -ChildPath '..\Config.xml'),
 
    [Parameter(Mandatory=$false)]
    [ValidateSet('Request', 'Require')]
    [String]$Mode = 'Request',
 
    [Parameter(Mandatory=$false)]
    [Alias('DNSRoot')]
    [Object]$Domain = $null,
 
    [Parameter(Mandatory=$false)]
    [String]$Server = $null,
 
    [Parameter(Mandatory=$false)]
    [Switch]$Confirm = $true,
 
    [Parameter(Mandatory=$false)]
    [Switch]$UseCache = $true
)
 
Set-StrictMode -Version Latest
 
#region Helpers
 
function Write-CTMLog {
<#
.SYNOPSIS
    Logs CTM messages.
.DESCRIPTION
    Logs CTM messages.
.PARAMETER Log
    Message to display.
.PARAMETER Type
    Type of message.
.PARAMETER NoNewline
    If specified, the display continues on the same line.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String]$Log = $null,
 
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Title1', 'Title2')]
        [String]$Type = 'Info',
 
        [Parameter(Mandatory=$false)]
        [Switch]$NoNewline = $false
    )
 
    begin {
    }
    process {
        $color = 'DarkYellow'
        switch ($Type) {
            'Info' {
                $color = 'DarkGray'
                break
            }
            'Error' {
                $color = 'Red'
                break
            }
            'Warning' {
                $color = 'Yellow'
                break
            }
            'Success' {
                $color = 'Green'
                break
            }
            'Title1' {
                $color = 'Magenta'
                break
            }
            'Title2' {
                $color = 'Cyan'
                break
            }
            default {
                break
            }
        }
        Write-Host -Object $Log -ForegroundColor $color -NoNewline:$NoNewline
    }
}
 
#endregion
 
function Get-CTMWindowsVersion {
<#
.SYNOPSIS
    Gets current version of Windows.
.DESCRIPTION
    Gets current version of Windows.
.OUTPUTS
    Version number.
#>
    $version = $null
    try {
        $osInfo = (Get-Item -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop)
        $revision = [Int32]$osInfo.GetValue('UBR')
        $version = [Environment]::OSVersion.Version
        $version = [Version](($version.Major, $version.Minor, $version.Build, $revision) -join '.')
        Write-CTMLog -Log "Windows current version is: $($version)" -Type Info
    } catch {
        Write-CTMLog -Log "Can not get Windows version. $_" -Type Error
        return [Version]'0.0.0.0'
    }
    return $version
}
 
function Check-CTMConfigXML {
<#
.SYNOPSIS
    Checks XML file.
.DESCRIPTION
    Checks XML file.
.PARAMETER Path
    Path to the XML file.
.PARAMETER Domain
    FQDN of the targeted Active Directory.
.OUTPUTS
    The XML object.
#>
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ (![String]::IsNullOrEmpty($_) -and (Test-Path -Path $_ -IsValid)) })]
        [String]$Path = $null,
 
        [Parameter(Mandatory=$true)]
        [String]$Domain = $null
    )
    if ([String]::IsNullOrEmpty($Path) -or
        !(Test-Path -Path $Path -IsValid) -or
        !(Test-Path -Path $Path)) {
        Write-CTMLog -Log "Configuration file '$Path' not found" -Type Error
        return $null
    }
    $Path = (Resolve-Path -Path $Path).Path
    $xml = $null
    $patternFQDN = '(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)'
    $patternAll = '[^\s]+.*'
    $nodeCTM = '//Settings/ESAEDomain'
    $isProdXml = $false
    try {
        Write-CTMLog -Log "Reading file '$Path'" -Type Info
        [Xml]$xml = Get-Content -Path $Path -ErrorAction Stop
        try {
            if (($xml -is [Xml]) -and ($xml.Settings.Solution -ine 'ESAE')) {
                $nodeCTM = '//Settings/Domain'
            }
            try {
                $isProdXml = ($xml.Settings.ESAEDomain.CAIP -inotmatch '^.+$')
            } catch {
                $isProdXml = $true
            }
        } catch {
            Add-Log -LogEntry "Wrong format for '$Path'. $_" -LogType Error
            return $null
        }
    } catch {
        Write-CTMLog -Log "Can not read file '$Path'" -Type Error
        return $null
    }
    $nodes = @{
        "$($nodeCTM)/NetBIOSName" = $patternAll
        "$($nodeCTM)/FQDNName" = $patternFQDN
        "$($nodeCTM)/CAPath" = $patternAll
        "$($nodeCTM)/IPsec/Global/IPsecCrlCheck" = '^(None|RequireCrlCheck)$'
        "$($nodeCTM)/IPsec/Global/IPsecExemptions" = $patternAll
        "$($nodeCTM)/IPsec/Global/IPsecEncapsulation" = '^(AH|ESP|AH\s*,\s*ESP)$'
        "$($nodeCTM)/IPsec/Global/IPsecKeyExchange" = '^(DH14|DH19|DH20|DH24)$'
        "$($nodeCTM)/IPsec/Global/IPsecQMHash" = '^(SHA256|SHA384|SHA512|AESGMAC128|AESGMAC192|AESGMAC256)$'
        "$($nodeCTM)/IPsec/Global/IPsecMMHash" = '^(SHA256|SHA384|SHA512)$'
        "$($nodeCTM)/IPsec/Global/IPsecQMEncryption" = '^(None|AES256|AESGCM128|AESGCM192|AESGCM256)$'
        "$($nodeCTM)/IPsec/Global/IPsecMMEncryption" = '^(None|AES256)$'
        "$($nodeCTM)/IPsec/Global/IPsecKeyModule" = '^(Default|IKEv1|AuthIP|IKEv2)$'
        "$($nodeCTM)/IPsec/Global/IPsecMaxSessions" = '^\d+$'
    }
    if (!$isProdXml) {
        $nodes.Add("$($nodeCTM)/DC1IP", $patternAll)
        $nodes.Add("$($nodeCTM)/DC2IP", $patternAll)
        $nodes.Add("$($nodeCTM)/WSUSIP", $patternAll)
        $nodes.Add("$($nodeCTM)/CAIP", $patternAll)
        $nodes.Add("$($nodeCTM)/MDTDHCPStartIP", $patternAll)
        $nodes.Add("$($nodeCTM)/MDTDHCPEndIP", $patternAll)
        $nodes.Add("$($nodeCTM)/MDTWSUS", '^(Yes|No)$')
        if ($xml.Settings.Solution -ieq 'ESAE') {
            $nodes.Add("$($nodeCTM)/SQLIP", $patternAll)
            $nodes.Add("$($nodeCTM)/SCOMIP", $patternAll)
            $nodes.Add("$($nodeCTM)/WEFIP", $patternAll)
            $nodes.Add("$($nodeCTM)/HV1IP", $patternAll)
            $nodes.Add("$($nodeCTM)/HV2IP", $patternAll)
            $nodes.Add("$($nodeCTM)/DomainJoinIP", $patternAll)
        }
    }
    $ShouldStop = $false
    Write-CTMLog -Log "Checking XML file integrity" -Type Info
    foreach ($node in $nodes.Keys) {
        $n = $xml.SelectSingleNode($node)
        if (!$n) {
            Write-CTMLog -Log "Can not read node '$node' from $Path" -Type Error
            $ShouldStop = $true
            continue
        }
        $value = $n.InnerText
        if ($value -notmatch $nodes[$node]) {
            Write-CTMLog -Log "Value of node '$node' ($value) is incorrect" -Type Error
            $ShouldStop = $true
            continue
        }
    }
    if ($ShouldStop) {
        return $null
    }
    try {
        $n = $null
        if ($xml.Settings.Solution -ieq 'ESAE') {
            $n = $xml.Settings.ESAEDomain
        } else {
            $n = $xml.Settings.Domain
        }
        $domainsList = @() + $n.FQDNName
        $domainsList += $n.MDTFQDN
    } catch {
    }
    try {
        $domainsList += $xml.Settings.ProductionDomains.domain.FQDN
    } catch {
    }
    if ($Domain -inotin $domainsList) {
        Write-CTMLog -Log "Domain '$Domain' not found in XML file" -Type Error
        return $null
    }
    return $xml
}
 
function Import-CTMPsModules {
<#
.SYNOPSIS
    Imports Windows PowerShell modules required by this script.
.DESCRIPTION
    Imports Windows PowerShell modules required by this script.
.OUTPUTS
    True on success, false otherwise.
#>
    $psModules = @(
        'ActiveDirectory'
        'GroupPolicy'
        'NetSecurity'
    )
    $success = $true
    $env:ADPS_LoadDefaultDrive = 0
    foreach ($psModule in $psModules) {
        try {
            Write-CTMLog -Log "Importing '$psModule' PowerShell module" -Type Info
            Import-Module -Name $psModule -Scope 'Global' -ErrorAction Stop | Out-Null
        } catch {
            Write-CTMLog -Log "Windows PowerShell module '$psModule' not found" -Type Error
            $success = $false
        }
    }
    return $success
}
 
function Get-CTMAdDomain {
<#
.SYNOPSIS
    Collects information about an Active Directory domain.
.DESCRIPTION
    Collects information about an Active Directory domain.
.PARAMETER Server
    Domain Controller to query.
.OUTPUTS
    AD Domain object or null.
#>
    param (
        [Parameter(Mandatory=$false)]
        [String]$Server = $null
    )
    $parameters = @{
        'ErrorAction' = 'Stop'
    }
    if (![String]::IsNullOrEmpty($Server)) {
        $parameters.Add('Server', $Server)
    }
    $domain = $null
    try {
        Write-CTMLog -Log 'Getting Active Directory domain' -Type Info
        $domain = Get-ADDomain @parameters
    } catch {
        Write-CTMLog -Log "No Active Directory Domain found. $_" -Type Error
        return $null
    }
    return $domain
}
 
function Get-CTMWritableDomainController {
<#
.SYNOPSIS
    Gets a witable Domain Controller.
.DESCRIPTION
    Gets a witable Domain Controller.
.PARAMETER Domain
    Active Directory domain object.
.PARAMETER Server
    Domain Controller to query.
.OUTPUTS
    Writable Domain Controller or null.
#>
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.ActiveDirectory.Management.ADPartition]$Domain = $null,
 
        [Parameter(Mandatory=$false)]
        [String]$Server = $null
    )
    if (!$Domain) {
        return $null
    }
    if ([String]::IsNullOrEmpty($Server) -or ($Server -ieq $Domain.PDCEmulator)) {
        return $Domain.PDCEmulator
    }
    $dcs = $Domain.ReplicaDirectoryServers
    if ($Server -iin $dcs) {
        return $Server
    }
    if ($Server.IndexOf('.') -lt 0) {
        $dcs = @() + ($dcs | Where-Object { $_ -like "$($Server).*" })
        if (($dcs.Count -eq 1) -and ![String]::IsNullOrEmpty($dcs[0])) {
            return "$($dcs[0])"
        }
    }
    Write-CTMLog -Log "No writable domain controller found named '$Server'" -Type Error
    return $null
}
 
function Check-RunAsAdmin {
    <#
.SYNOPSIS
    Checks if Run As Administrator is required.
.DESCRIPTION
    Checks if Run As Administrator is required.
.PARAMETER Server
    Domain Controller to query.
.OUTPUTS
    False if an error occurrs or if requirements are not met.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]$Server = $null
    )
    if ([String]::IsNullOrEmpty($Server)) {
        Write-CTMLog -Log 'Server can not be empty' -Type Error
        return $false
    }
    $fqdn = $null
    try {
        $wmi = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($wmi) {
            if ($wmi.ProductType -ne 2) {
                Write-CTMLog -Log 'Current machine is not a Domain Controller' -Type Info
                return $true
            }
            Write-CTMLog -Log 'Current machine is a Domain Controller' -Type Info
            $wmi = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            if ($wmi) {
                $fqdn = "$($wmi.DNSHostName).$($wmi.Domain)"
            }
        }
    } catch {
        Write-CTMLog -Log "Error while executing WMI request. $_"-Type Error
        return $false
    }
    if ([String]::IsNullOrEmpty($fqdn)) {
        Write-CTMLog -Log 'Error while building machine''s FQDN' -Type Error
        return $false
    }
    $isAdm = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdm = $isAdm.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $fqdn = ($fqdn -ieq $Server)
    $isAdm = (!$fqdn -or ($fqdn -and $isAdm))
    if (!$isAdm) {
        Write-CTMLog -Log 'The script must run as Administrator' -Type Error
    }
    return $isAdm
}
 
function Check-UserDAPermissions {
<#
.SYNOPSIS
    Checks if a user is member of Domain Admins.
.DESCRIPTION
    Checks if a user is member of Domain Admins.
.PARAMETER User
    User's SamAccountName, DN, SID or GUID.
.PARAMETER Server
    Domain Controller to query.
.OUTPUTS
    True if the user is member of Domain Admins, false otherwise.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]$User = $null,
        [Parameter(Mandatory=$false)]
        [String]$Server = $null
    )
    try {
        # Gets User's information from Active Directory.
        Write-CTMLog -Log 'Collecting current user information from Active Directory' -Type Info
        $parameters = @{
            'Identity' = $User
            'Properties' = @('DistinguishedName', 'SamAccountName', 'SID')
            'ErrorAction' = 'Stop'
        }
        if (![String]::IsNullOrEmpty($Server)) {
            $parameters.Add('Server', $Server)
        }
        $adUser = Get-ADUser @parameters
        if (!$adUser) {
            Write-CTMLog -Log "User '$User' not found in Active Directory" -Type Error
            return $false
        }
        Write-CTMLog -Log 'Checking if user is member of Domain Admins group' -Type Info
 
        # Gets Domain SID from User's SID.
        Write-CTMLog -Log 'Building domain SID from user''s SID' -Type Info
        $domainSID = $adUser.SID
        $array = "$domainSID".split('-')
        [Array]::Reverse($array)
        $rid, $array = $array
        [Array]::Reverse($array)
        $domainSID = $array -join '-'
 
        # Checks Domain Admins members.
        Write-CTMLog -Log 'Checking Domain Admins group members' -Type Info
        $parameters = @{
            'Identity' = "$($domainSID)-512"
            'Recursive' = $true
            'ErrorAction' = 'Stop'
        }
        if (![String]::IsNullOrEmpty($Server)) {
            $parameters.Add('Server', $Server)
        }
        $members = Get-ADGroupMember @parameters
        $isDA = $false
        foreach ($member in $members) {
            if ($member.distinguishedName -eq $adUser.distinguishedName) {
                $isDA = $true
                break
            }
        }
        if (!$isDA) {
            Write-CTMLog -Log "User '$userName' is not member of Domain Admins group" -Type Error
            return $false
        }
    } catch {
        Write-CTMLog -Log "Error while collecting data from Active Directory. $_" -Type Error
        return $false
    }
    return $true
}
 
function Get-CTMIPsecSettings {
<#
.SYNOPSIS
    Sets IPsec settings.
.DESCRIPTION
    Sets IPsec settings.
.PARAMETER Xml
    Xml object.
.OUTPUTS
    Hashtable or null.
#>
    param (
        [Parameter(Mandatory=$true)]
        [Xml]$Xml = $null
    )
    if ($xml -isnot [Xml]) {
        Write-CTMLog -Log 'Invalid Xml object' -Type Error
        return $null
    }
    $nodeRoot = $null
    try {
        if ($xml.Settings.Solution -ieq 'ESAE') {
            $nodeRoot = $Xml.Settings.ESAEDomain
        } else {
            $nodeRoot = $Xml.Settings.Domain
        }
    } catch {
        Write-CTMLog -Log "Invalid Xml object. $_" -Type Error
        return $null
    }
    try {
        $node = $nodeRoot.IPsec.Global
        $h = @{
            'CAPath' = $nodeRoot.CAPath
            'IPsecCrlCheck' = $node.IPsecCrlCheck.Trim()
            'IPsecExemptions' = $node.IPsecExemptions.Trim()
            'IPsecEncapsulation' = @() + $node.IPsecEncapsulation.Split(',').Trim()
            'IPsecKeyExchange' = $node.IPsecKeyExchange.Trim()
            'IPsecQMHash' = $node.IPsecQMHash.Trim()
            'IPsecMMHash' = $node.IPsecMMHash.Trim()
            'IPsecQMEncryption' = $node.IPsecQMEncryption.Trim()
            'IPsecMMEncryption' = $node.IPsecMMEncryption.Trim()
            'IPsecKeyModule' = $node.IPsecKeyModule.Trim()
            'IPsecMaxSessions' = [Int]$node.IPsecMaxSessions
        }
        Write-CTMLog -Log 'IPsec settings found' -Type Info
        return $h
    } catch {
        Write-CTMLog -Log "Error while reading IPsec settings. $_" -Type Error
    }
    return $null
}
 
function Build-MdtRules {
<#
.SYNOPSIS
    Builds MDT IPsec rules.
.DESCRIPTION
    Builds MDT IPsec rules.
.PARAMETER XmlNode
    Xml node.
.OUTPUTS
    List of IPsec rules for MDT or null.
#>
    param (
        [Parameter(Mandatory=$true)]
        [System.Xml.XmlElement]$XmlNode = $null
    )
    if (!$XmlNode) {
        Write-CTMLog -Log 'XmlNode can not be null' -Type Error
        return $null
    }
    $rules = $null
    try {
        $rules = $XmlNode.IPsec.MDTRules.Rule
    } catch {
        $rules = $null
    }
    if ($rules) {
        return $rules
    }
    Write-CTMLog -Log 'No MDT rules found: default IPsec rules will be used'
    $domain = $XmlNode.MDTFQDN
    $mdtNB = "$($XmlNode.MDTNetBIOSName)".ToUpper()
    $deployIPs = @(
        $XmlNode.DomainJoinIP.Split(',').Trim()
        ($XmlNode.MDTDHCPStartIP.Trim() + '-' + $XmlNode.MDTDHCPEndIP.Trim())
        $XmlNode.DC1IP.Split(',').Trim()
        $XmlNode.DC2IP.Split(',').Trim()
        $XmlNode.WSUSIP.Split(',').Trim()
        $XmlNode.CAIP.Split(',').Trim()
        $XmlNode.SQLIP.Split(',').Trim()
        $XmlNode.SCOMIP.Split(',').Trim()
        $XmlNode.WEFIP.Split(',').Trim()
        $XmlNode.HV1IP.Split(',').Trim()
        $XmlNode.HV2IP.Split(',').Trim()
    ) | Where-Object { ![String]::IsNullOrEmpty($_) -and ($_ -ine 'N/A') }
    $mdtRules = @(
        @{
            'Name' = "$($mdtNB)-Forest-Any-Any-Isolation"
            'Inbound' = 'Require'
            'Outbound' = 'Require'
            'LocalAddress' = @() + 'Any'
            'RemoteAddress' = @() + 'Any'
            'LocalPort' = @() + 'Any'
            'RemotePort' = @() + 'Any'
            'Protocol' = 'Any'
            'GPO' = "$($domain)\$($mdtNB) Domain IPsec Policy"
            'Location' = @() + $domain
        }
        @{
            'Name' = "$($mdtNB)-Forest-Deployment-MDT"
            'Inbound' = 'Request'
            'Outbound' = 'Request'
            'LocalAddress' = @() + 'Any'
            'RemoteAddress' = $deployIPs
            'LocalPort' = @() + 'Any'
            'RemotePort' = @() + 'Any'
            'Protocol' = 'Any'
            'GPO' = "$($domain)\$($mdtNB) Deployment IPsec Policy"
            'Location' = @() + 'Domain Controllers'
        }
    )
    if ($XmlNode.MDTWSUS -ieq 'Yes') {
        $mdtRules += @{
            'Name' = "$($mdtNB)-Forest-Deployment-WSUS"
            'Inbound' = 'Request'
            'Outbound' = 'Request'
            'LocalAddress' = @() + 'Any'
            'RemoteAddress' = $deployIPs
            'LocalPort' = @() + @(
                '8530'
                '8531'
            )
            'RemotePort' = @() + 'Any'
            'Protocol' = 'TCP'
            'GPO' = "$($domain)\$($mdtNB) WSUS IPsec Policy"
            'Location' = @() + 'Domain Controllers'
        }
        $mdtRules += @{
            'Name' = "$($mdtNB)-Forest-WSUS-WU"
            'Inbound' = 'Require'
            'Outbound' = 'Request'
            'LocalAddress' = @() + 'Any'
            'RemoteAddress' = 'Any' # proxy IP addresses?
            'LocalPort' = @() + 'Any'
            'RemotePort' = @() + 'Any' # 80, 443, 8530, or proxy port?
            'Protocol' = 'TCP'
            'GPO' = "$($domain)\$($mdtNB) WSUS IPsec Policy"
            'Location' = @() + 'Domain Controllers'
        }
    }
    $rules = @()
    foreach ($mdtRule in $mdtRules) {
        $rule = New-Object System.Object
        foreach ($k in $mdtRule.Keys) {
            $rule | Add-Member -MemberType NoteProperty -Name $k -Value $mdtRule[$k] -Force
        }
        $rules += $rule
    }
    return (@() + $rules)
}
 
function Get-CTMIPsecRules {
<#
.SYNOPSIS
    Extracts IPsec rules from an XML file.
.DESCRIPTION
    Extracts IPsec rules from an XML file.
.PARAMETER Xml
    Xml object.
.PARAMETER Domain
    Active Directory domain FQDN.
.OUTPUTS
    List of IPsec rules or null.
#>
    param (
        [Parameter(Mandatory=$true)]
        [Xml]$Xml = $null,
 
        [Parameter(Mandatory=$true)]
        [String]$Domain = $null
    )
    if ([String]::IsNullOrEmpty($Domain)) {
        Write-CTMLog -Log 'Domain can not be empty' -Type Error
        return $null
    }
    $rules = $null
    if ($Xml -isnot [Xml]) {
        Write-CTMLog -Log 'Invalid Xml object' -Type Error
        return $null
    }
    $nodeRoot = $null
    try {
        if ($Xml.Settings.Solution -ieq 'ESAE') {
            $nodeRoot = $Xml.Settings.ESAEDomain
        } else {
            $nodeRoot = $Xml.Settings.Domain
        }
    } catch {
        Write-CTMLog -Log "Invalid Xml object. $_" -Type Error
        return $null
    }
    $isHF = $false
    $isMDT = $false
    try {
        $isHF = ($Domain -ieq $nodeRoot.FQDNName)
    } catch {
        $isHF = $false
    }
    try {
        $isMDT = ($Domain -ieq $nodeRoot.MDTFQDN)
    } catch {
        $isMDT = $false
    }
    if ($isHF) {
        try {
            $rules = $nodeRoot.IPsec.Rules.Rule
        } catch {
            $rules = $null
        }
    } elseif ($isMDT) {
        $rules = Build-MdtRules -XmlNode $nodeRoot
    } else {
        try {
            $prodDomains = @() + $Xml.Settings.ProductionDomains.domain
            foreach ($prodDomain in $prodDomains) {
                try {
                    if ($Domain -ieq $prodDomain.FQDN) {
                        try {
                            $rules = $prodDomain.IPsec.Rules.Rule
                        } catch {
                            $rules = $null
                        }
                        break
                    }
                } catch {
                    Write-CTMLog -Log 'FQDN not found for a production domain (skipped)' -Type Warning
                }
            }
        } catch {
            Write-CTMLog -Log 'No production domains found in XML file' -Type Warning
        }
    }
    if (!$rules) {
        Write-CTMLog -Log "No IPsec rules found for domain '$Domain' in XML file" -Type Warning
        return $null
    } else {
        if ($rules.Count -gt 1) {
            $s = "$($rules.Count) IPsec rules to create:`r`n"
        } else {
            $s = "$($rules.Count) IPsec rule to create:`r`n"
        }
        foreach ($r in $rules) {
            $s += "- $($r.Name) (in GPO '$($r.GPO)')`r`n"
        }
        Write-CTMLog -Log $s.TrimEnd("`r`n") -Type Info
    }
    $i = 0
    $success = $true
    $list = @()
    $parameters = @{
        'MemberType' = 'NoteProperty'
        'Force' = $true
        'ErrorAction' = 'Stop'
    }
    foreach ($rule in $rules) {
        $i++
        try {
            $o = New-Object System.Object
            $d, $gpoName = (@() + $rule.GPO.Split('\'))
            if ($d -ine $Domain) {
                Write-CTMLog -Log "Domain specified in '$($rule.GPO)' does not match '$Domain'" `
                             -Type Error
                $success = $false
                continue
            }
            $members = @{
                'Name' = $rule.Name.Trim()
                'Inbound' = $rule.Inbound.Trim()
                'Outbound' = $rule.Outbound.Trim()
                'LocalAddress' = @() + $rule.LocalAddress.Split(',').Trim()
                'RemoteAddress' = @() + $rule.RemoteAddress.Split(',').Trim()
                'LocalPort' = @() + $rule.LocalPort.Split(',').Trim()
                'RemotePort' = @() + $rule.RemotePort.Split(',').Trim()
                'Protocol' = $rule.Protocol.Trim()
                'GPOName' = $gpoName.Trim()
                'GPODomain' = $Domain
                'Location' = @() + $rule.Location.Split(',').Trim()
            }
            foreach ($key in $members.Keys) {
                $o | Add-Member -Name $key -Value $members[$key] @parameters
            }
            $list += $o
        } catch {
            Write-CTMLog -Log "Error while reading rule #$($i) (skipped). $_" -Type Error
            $success = $false
        }
    }
    if (!$success) {
        return $null
    }
    return $list
}
 
function Create-CTMIPsecGpo {
<#
.SYNOPSIS
    Creates IPsec GPOs.
.DESCRIPTION
    Creates IPsec GPOs.
.PARAMETER Name
    Name of the GPO.
.PARAMETER Links
    List of Organizational Units where the GPO should be linked to.
.PARAMETER Domain
    Domain of the GPO.
.PARAMETER Server
    Active Directory Domain Controller to use.
.OUTPUTS
    Null on error or GPO object is the GPO exists.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]$Name = $null,
 
        [Parameter(Mandatory=$false)]
        [String[]]$Links = $null,
 
        [Parameter(Mandatory=$false)]
        [String]$Domain = $null,
 
        [Parameter(Mandatory=$false)]
        [String]$Server = $null
    )
    if ([String]::IsNullOrEmpty($Name)) {
        Write-CTMLog -Log 'Name can not be empty' -Type Error
        return $null
    }
    $parameters = @{
        'ErrorAction' = 'Stop'
    }
    if (![String]::IsNullOrEmpty($Domain)) {
        $parameters.Add('Domain', $Domain)
    }
    if (![String]::IsNullOrEmpty($Server)) {
        $parameters.Add('Server', $Server)
    }
 
    # Creates GPO.
    $gpo = $null
    try {
        $gpo = Get-GPO -Name $Name @parameters
        Write-CTMLog -Log "GPO '$($Name)' already exists" -Type Info
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) {
            $gpo = $null
        } else {
            Write-CTMLog -Log "Unable to get GPO $($Name). $_" -Type Error
            return $null
        }
    }
    if (!$gpo) {
        try {
            $gpo = New-GPO -Name $Name @parameters
            $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled
            Write-CTMLog -Log "GPO '$($Name)' created" -Type Info
        } catch {
            Write-CTMLog -Log "Unable to create GPO $($Name). $_" -Type Error
            return $null
        }
    }
    if ($gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled) {
        Write-CTMLog -Log "Status of GPO '$($Name)' is not defined to 'UserSettingsDisabled'" `
                     -Type Warning
    }
    $Name = $gpo.DisplayName
 
    # Links GPO.
    foreach ($ouName in $Links) {
        if ([String]::IsNullOrEmpty($ouName)) {
            continue
        }
        $dn = $null
        $enforced = 'No'
        if ($ouName -ieq $Domain) {
            $dn = 'DC=' + $Domain.Replace('.', ',DC=')
            #$enforced = 'Yes'
        } else {
            try {
                $ou = Get-ADOrganizationalUnit -Server $Server -Filter "Name -eq '$ouName'" `
                                               -ErrorAction Stop
                if (!$ou) {
                    Write-CTMLog -Log "Can not link GPO to '$($ouName)' (OU not found)" -Type Warning
                    continue
                }
                if ($ou -isnot [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]) {
                    Write-CTMLog -Log "Can not link GPO: multiple OUs with name '$($ouName)' found" `
                                 -Type Warning
                    continue
                }
                $dn = $ou.DistinguishedName
            } catch {
                Write-CTMLog -Log "Can not link GPO to '$($ouName)'. $_" -Type Warning
                $dn = $null
            }
        }
        if ([String]::IsNullOrEmpty($dn)) {
            continue
        }
        $parameters = @{
            'Target' = $dn
            'Name' = $Name
            'LinkEnabled' = 'Yes'
            'Enforced' = $enforced
            'ErrorAction' = 'Stop'
        }
        try {
            New-GPLink @parameters | Out-Null
            Write-CTMLog -Log "GPO '$Name' has been linked to '$dn'" -Type Info
        } catch {
            Write-CTMLog -Log "GPO '$Name' is already linked to '$dn'" -Type Info
        }
    }
    return $gpo
}
 
function Update-CTMIPsecGpoSettings {
<#
.SYNOPSIS
    Updates IPsec GPOs settings.
.DESCRIPTION
    Updates IPsec GPOs settings.
.PARAMETER Name
    GPO's name.
.PARAMETER Mode
    IPsec mode.
.PARAMETER Domain
    GPO's domain FQDN.
.PARAMETER Settings
    IPsec settings.
.PARAMETER Rules
    List of IPsec rules.
.PARAMETER Server
    Active Directory Domain Controller to use.
.PARAMETER Cache
    Use a cache to update the GPO.
.OUTPUTS
    True on success, false otherwise.
#>
    param (
        [Parameter(Mandatory=$true)]
        [String]$Name = $null,
 
        [Parameter(Mandatory=$false)]
        [ValidateSet('Request', 'Require')]
        [String]$Mode = 'Request',
 
        [Parameter(Mandatory=$true)]
        [String]$Domain = $null,
 
        [Parameter(Mandatory=$false)]
        [Hashtable]$Settings = $null,
 
        [Parameter(Mandatory=$false)]
        [Array]$Rules = $null,
 
        [Parameter(Mandatory=$false)]
        [String]$Server = $null,
 
        [Parameter(Mandatory=$false)]
        [Switch]$Cache = $true
    )
    if ([String]::IsNullOrEmpty($Name)) {
        Write-CTMLog -Log 'Name can not be empty' -Type Error
        return $false
    }
    if ([String]::IsNullOrEmpty($Domain)) {
        Write-CTMLog -Log 'Domain can not be empty' -Type Error
        return $false
    }
    $gpoFqdn = "$($Domain)\$($Name)"
    $parameters = @{
        'ErrorAction' = 'Stop'
    }
    if (![String]::IsNullOrEmpty($Server)) {
        $parameters.Add('DomainController', $Server)
    }
 
    # Creates session.
    $session = $null
    if ($Cache) {
        try {
            $session = Open-NetGPO -PolicyStore $gpoFqdn @parameters
            Write-CTMLog -Log 'GPO has been cached' -Type Info
        } catch {
            Write-CTMLog -Log "Unable to cache the GPO (is PDCe available?). $_" -Type Error
            return $false
        }
    }
 
    # Removes IPsec configuration.
    $parameters = @{
        'ErrorAction' = 'Stop'
    }
    if ($session) {
        $parameters.Add('GPOSession', $session)
    } else {
        $parameters.Add('PolicyStore', $gpoFqdn)
    }
    try {
        Remove-NetIPsecPhase1AuthSet -All @parameters
        Remove-NetIPsecMainModeCryptoSet -All @parameters
        Remove-NetIPsecMainModeRule -All @parameters
        Remove-NetIPsecQuickModeCryptoSet -All @parameters
        Remove-NetIPsecRule -All @parameters
        Write-CTMLog -Log 'IPsec configuration removed from the GPO' -Type Info
    } catch {
        Write-CTMLog -Log "Error while deleting IPsec configuration. $_" -Type Error
        return $false
    }
 
    # Sets Firewall settings.
    $fw = $null
    try {
        $fw = Get-NetFirewallSetting @parameters
        Write-CTMLog -Log 'Current firewall settings reviewed' -Type Info
    } catch {
        Write-CTMLog -Log "Unable to get firewall settings. $_" -Type Error
        return $false
    }
    try {
        $fw | Set-NetFirewallSetting -Exemptions $Settings['IPsecExemptions'] `
                                     -CertValidationLevel $Settings['IPsecCrlCheck'] `
                                     -ErrorAction stop | Out-Null
        Write-CTMLog -Log 'Firewall settings updated' -Type Info
    } catch {
        Write-CTMLog -Log "Unable to configure firewall settings. $_" -Type Error
        return $false
    }
    try {
        $logFile = '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log'
        Set-NetFirewallProfile -Profile Domain, Public, Private `
                               -Enabled True `
                               -DefaultInboundAction Block `
                               -DefaultOutboundAction Allow `
                               -AllowLocalIPsecRules True `
                               -EnableStealthModeForIPsec True `
                               -LogAllowed True `
                               -LogBlocked True `
                               -LogMaxSizeKilobytes 32767 `
                               -LogFileName $logFile `
                               @parameters | Out-Null
        Write-CTMLog -Log 'Firewall profiles updated' -Type Info
    } catch {
        Write-CTMLog -Log "Unable to configure firewall profiles. $_" -Type Error
        return $false
    }
 
    # Creates Phase 1 authentication set.
    $p1AuthSetName = 'Computer Certificate Auth Set'
    $p1AuthSet = $null
    try {
        $p1AuthSet = Get-NetIPsecPhase1AuthSet -DisplayName $p1AuthSetName @parameters
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) {
            $p1AuthSet = $null
        } else {
            Write-CTMLog -Log "Unable to get phase 1 authentication set '$p1AuthSetName'. $_" -Type Error
            return $false
        }
    }
    if (!$p1AuthSet) {
        try {
            $p1Proposal = New-NetIPsecAuthProposal -Machine `
                                                   -Cert `
                                                   -Authority $Settings['CAPath'] `
                                                   -AuthorityType Root `
                                                   -ErrorAction Stop
            $p1AuthSet = New-NetIPsecPhase1AuthSet -DisplayName $p1AuthSetName `
                                                   -Proposal $p1Proposal `
                                                   @parameters
            Write-CTMLog -Log "Phase 1 authentication set '$p1AuthSetName' created" -Type Info
        } catch {
            Write-CTMLog -Log "Unable to create phase 1 authentication set. $_" -Type Error
            return $false
        }
    } else {
        Write-CTMLog -Log 'Using existing phase 1 authentication set' -Type Info
    }
 
    # Creates main mode cryptographic sets.
    $mmCryptoSetName = 'Main Mode Crypto Set'
    $mmCryptoSet = $null
    try {
        $mmCryptoSet = Get-NetIPsecMainModeCryptoSet -DisplayName $mmCryptoSetName @parameters
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) {
            $mmCryptoSet = $null
        } else {
            Write-CTMLog -Log "Unable to get main mode cryptographic sets '$mmCryptoSetName'. $_" -Type Error
            return $false
        }
    }
    if (!$mmCryptoSet) {
        try {
            $mmProposal = New-NetIPsecMainModeCryptoProposal -Encryption $Settings['IPsecMMEncryption'] `
                                                             -Hash $Settings['IPsecMMHash'] `
                                                             -KeyExchange $Settings['IPsecKeyExchange'] `
                                                             -ErrorAction stop
            $mmCryptoSet = New-NetIPsecMainModeCryptoSet -DisplayName $mmCryptoSetName `
                                                         -Proposal $mmProposal `
                                                         -MaxSessions $Settings['IPsecMaxSessions'] `
                                                         -ForceDiffieHellman $true `
                                                         @parameters
            Write-CTMLog -Log "Main mode cryptographic sets '$mmCryptoSetName' created" -Type Info
        } catch {
            Write-CTMLog -Log "Unable to create main mode cryptographic sets. $_" -Type Error
            return $false
        }
    } else {
        Write-CTMLog -Log 'Using existing main mode cryptographic sets' -Type Info
    }
 
    # Creates main mode rule.
    $mmRuleName = 'Main Mode Rule'
    $mmRule = $null
    try {
        $mmRule = Get-NetIPsecMainModeRule -DisplayName $mmRuleName @parameters
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) {
            $mmRule = $null
        } else {
            Write-CTMLog -Log "Unable to get main mode rule '$mmRuleName'. $_" -Type Error
            return $false
        }
    }
    if (!$mmRule) {
        try {
            $mmRule = New-NetIPsecMainModeRule -DisplayName $mmRuleName `
                                               -MainModeCryptoSet $mmCryptoSet.Name `
                                               -Phase1AuthSet $p1AuthSet.Name `
                                               @parameters
            Write-CTMLog -Log "Main mode rule '$mmRuleName' created" -Type Info
        } catch {
            Write-CTMLog -Log "Unable to create main mode rule. $_" -Type Error
            return $false
        }
    } else {
        Write-CTMLog -Log 'Using existing main mode rule' -Type Info
    }
 
    # Creates quick mode cryptographic sets.
    $qmCryptoSetName = 'Phase 2 Crypto Set'
    $qmCryptoSet = $null
    try {
        $qmCryptoSet = Get-NetIPsecQuickModeCryptoSet -DisplayName $qmCryptoSetName @parameters
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) {
            $qmCryptoSet = $null
        } else {
            Write-CTMLog -Log "Unable to get quick mode cryptographic set '$qmCryptoSetName'. $_" -Type Error
            return $false
        }
    }
    if (!$qmCryptoSet) {
        $parametersQm = @{
            'Encapsulation' = $Settings['IPsecEncapsulation']
            'Encryption' = $Settings['IPsecQMEncryption']
            'ErrorAction' = 'Stop'
        }
        if ('AH' -iin $Settings['IPsecEncapsulation']) {
            $parametersQm.Add('AHHash', $Settings['IPsecQMHash'])
        }
        if ('ESP' -iin $Settings['IPsecEncapsulation']) {
            $parametersQm.Add('ESPHash', $Settings['IPsecQMHash'])
        }
        try {
            $qmProposal = New-NetIPsecQuickModeCryptoProposal @parametersQm
            $qmCryptoSet = New-NetIPsecQuickModeCryptoSet -DisplayName $qmCryptoSetName `
                                                          -Proposal $qmProposal `
                                                          -PerfectForwardSecrecyGroup SameAsMainMode `
                                                          @parameters
            Write-CTMLog -Log "Quick mode cryptographic sets '$qmCryptoSetName' created" -Type Info
        } catch {
            Write-CTMLog -Log "Unable to create quick mode cryptographic sets. $_" -Type Error
            return $false
        }
    } else {
        Write-CTMLog -Log 'Using existing quick mode cryptographic set' -Type Info
    }
 
    # Creates IPsec rule.
    $inboundSec = $null
    $outboundSec = $null
    foreach ($rule in $Rules) {
        $inboundSec = $rule.Inbound
        $outboundSec = $rule.Outbound
        if ($Mode -eq 'Request') {
            $inboundSec = $Mode
            $outboundSec = $Mode
        }
        $parametersRule = @{
            'DisplayName' = $rule.Name
            'InboundSecurity' = $inboundSec
            'OutboundSecurity' = $outboundSec
            'QuickModeCryptoSet' = $qmCryptoSet.Name
            'Phase1AuthSet' = $p1AuthSet.Name
            'KeyModule' = $Settings['IPsecKeyModule']
            'LocalAddress' = $rule.LocalAddress
            'RemoteAddress' = $rule.RemoteAddress
            'Protocol' = $rule.Protocol
            'Mode' = 'Transport'
            'Profile' = 'Any'
        }
        if ($rule.Protocol -iin @('TCP', 'UDP')) {
            $parametersRule.Add('LocalPort', $rule.LocalPort)
            $parametersRule.Add('RemotePort', $rule.RemotePort)
        }
        $parametersRule += $parameters
        $ipsecRule = $null
        try {
            $ipsecRule = New-NetIPsecRule @parametersRule
            Write-CTMLog -Log "IPsec rule '$($rule.Name)' created" -Type Info
        } catch {
            Write-CTMLog -Log "Unable to create IPsec rule '$($rule.Name)'. $_" -Type Error
            return $false
        }
    }
 
    # Closes session.
    try {
        if ($session) {
            Save-NetGPO -GPOSession $session -ErrorAction Stop
            Write-CTMLog -Log 'GPO saved and updated' -Type Info
        }
    } catch {
        Write-CTMLog -Log "Unable to update the GPO. $_" -Type Error
        return $false
    }
    return $true
}
 
function Get-CTMConfirmation {
<#
.SYNOPSIS
    Asks confirmation.
.DESCRIPTION
    Asks confirmation.
.OUTPUTS
    True if the user want to continue, false otherwise.
#>
    param (
        [Parameter(Mandatory=$false)]
        [String]$Message = 'Do you want to continue ([Y]es or [N]o)?'
    )
    try {
        $answer = Read-Host -Prompt $Message -ErrorAction Stop
        return ($answer -iin @('y', 'yes'))
    } catch {
        Write-CTMLog -Log "An error occurred while asking for confirmation. $_" -Type Error
    }
    return $false
}
 
function Set-CTMIPsecGpos {
<#
.SYNOPSIS
    Sets IPsec GPOs.
.DESCRIPTION
    Sets IPsec GPOs.
.PARAMETER Rules
    List of IPsec rules.
.PARAMETER Settings
    IPsec settings.
.PARAMETER Mode
    IPsec Mode.
.PARAMETER Server
    Active Directory Domain Controller to use.
.PARAMETER UseCache
    Should the GPO be cached?
.OUTPUTS
    True on success, false otherwise.
#>
    param (
        [Parameter(Mandatory=$true)]
        [Array]$Rules = $null,
 
        [Parameter(Mandatory=$true)]
        [Hashtable]$Settings = $null,
 
        [Parameter(Mandatory=$false)]
        [ValidateSet('Request', 'Require')]
        [String]$Mode = 'Request',
 
        [Parameter(Mandatory=$false)]
        [String]$Server = $null,
 
        [Parameter(Mandatory=$false)]
        [Switch]$UseCache = $true
    )
    if ($Rules -isnot [Array]) {
        Write-CTMLog -Log 'Rules can not be empty' -Type Error
        return $false
    }
    if ($Settings -isnot [Hashtable]) {
        Write-CTMLog -Log 'Settings can not be empty' -Type Error
        return $false
    }
 
    # Gets IPsec GPOs from IPsec rules.
    Write-CTMLog -Log 'Listing GPOs from IPsec rules' -Type Title2
    $domain = $Rules | Select-Object -ExpandProperty 'GPODomain' -Unique
    if ($domain -isnot [String]) {
        Write-CTMLog -Log 'All GPOs must be part of the same domain' -Type Error
        return $false
    }
    $gpoNames = @() + ($Rules | Select-Object -ExpandProperty 'GPOName' -Unique)
    $gpoLinks = @{}
    foreach ($rule in $Rules) {
        $n = $rule.GPOName.ToLower()
        if (!$gpoLinks.ContainsKey($n)) {
            $gpoLinks.Add($n, (@() + $rule.Location))
            Write-CTMLog -Log "GPO '$($rule.GPOName)' found in IPsec rules" -Type Info
        } else {
            $list = $gpoLinks[$n] + $rule.Location | Select-Object -Unique
            $gpoLinks[$n] = (@() + $list)
        }
    }
 
    # Creates IPSec GPOs.
    $gpos = @()
    foreach ($gpoName in $gpoNames) {
        if ([String]::IsNullOrEmpty($gpoName)) {
            continue
        }
        $links = $null
        $n = $gpoName.ToLower()
        if ($gpoLinks.ContainsKey($n)) {
            $links = $gpoLinks[$n]
        }
        Write-CTMLog -Log "Creating GPO '$gpoName'" -Type Title2
        $gpo = Create-CTMIPsecGpo -Name $gpoName -Domain $domain -Server $Server -Links $links
        if (!$gpo) {
            return $false
        }
        $gpos += $gpo
    }
 
    # Updates IPsec GPOs.
    foreach ($gpo in $gpos) {
        if (!$gpo) {
            continue
        }
        Write-CTMLog -Log "Updating GPO '$($gpo.DisplayName)'" -Type Title2
        $r = $Rules | Where-Object { $_.GPOName -ieq $gpo.DisplayName }
        $parameters = @{
            'Name' = $gpo.DisplayName
            'Domain' = $domain
            'Settings' = $Settings
            'Rules' = $r
            'Mode' = $Mode
            'Server' = $Server
            'Cache' = $UseCache
        }
        if (!(Update-CTMIPsecGpoSettings @parameters)) {
            return $false
        }
    }
 
    return $true
}
 
function Configure-CTMIPsec {
<#
.SYNOPSIS
    This script configures IPsec rules.
.DESCRIPTION
    This script configures IPsec rules. Settings are collected from XML file.
.PARAMETER ConfigFile
    Path to the XML configuration file containing IPsec rules description.
.PARAMETER Mode
    IPsec mode to use.
.PARAMETER Domain
    FQDN of the targeted Active Directory. If not specified, the current
    Active Directory domain is used.
.PARAMETER Server
    Domain Controller to use for write operations. If not specified, PDC
    Emulator will be used.
.PARAMETER Confirm
    If true, confirmation is required to execute the script.
.PARAMETER UseCache
    If true (default value) GPO are cached, settings are changed locally,
    then the GPO is saved and finally updated on the DC.
.OUTPUTS
    False if an error occurs, true otherwise.
#>
    [CmdletBinding(DefaultParametersetname='All')]
    param (
        [Parameter(Mandatory=$false)]
        [ValidateScript({ (![String]::IsNullOrEmpty($_) -and (Test-Path -Path $_ -IsValid)) })]
        [String]$ConfigFile = (Join-Path -Path $PSScriptRoot -ChildPath '..\Config.xml'),
 
        [Parameter(Mandatory=$false)]
        [ValidateSet('Request', 'Require')]
        [String]$Mode = 'Request',
 
        [Parameter(Mandatory=$false)]
        [Alias('DNSRoot')]
        [Object]$Domain = $null,
 
        [Parameter(Mandatory=$false)]
        [String]$Server = $null,
 
        [Parameter(Mandatory=$false)]
        [Switch]$Confirm = $true,
 
        [Parameter(Mandatory=$false)]
        [Switch]$UseCache = $true
    )
 
    # Checks Windows version.
    Write-CTMLog -Log 'Checking Windows version' -Type Title1
    $version = Get-CTMWindowsVersion
    if ($version -lt [Version]'6.3') {
        Write-CTMLog -Log 'Windows 6.3 or later is required to run the script' -Type Error
        return $false
    }
 
    # Imports required PowerShell modules.
    Write-CTMLog -Log 'Importing required PowerShell modules' -Type Title1
    if (!(Import-CTMPsModules)) {
        return $false
    }
 
    # Checks script's parameters.
    Write-CTMLog -Log 'Checking script''s parameters' -Type Title1
    if ([String]::IsNullOrEmpty($Domain)) {
        $Domain = $env:USERDNSDOMAIN
    }
    $Domain = Get-CTMAdDomain -Server $Server
    if (!$Domain) {
        return $false
    }
    Write-CTMLog -Log "Target domain is: $($Domain.DNSRoot)" -Type Info
    $Server = Get-CTMWritableDomainController -Domain $Domain -Server $Server
    if ([String]::IsNullOrEmpty($Server)) {
        return $false
    }
    Write-CTMLog -Log "Target server is: $($Server)" -Type Info
    Write-CTMLog -Log "IPsec mode is: $($Mode)" -Type Info
    if (!(Check-RunAsAdmin -Server $Server)) {
        return $false
    }
 
    # Checks if current user is Domain Administrator.
    #Write-CTMLog -Log 'Checking if current user is Domain Administrator' -Type Title1
    #if (!(Check-UserDAPermissions -User $env:USERNAME -Server $Server)) {
    #    return $false
    #}
 
    # Checks XML.
    Write-CTMLog -Log 'Checking XML configuration file' -Type Title1
    [Xml]$xml = Check-CTMConfigXML -Path $ConfigFile -Domain $Domain.DNSRoot
    if (!$xml) {
        return $false
    }
 
    # Gets IPsec settings.
    Write-CTMLog -Log 'Getting IPsec settings' -Type Title1
    $settings = Get-CTMIPsecSettings -Xml $xml
    if (!$settings) {
        return $false
    }
 
    # Builds IPsec rules.
    Write-CTMLog -Log 'Building IPsec rules' -Type Title1
    $rules = Get-CTMIPsecRules -Xml $xml -Domain $Domain.DNSRoot
    if (!$rules) {
        return $false
    }
 
    # Asks for confirmation.
    if ($Confirm) {
        Write-CTMLog -Log 'Asking for confirmation to continue' -Type Title1
        if (!(Get-CTMConfirmation)) {
            return $false
        }
    }
 
    # Sets GPOs.
    Write-CTMLog -Log "Setting GPOs with mode $($Mode)" -Type Title1
    if (!(Set-CTMIPsecGpos -Settings $settings `
                           -Rules $rules `
                           -Mode $Mode `
                           -Server $Server `
                           -UseCache:$UseCache)) {
        return $false
    }
    return $true
}
 
$success = Configure-CTMIPsec @PSBoundParameters
if ($success) {
    Write-CTMLog -Log 'Script successfully executed' -Type Success
} else {
    Write-CTMLog -Log 'Failed to execute the script' -Type Error
}
$success

