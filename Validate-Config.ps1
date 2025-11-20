<#
.SYNOPSIS
    Validates Config.xml against Network-Security-Utility.ps1 requirements.
.DESCRIPTION
    Checks XML structure, required fields, and compatibility.
#>

param (
    [String]$ConfigPath = ".\Config.xml"
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Config.xml Validation Report" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$validationErrors = @()
$validationWarnings = @()
$validationPassed = 0

# Test 1: File Exists
Write-Host "[TEST 1] Checking file exists..." -ForegroundColor Yellow
if (Test-Path $ConfigPath) {
    Write-Host "  [OK] PASSED: File found" -ForegroundColor Green
    $validationPassed++
} else {
    Write-Host "  [X] FAILED: File not found: $ConfigPath" -ForegroundColor Red
    $validationErrors += "Config file not found"
    exit 1
}

# Test 2: XML Parse
Write-Host "`n[TEST 2] Parsing XML..." -ForegroundColor Yellow
try {
    [xml]$xml = Get-Content -Path $ConfigPath -ErrorAction Stop
    Write-Host "  [OK] PASSED: XML is well-formed" -ForegroundColor Green
    $validationPassed++
} catch {
    Write-Host "  [X] FAILED: XML parse error: $($_.Exception.Message)" -ForegroundColor Red
    $validationErrors += "XML parse error: $($_.Exception.Message)"
    exit 1
}

# Test 3: Root Node Structure
Write-Host "`n[TEST 3] Validating root structure..." -ForegroundColor Yellow
if ($xml.Settings) {
    Write-Host "  [OK] PASSED: Root <Settings> node found" -ForegroundColor Green
    $validationPassed++
} else {
    Write-Host "  [X] FAILED: Missing <Settings> root node" -ForegroundColor Red
    $validationErrors += "Missing <Settings> root node"
}

# Test 4: Domain Node
Write-Host "`n[TEST 4] Checking domain configuration..." -ForegroundColor Yellow
$domainNode = $null
if ($xml.Settings.ESAEDomain) {
    $domainNode = $xml.Settings.ESAEDomain
    Write-Host "  [OK] PASSED: Using ESAEDomain node" -ForegroundColor Green
    Write-Host "    - NetBIOS: $($domainNode.NetBIOSName)" -ForegroundColor Gray
    Write-Host "    - FQDN: $($domainNode.FQDNName)" -ForegroundColor Gray
    Write-Host "    - DN: $($domainNode.DN)" -ForegroundColor Gray
    $validationPassed++
} elseif ($xml.Settings.Domain) {
    $domainNode = $xml.Settings.Domain
    Write-Host "  [OK] PASSED: Using Domain node" -ForegroundColor Green
    $validationPassed++
} else {
    Write-Host "  [X] FAILED: No ESAEDomain or Domain node found" -ForegroundColor Red
    $validationErrors += "Missing domain configuration node"
}

# Test 5: IPsec Global Settings
Write-Host "`n[TEST 5] Validating IPsec Global Settings..." -ForegroundColor Yellow
if ($domainNode.IPsec.Global) {
    $global = $domainNode.IPsec.Global
    $requiredSettings = @(
        'IPsecCrlCheck', 'IPsecExemptions', 'IPsecEncapsulation',
        'IPsecKeyExchange', 'IPsecQMHash', 'IPsecMMHash',
        'IPsecQMEncryption', 'IPsecMMEncryption', 'IPsecKeyModule', 'IPsecMaxSessions'
    )
    
    $missingSettings = @()
    foreach ($setting in $requiredSettings) {
        if ([String]::IsNullOrWhiteSpace($global.$setting)) {
            $missingSettings += $setting
        }
    }
    
    if ($missingSettings.Count -eq 0) {
        Write-Host "  [OK] PASSED: All required IPsec settings present" -ForegroundColor Green
        Write-Host "    - CRL Check: $($global.IPsecCrlCheck)" -ForegroundColor Gray
        Write-Host "    - Exemptions: $($global.IPsecExemptions)" -ForegroundColor Gray
        Write-Host "    - Encapsulation: $($global.IPsecEncapsulation)" -ForegroundColor Gray
        Write-Host "    - Key Exchange: $($global.IPsecKeyExchange)" -ForegroundColor Gray
        Write-Host "    - QM Encryption: $($global.IPsecQMEncryption)" -ForegroundColor Gray
        Write-Host "    - MM Encryption: $($global.IPsecMMEncryption)" -ForegroundColor Gray
        Write-Host "    - QM Hash: $($global.IPsecQMHash)" -ForegroundColor Gray
        Write-Host "    - MM Hash: $($global.IPsecMMHash)" -ForegroundColor Gray
        Write-Host "    - Key Module: $($global.IPsecKeyModule)" -ForegroundColor Gray
        Write-Host "    - Max Sessions: $($global.IPsecMaxSessions)" -ForegroundColor Gray
        $validationPassed++
    } else {
        Write-Host "  [X] FAILED: Missing required settings:" -ForegroundColor Red
        foreach ($missing in $missingSettings) {
            Write-Host "    - $missing" -ForegroundColor Yellow
            $validationErrors += "Missing setting: $missing"
        }
    }
} else {
    Write-Host "  [X] FAILED: No IPsec.Global node found" -ForegroundColor Red
    $validationErrors += "Missing IPsec.Global configuration"
}

# Test 6: IPsec Rules
Write-Host "`n[TEST 6] Validating IPsec Rules..." -ForegroundColor Yellow
if ($domainNode.IPsec.Rules.Rule) {
    $rules = $domainNode.IPsec.Rules.Rule
    $ruleCount = @($rules).Count
    Write-Host "  [OK] PASSED: Found $ruleCount IPsec rules" -ForegroundColor Green
    $validationPassed++
    
    # Check first 3 rules for required fields
    $requiredRuleFields = @('Name', 'Inbound', 'Outbound', 'LocalAddress', 'RemoteAddress', 'LocalPort', 'RemotePort', 'Protocol')
    $sampleRules = @($rules) | Select-Object -First 3
    
    Write-Host "`n  Sample Rules:" -ForegroundColor Cyan
    foreach ($rule in $sampleRules) {
        $missingFields = @()
        foreach ($field in $requiredRuleFields) {
            if ([String]::IsNullOrWhiteSpace($rule.$field)) {
                $missingFields += $field
            }
        }
        
        if ($missingFields.Count -eq 0) {
            Write-Host "    [OK] $($rule.Name)" -ForegroundColor Green
            Write-Host "      - Inbound: $($rule.Inbound) | Outbound: $($rule.Outbound)" -ForegroundColor Gray
            Write-Host "      - Protocol: $($rule.Protocol) | LocalPort: $($rule.LocalPort) | RemotePort: $($rule.RemotePort)" -ForegroundColor Gray
            Write-Host "      - LocalAddress: $($rule.LocalAddress)" -ForegroundColor Gray
            Write-Host "      - RemoteAddress: $($rule.RemoteAddress)" -ForegroundColor Gray
            if ($rule.GPO) {
                Write-Host "      - GPO: $($rule.GPO)" -ForegroundColor Gray
            }
            if ($rule.Location) {
                Write-Host "      - Location: $($rule.Location)" -ForegroundColor Gray
            }
        } else {
            Write-Host "    [!] $($rule.Name) - Missing fields: $($missingFields -join ', ')" -ForegroundColor Yellow
            $validationWarnings += "Rule '$($rule.Name)' missing: $($missingFields -join ', ')"
        }
    }
    
    if ($ruleCount -gt 3) {
        Write-Host "    ... and $($ruleCount - 3) more rules" -ForegroundColor Gray
    }
} else {
    Write-Host "  [!] WARNING: No IPsec rules found" -ForegroundColor Yellow
    $validationWarnings += "No IPsec rules defined"
}

# Test 7: Cryptographic Validation
Write-Host "`n[TEST 7] Validating Cryptographic Settings..." -ForegroundColor Yellow
$cryptoValid = $true

# Valid options (from the script)
$validEncapsulation = @('None', 'AH', 'ESP', 'AH,ESP', 'ESP,AH')
$validKeyExchange = @('DH1', 'DH2', 'DH14', 'DH19', 'DH20', 'DH24', 'ECDHP256', 'ECDHP384')
$validQMHash = @('MD5', 'SHA1', 'SHA256', 'SHA384', 'AESGMAC128', 'AESGMAC192', 'AESGMAC256')
$validMMHash = @('MD5', 'SHA1', 'SHA256', 'SHA384')
$validQMEncryption = @('DES', 'DES3', 'AES128', 'AES192', 'AES256', 'AESGCM128', 'AESGCM192', 'AESGCM256', 'None')
$validMMEncryption = @('DES', 'DES3', 'AES128', 'AES192', 'AES256')

if ($domainNode.IPsec.Global) {
    $global = $domainNode.IPsec.Global
    
    if ($global.IPsecEncapsulation -notin $validEncapsulation) {
        Write-Host "  [X] Invalid Encapsulation: $($global.IPsecEncapsulation)" -ForegroundColor Red
        Write-Host "    Valid options: $($validEncapsulation -join ', ')" -ForegroundColor Yellow
        $cryptoValid = $false
        $validationErrors += "Invalid Encapsulation value"
    }
    
    if ($global.IPsecKeyExchange -notin $validKeyExchange) {
        Write-Host "  [X] Invalid Key Exchange: $($global.IPsecKeyExchange)" -ForegroundColor Red
        Write-Host "    Valid options: $($validKeyExchange -join ', ')" -ForegroundColor Yellow
        $cryptoValid = $false
        $validationErrors += "Invalid KeyExchange value"
    }
    
    if ($global.IPsecQMHash -notin $validQMHash) {
        Write-Host "  [X] Invalid QM Hash: $($global.IPsecQMHash)" -ForegroundColor Red
        Write-Host "    Valid options: $($validQMHash -join ', ')" -ForegroundColor Yellow
        $cryptoValid = $false
        $validationErrors += "Invalid QMHash value"
    }
    
    if ($global.IPsecMMHash -notin $validMMHash) {
        Write-Host "  [X] Invalid MM Hash: $($global.IPsecMMHash)" -ForegroundColor Red
        Write-Host "    Valid options: $($validMMHash -join ', ')" -ForegroundColor Yellow
        $cryptoValid = $false
        $validationErrors += "Invalid MMHash value"
    }
    
    if ($global.IPsecQMEncryption -notin $validQMEncryption) {
        Write-Host "  [X] Invalid QM Encryption: $($global.IPsecQMEncryption)" -ForegroundColor Red
        Write-Host "    Valid options: $($validQMEncryption -join ', ')" -ForegroundColor Yellow
        $cryptoValid = $false
        $validationErrors += "Invalid QMEncryption value"
    }
    
    if ($global.IPsecMMEncryption -notin $validMMEncryption) {
        Write-Host "  [X] Invalid MM Encryption: $($global.IPsecMMEncryption)" -ForegroundColor Red
        Write-Host "    Valid options: $($validMMEncryption -join ', ')" -ForegroundColor Yellow
        $cryptoValid = $false
        $validationErrors += "Invalid MMEncryption value"
    }
    
    if ($cryptoValid) {
        Write-Host "  [OK] PASSED: All cryptographic settings are valid" -ForegroundColor Green
        $validationPassed++
    }
} else {
    Write-Host "  [X] FAILED: Cannot validate without IPsec.Global settings" -ForegroundColor Red
}

# Test 8: Additional Configuration Elements
Write-Host "`n[TEST 8] Checking additional configuration..." -ForegroundColor Yellow
$additionalElements = @()

if ($domainNode.CAPath) {
    $additionalElements += "CA Path: $($domainNode.CAPath)"
}
if ($xml.Settings.Azure) {
    $additionalElements += "Azure configuration present"
}
if ($xml.Settings.ProductionDomains) {
    $domainCount = @($xml.Settings.ProductionDomains.domain).Count
    $additionalElements += "Production domains: $domainCount"
}

if ($additionalElements.Count -gt 0) {
    Write-Host "  [i] Additional configuration found:" -ForegroundColor Cyan
    foreach ($element in $additionalElements) {
        Write-Host "    - $element" -ForegroundColor Gray
    }
} else {
    Write-Host "  [i] Only IPsec configuration present" -ForegroundColor Cyan
}

# Test 9: MDT/Deployment Configuration (Optional)
Write-Host "`n[TEST 9] Checking MDT/Deployment configuration..." -ForegroundColor Yellow
$mdtFields = @()
$mdtIPs = @()

# Check for production vs non-production XML
$isProdXml = $true
try {
    if ($domainNode.CAIP -match '^.+$') {
        $isProdXml = $false
    }
} catch {
    $isProdXml = $true
}

if (-not $isProdXml) {
    # Check for name fields
    if ($domainNode.NetBIOSName) {
        $mdtFields += "NetBIOSName: $($domainNode.NetBIOSName)"
    }
    if ($domainNode.FQDNName) {
        $mdtFields += "FQDNName: $($domainNode.FQDNName)"
    }
    if ($domainNode.MDTNetBIOSName) {
        $mdtFields += "MDTNetBIOSName: $($domainNode.MDTNetBIOSName)"
    }
    if ($domainNode.MDTFQDN) {
        $mdtFields += "MDTFQDN: $($domainNode.MDTFQDN)"
    }
    
    # Check infrastructure IPs
    $ipFieldNames = @('DC1IP', 'DC2IP', 'WSUSIP', 'CAIP', 'SQLIP', 'SCOMIP', 'WEFIP', 'HV1IP', 'HV2IP', 'DomainJoinIP')
    foreach ($ipField in $ipFieldNames) {
        if ($domainNode.$ipField -and $domainNode.$ipField -ne 'N/A') {
            $mdtFields += "$ipField present"
            $mdtIPs += $domainNode.$ipField.Split(',').Trim() | Where-Object { -not [String]::IsNullOrWhiteSpace($_) -and $_ -ine 'N/A' }
        }
    }
    
    # Check DHCP range
    if ($domainNode.MDTDHCPStartIP -and $domainNode.MDTDHCPEndIP) {
        $mdtFields += "DHCP Range configured"
        $mdtIPs += ($domainNode.MDTDHCPStartIP.Trim() + '-' + $domainNode.MDTDHCPEndIP.Trim())
    }
    
    # Check WSUS flag
    if ($domainNode.MDTWSUS) {
        $mdtFields += "MDTWSUS: $($domainNode.MDTWSUS)"
    }
    
    if ($mdtFields.Count -gt 0) {
        Write-Host "  [i] MDT/Deployment configuration detected:" -ForegroundColor Cyan
        Write-Host "    - $($mdtFields.Count) MDT field(s) found" -ForegroundColor Gray
        Write-Host "    - $($mdtIPs.Count) infrastructure IP(s) available for deployment rules" -ForegroundColor Gray
        if ($mdtIPs.Count -gt 0) {
            Write-Host "  [OK] Network-Security-Utility.ps1 will generate deployment IPsec rules" -ForegroundColor Green
        }
    } else {
        Write-Host "  [i] No MDT/Deployment fields present (production XML)" -ForegroundColor Cyan
        Write-Host "    Standard IPsec rules only will be deployed" -ForegroundColor Gray
    }
} else {
    Write-Host "  [i] Production XML detected (no infrastructure IPs)" -ForegroundColor Cyan
    Write-Host "    Standard IPsec rules only will be deployed" -ForegroundColor Gray
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Config File: $ConfigPath" -ForegroundColor White
$fileInfo = Get-Item $ConfigPath
Write-Host "  * Size: $([math]::Round($fileInfo.Length/1KB, 2)) KB" -ForegroundColor Gray
Write-Host "  * Last Modified: $($fileInfo.LastWriteTime)" -ForegroundColor Gray

Write-Host "`nValidation Results:" -ForegroundColor White
Write-Host "  * Tests Passed: $validationPassed" -ForegroundColor Green
Write-Host "  * Errors: $($validationErrors.Count)" -ForegroundColor $(if ($validationErrors.Count -eq 0) { 'Green' } else { 'Red' })
Write-Host "  * Warnings: $($validationWarnings.Count)" -ForegroundColor $(if ($validationWarnings.Count -eq 0) { 'Green' } else { 'Yellow' })

if ($validationErrors.Count -eq 0) {
    Write-Host "`n[PASS] CONFIG FILE IS VALID AND COMPATIBLE" -ForegroundColor Green
    Write-Host "`nThe configuration file meets all requirements for Network-Security-Utility.ps1" -ForegroundColor White
    Write-Host "You can use this file with the -ConfigFile parameter in both LOCAL and ENTERPRISE modes.`n" -ForegroundColor White
    exit 0
} else {
    Write-Host "`n[FAIL] CONFIG FILE HAS ERRORS" -ForegroundColor Red
    Write-Host "`nErrors found:" -ForegroundColor Yellow
    foreach ($error in $validationErrors) {
        Write-Host "  * $error" -ForegroundColor Red
    }
    Write-Host "`n"
    exit 1
}

