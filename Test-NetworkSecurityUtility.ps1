<#
.SYNOPSIS
    Comprehensive test suite for Network-Security-Utility.ps1
    
.DESCRIPTION
    Runs non-destructive tests to validate the script is ready for use.
    Does NOT require administrator privileges.
    Does NOT modify system settings.
#>

param()

$scriptPath = Join-Path $PSScriptRoot "Network-Security-Utility.ps1"
$configPath = Join-Path $PSScriptRoot "Config.xml"

Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host " Network-Security-Utility.ps1 - Test Suite" -ForegroundColor Cyan
Write-Host "===============================================================================`n" -ForegroundColor Cyan

$testsPassed = 0
$testsTotal = 0

# Test 1: File Exists
$testsTotal++
Write-Host "[TEST 1] Checking file exists..." -ForegroundColor Yellow
if (Test-Path $scriptPath) {
    Write-Host "  [PASS] File found" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "  [FAIL] File not found: $scriptPath" -ForegroundColor Red
    exit 1
}

# Test 2: Syntax Validation
$testsTotal++
Write-Host "`n[TEST 2] Validating PowerShell syntax..." -ForegroundColor Yellow
try {
    $content = Get-Content -Path $scriptPath -Raw
    $errors = $null
    $tokens = [System.Management.Automation.PSParser]::Tokenize($content, [ref]$errors)
    
    if ($errors.Count -eq 0) {
        Write-Host "  [PASS] No syntax errors ($($tokens.Count) tokens parsed)" -ForegroundColor Green
        $testsPassed++
    } else {
        Write-Host "  [FAIL] Syntax errors found: $($errors.Count)" -ForegroundColor Red
        $errors | Select-Object -First 5 | ForEach-Object {
            Write-Host "    Line $($_.Token.StartLine): $($_.Message)" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "  [FAIL] Parse error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: Encoding Check
$testsTotal++
Write-Host "`n[TEST 3] Checking for Unicode characters..." -ForegroundColor Yellow
$unicode = [regex]::Matches($content, '[^\x00-\x7F]')
if ($unicode.Count -eq 0) {
    Write-Host "  [PASS] Pure ASCII - No Unicode characters" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "  [FAIL] Found $($unicode.Count) Unicode characters" -ForegroundColor Red
    $unicode | Select-Object -First 5 | ForEach-Object {
        $char = $_.Value
        $index = $_.Index
        $line = ($content.Substring(0, $index) -split "`n").Count
        Write-Host "    Line $line : '$char' (U+$([int][char]$char).ToString('X4'))" -ForegroundColor Yellow
    }
}

# Test 4: Function Enumeration
$testsTotal++
Write-Host "`n[TEST 4] Enumerating functions..." -ForegroundColor Yellow
$functionPattern = '^\s*function\s+([\w-]+)\s*\{'
$functions = [regex]::Matches($content, $functionPattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
$functionNames = $functions | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

if ($functionNames.Count -gt 0) {
    Write-Host "  [PASS] Found $($functionNames.Count) unique functions" -ForegroundColor Green
    $testsPassed++
    
    # Check for critical functions
    $criticalFuncs = @('Write-Log', 'Initialize-Environment', 'Show-LocalMenu', 'Show-EnterpriseMenu')
    $missingFuncs = $criticalFuncs | Where-Object { $_ -notin $functionNames }
    
    if ($missingFuncs.Count -eq 0) {
        Write-Host "    All critical functions present" -ForegroundColor Gray
    } else {
        Write-Host "    [WARN] Missing critical functions: $($missingFuncs -join ', ')" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [FAIL] No functions found" -ForegroundColor Red
}

# Test 5: Parameters Check
$testsTotal++
Write-Host "`n[TEST 5] Checking script parameters..." -ForegroundColor Yellow
if ($content -match 'param\s*\(') {
    Write-Host "  [PASS] Parameter block found" -ForegroundColor Green
    $testsPassed++
    
    $expectedParams = @('ConfigFile', 'LogFile', 'Mode', 'NonInteractive')
    foreach ($param in $expectedParams) {
        if ($content -match "\`$$param") {
            Write-Host "    [OK] Parameter: $param" -ForegroundColor Gray
        } else {
            Write-Host "    [WARN] Parameter not found: $param" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "  [FAIL] No parameter block found" -ForegroundColor Red
}

# Test 6: Administrator Check
$testsTotal++
Write-Host "`n[TEST 6] Checking administrator privileges..." -ForegroundColor Yellow
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "  [OK] Running as Administrator - Can execute script" -ForegroundColor Green
    $testsPassed++
} else {
    Write-Host "  [INFO] NOT running as Administrator" -ForegroundColor Yellow
    Write-Host "    Script execution requires admin rights" -ForegroundColor Gray
    Write-Host "    Tests can run without admin privileges" -ForegroundColor Gray
}

# Test 7: Module Dependencies
$testsTotal++
Write-Host "`n[TEST 7] Checking module dependencies..." -ForegroundColor Yellow
$requiredModules = @{
    'NetSecurity' = $true   # Always required
    'ActiveDirectory' = $false  # Enterprise mode only
    'GroupPolicy' = $false      # Enterprise mode only
}

$modulesOK = $true
foreach ($module in $requiredModules.Keys) {
    $available = Get-Module -ListAvailable -Name $module
    if ($available) {
        Write-Host "    [OK] $module (v$($available[0].Version))" -ForegroundColor Green
    } else {
        if ($requiredModules[$module]) {
            Write-Host "    [FAIL] $module - REQUIRED but not found" -ForegroundColor Red
            $modulesOK = $false
        } else {
            Write-Host "    [INFO] $module - Not available (Enterprise mode only)" -ForegroundColor Gray
        }
    }
}

if ($modulesOK) {
    $testsPassed++
}

# Test 8: Config File Check
$testsTotal++
Write-Host "`n[TEST 8] Checking configuration file..." -ForegroundColor Yellow
if (Test-Path $configPath) {
    try {
        [xml]$config = Get-Content -Path $configPath
        Write-Host "  [PASS] Config.xml is valid" -ForegroundColor Green
        $testsPassed++
        
        $fileSize = (Get-Item $configPath).Length
        Write-Host "    Size: $([math]::Round($fileSize/1KB, 2)) KB" -ForegroundColor Gray
        
        if ($config.Settings) {
            Write-Host "    [OK] <Settings> root node present" -ForegroundColor Gray
        }
        
        if ($config.Settings.ESAEDomain -or $config.Settings.Domain) {
            Write-Host "    [OK] Domain configuration present" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [FAIL] Config.xml parse error: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  [INFO] Config.xml not found (script will prompt)" -ForegroundColor Yellow
    $testsPassed++
}

# Test 9: ScriptBlock Compilation
$testsTotal++
Write-Host "`n[TEST 9] Testing ScriptBlock compilation..." -ForegroundColor Yellow
try {
    $sb = [ScriptBlock]::Create($content)
    Write-Host "  [PASS] Script can be compiled to ScriptBlock" -ForegroundColor Green
    $testsPassed++
} catch {
    Write-Host "  [FAIL] ScriptBlock compilation failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 10: Help Documentation
$testsTotal++
Write-Host "`n[TEST 10] Checking help documentation..." -ForegroundColor Yellow
if ($content -match '^\s*<#' -and $content -match '\.SYNOPSIS' -and $content -match '\.DESCRIPTION') {
    Write-Host "  [PASS] Comment-based help present" -ForegroundColor Green
    $testsPassed++
    
    if ($content -match '\.PARAMETER') {
        Write-Host "    [OK] Parameter documentation found" -ForegroundColor Gray
    }
    if ($content -match '\.EXAMPLE') {
        Write-Host "    [OK] Usage examples found" -ForegroundColor Gray
    }
} else {
    Write-Host "  [FAIL] No comment-based help found" -ForegroundColor Red
}

# Summary
Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host " TEST RESULTS" -ForegroundColor Cyan
Write-Host "===============================================================================`n" -ForegroundColor Cyan

$passRate = [math]::Round(($testsPassed / $testsTotal) * 100, 1)

Write-Host "Tests Passed: $testsPassed / $testsTotal ($passRate%)" -ForegroundColor $(if ($passRate -ge 80) { 'Green' } elseif ($passRate -ge 60) { 'Yellow' } else { 'Red' })

if ($testsPassed -eq $testsTotal) {
    Write-Host "`nSTATUS: ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host "The script is ready for use.`n" -ForegroundColor White
    exit 0
} elseif ($passRate -ge 80) {
    Write-Host "`nSTATUS: MOST TESTS PASSED" -ForegroundColor Yellow
    Write-Host "The script should work but review warnings above.`n" -ForegroundColor White
    exit 0
} else {
    Write-Host "`nSTATUS: TESTS FAILED" -ForegroundColor Red
    Write-Host "Review errors above before using the script.`n" -ForegroundColor White
    exit 1
}
