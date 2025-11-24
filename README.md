# 🛡️ Network Security Utility

**Enterprise-Grade IPsec Configuration and Management Tool for Windows Server**

Version 2.0 | PowerShell 5.1+ | Windows Server 2012 R2+

---

## 📋 Overview

The Network Security Utility is a comprehensive PowerShell-based solution for managing IPsec policies and Windows Firewall configurations across both standalone servers and Active Directory environments. It provides a user-friendly menu-driven interface for deploying, managing, and migrating IPsec configurations with built-in safety features and extensive validation.

### Key Features

- ✅ **Dual Mode Operation**: LOCAL mode for standalone servers, ENTERPRISE mode for domain-wide GPO deployment
- ✅ **Active Directory IPsec Migration**: Export, import, and compare IPsec configurations between domains
- ✅ **XML-Based Configuration**: Version-controlled, human-readable configuration files
- ✅ **Comprehensive Validation**: Pre-deployment configuration validation with detailed error reporting
- ✅ **Safety-First Design**: Built-in backup/restore functionality, WhatIf mode, and rollback capabilities
- ✅ **Automated Reporting**: HTML reports, IPsec statistics, and GPO replication status
- ✅ **Partial Configuration Support**: Deploy only IPsec or only Firewall settings
- ✅ **Production-Ready**: Extensive error handling, logging, and compatibility checks

---

## 📁 Project Files

### Core Scripts

| File | Description | Required |
|------|-------------|----------|
| **Network-Security-Utility.ps1** | Main utility script (6,383 lines) with menu-driven interface for all IPsec and firewall operations | ✅ Required |
| **Validate-Config.ps1** | Standalone configuration validator that checks XML files for errors before deployment | ⚠️ Recommended |
| **Validate-ScriptFunctions.ps1** | Shared validation functions library used by both main script and validator | ⚠️ Recommended |
| **Configure-LocalIPsec.ps1** | Legacy standalone script for local IPsec configuration (superseded by main utility) | ❌ Optional |
| **Configure-CTMIPsec.ps1** | Legacy CTM-specific IPsec configuration script (superseded by main utility) | ❌ Optional |

### Configuration Files

| File | Description | Required |
|------|-------------|----------|
| **Config.xml** | Sample XML configuration template with IPsec policies, filter lists, and firewall rules | ✅ Required |

### Documentation

| File | Description | Required |
|------|-------------|----------|
| **Network-Security-Utility-Administrator-Guide.html** | Comprehensive HTML administrator guide (2,110 lines) with workflows, examples, and troubleshooting | ⚠️ Recommended |
| **AD-IPsec-Migration-Guide.md** | Detailed guide for Active Directory IPsec migration between domains | ⚠️ Recommended |
| **README.md** | This file - project overview and quick start guide | ℹ️ This File |

---

## 🚀 Quick Start (60 Seconds)

### Prerequisites

- Windows Server 2012 R2 or later
- PowerShell 5.1 or later
- Administrator privileges
- For Enterprise mode: Domain Admin rights, ActiveDirectory/GroupPolicy PowerShell modules

### Basic Usage

1. **Download Files**
   ```powershell
   # Download to working directory
   cd C:\temp
   ```

2. **Edit Configuration**
   ```powershell
   # Customize Config.xml with your settings
   notepad Config.xml
   ```

3. **Validate Configuration**
   ```powershell
   # Run validation before deployment
   .\Validate-Config.ps1 -ConfigFile ".\Config.xml"
   ```

4. **Deploy**
   ```powershell
   # Run main utility
   .\Network-Security-Utility.ps1
   
   # Choose mode:
   # - Option 1: LOCAL mode (standalone server)
   # - Option 2: ENTERPRISE mode (GPO deployment)
   ```

---

## 🎯 Common Workflows

### Scenario 1: Deploy to Single Server (LOCAL Mode)

```powershell
# 1. Run the utility
.\Network-Security-Utility.ps1

# 2. Select: 1 (ENTER LOCAL MODE)
# 3. Select: 2 (Load Configuration from XML)
# 4. Select: 14 (Backup Current Settings) ⚠️ CRITICAL
# 5. Select: 11 (Apply Complete Configuration - All Steps)
# 6. Select: 3 (View IPsec Statistics & Status)
```

### Scenario 2: Deploy Domain-Wide (ENTERPRISE Mode)

```powershell
# 1. Run the utility
.\Network-Security-Utility.ps1

# 2. Select: 2 (ENTER ENTERPRISE MODE)
# 3. Select: 3 (Load/Test XML Configuration File)
# 4. Select: 20 (Preview Changes - WhatIf Mode)
# 5. Select: 17 (Backup Current Settings) ⚠️ CRITICAL
# 6. Select: 13 (Apply Complete GPO Configuration)
# 7. Select: 14 (Test GPO Replication Status)
```

### Scenario 3: Migrate IPsec Between Domains

```powershell
# On SOURCE domain controller:
.\Network-Security-Utility.ps1
# Select: 2 (ENTERPRISE MODE)
# Select: 21 (Export IPsec from AD IP Security Container)
# Save exported XML file

# On TARGET domain controller:
.\Network-Security-Utility.ps1
# Select: 2 (ENTERPRISE MODE)
# Select: 22 (Import IPsec to AD IP Security Container)
# Review planned changes
# Select: 23 (Compare IPsec Between Domains)
```

See **AD-IPsec-Migration-Guide.md** for complete migration workflows.

---

## 📖 Menu Structure

### LOCAL Mode Options (0-20)

**INFORMATION & TESTING**
- `1` - View Current IPsec Configuration
- `2` - Load/Test XML Configuration File
- `3` - View IPsec Statistics and Status
- `4` - Show Loaded Configuration

**LOCAL CONFIGURATION**
- `5` - Remove All IPsec Rules
- `6` - Configure Windows Firewall
- `7` - Create Phase 1 Authentication
- `8` - Create Main Mode Crypto Sets
- `9` - Create Quick Mode Crypto Sets
- `10` - Apply IPsec Rules
- `11` - Apply Complete Configuration (All Steps)

**UTILITIES**
- `12` - Export Current Configuration to XML
- `13` - Generate HTML Report
- `14` - Backup Current Settings ⚠️
- `15` - Restore from Backup ⚠️
- `16` - View Firewall Logs

**TROUBLESHOOTING**
- `17` - Test IPsec Connectivity to Remote Host
- `18` - View IPsec Event Logs
- `19` - View Certificate Information

**ANALYSIS**
- `20` - Preview Changes (WhatIf Mode)

**EXIT**
- `0` - Exit

### ENTERPRISE Mode Options (0-23)

**INFORMATION & TESTING**
- `1` - View Current Local IPsec Configuration
- `2` - View GPO IPsec Configuration
- `3` - Load/Test XML Configuration File
- `4` - View IPsec Statistics and Status
- `5` - Show Loaded Configuration

**LOCAL CONFIGURATION (This Server Only)**
- `6` - Remove All Local IPsec Rules
- `7` - Configure Local Windows Firewall
- `8` - Apply Local IPsec Configuration

**DOMAIN CONFIGURATION (GPO/Active Directory)**
- `9` - List Existing IPsec GPOs
- `10` - Create/Update IPsec GPOs
- `11` - Link GPOs to OUs
- `12` - Remove IPsec GPOs
- `13` - Apply Complete GPO Configuration
- `14` - Test GPO Replication Status

**AD IPSEC MIGRATION (Domain-to-Domain)**
- `21` - Export IPsec from AD IP Security Container
- `22` - Import IPsec to AD IP Security Container
- `23` - Compare IPsec Between Domains

**UTILITIES**
- `15` - Export Current Configuration to XML
- `16` - Generate HTML Report
- `17` - Backup Current Settings ⚠️
- `18` - Restore from Backup ⚠️
- `19` - View Firewall Logs

**ANALYSIS**
- `20` - Preview Changes (WhatIf Mode)

**EXIT**
- `0` - Exit

---

## 🔒 Safety Features

### Always Backup Before Deployment

```powershell
# The utility includes automated backup/restore:
# - Backup: Menu Option 14 (LOCAL) or 17 (ENTERPRISE)
# - Restore: Menu Option 15 (LOCAL) or 18 (ENTERPRISE)

# Backups include:
# - All IPsec policies and filter lists
# - Windows Firewall rules
# - Connection Security Rules
# - Timestamp and metadata
```

### Golden Rule: BACKUP → TEST → DEPLOY → VERIFY

1. **BACKUP**: Create backup before any changes
2. **TEST**: Use WhatIf mode (Option 20) or test locally first
3. **DEPLOY**: Apply configuration
4. **VERIFY**: Check IPsec statistics and connectivity

---

## 📊 Configuration File (Config.xml)

The XML configuration file defines:

- **IPsec Policies**: Encryption and authentication settings
- **Filter Lists**: Traffic matching rules (IP ranges, ports, protocols)
- **Filter Actions**: Permit, block, or negotiate security
- **Firewall Rules**: Windows Firewall allow/block rules
- **Domain Settings**: GPO names, OU paths, replication settings

### Sample Structure

```xml
<?xml version="1.0" encoding="utf-8"?>
<NetworkSecurityConfig>
    <IPsecPolicies>
        <Policy Name="Server Isolation Policy" Description="...">
            <FilterLists>
                <FilterList Name="Trusted Subnets">...</FilterList>
            </FilterLists>
            <FilterActions>
                <Action Name="Require IPsec">...</Action>
            </FilterActions>
        </Policy>
    </IPsecPolicies>
    <FirewallRules>
        <Rule Name="Allow RDP" Direction="Inbound">...</Rule>
    </FirewallRules>
    <DomainConfig>
        <GPOName>IPsec-ServerIsolation</GPOName>
        <OUPaths>
            <OU>OU=Servers,DC=contoso,DC=com</OU>
        </OUPaths>
    </DomainConfig>
</NetworkSecurityConfig>
```

---

## 🔧 Requirements

### System Requirements

- **Operating System**: Windows Server 2012 R2 or later
- **PowerShell**: Version 5.1 or later
- **Execution Policy**: RemoteSigned or Unrestricted
- **Privileges**: Run as Administrator

### PowerShell Modules

| Module | Required For | Auto-Check |
|--------|--------------|------------|
| ActiveDirectory | ENTERPRISE mode, AD migration | ✅ Yes |
| GroupPolicy | ENTERPRISE mode, GPO operations | ✅ Yes |
| NetSecurity | IPsec and Firewall management | ✅ Yes |

The utility automatically checks for required modules and provides installation guidance.

---

## 📚 Documentation Guide

| Document | Use Case | Audience |
|----------|----------|----------|
| **README.md** (this file) | Quick start, overview, file reference | Everyone |
| **Network-Security-Utility-Administrator-Guide.html** | Complete workflows, troubleshooting, examples | Administrators |
| **AD-IPsec-Migration-Guide.md** | Domain-to-domain IPsec migration | Migration Engineers |
| **Config.xml** | Configuration template and examples | Configuration Managers |

### Recommended Reading Order

1. **README.md** - Get familiar with the tool
2. **Network-Security-Utility-Administrator-Guide.html** - Learn workflows
3. **Validate-Config.ps1** - Understand validation before deployment
4. **AD-IPsec-Migration-Guide.md** - Only if performing domain migration

---

## 🛠️ Advanced Features

### Partial Configuration Support

Deploy only IPsec OR only Firewall settings:

```xml
<!-- IPsec only - omit <FirewallRules> section -->
<NetworkSecurityConfig>
    <IPsecPolicies>...</IPsecPolicies>
</NetworkSecurityConfig>

<!-- Firewall only - omit <IPsecPolicies> section -->
<NetworkSecurityConfig>
    <FirewallRules>...</FirewallRules>
</NetworkSecurityConfig>
```

### WhatIf Mode (Risk-Free Preview)

```powershell
# Enterprise Mode → Option 20
# Shows exactly what would be changed WITHOUT making changes
# Displays: GPO settings, OU links, expected replication
```

### Automated HTML Reporting

```powershell
# Menu Option 13 (LOCAL) or 16 (ENTERPRISE): Generate HTML Report
# Creates detailed report with:
# - Current IPsec policies
# - Active Security Associations
# - Firewall rules
# - System information
```

---

## 🔍 Troubleshooting

### Common Issues

**"Config.xml validation failed"**
- Run `.\Validate-Config.ps1 -ConfigFile ".\Config.xml" -Verbose`
- Check for XML syntax errors, missing required fields

**"Unable to connect to Domain Controller"**
- Verify network connectivity: `Test-Connection -ComputerName DC01`
- Check ActiveDirectory module: `Get-Module -ListAvailable ActiveDirectory`

**"IPsec policy not applying"**
- Check local policy precedence: `netsh ipsec static show all`
- Verify GPO replication: Menu Option 14 in Enterprise mode

**Lost connectivity after deployment**
- Use backup/restore: Menu Option 15 (LOCAL) or 18 (ENTERPRISE)
- Check filter lists for overly restrictive rules

See **Network-Security-Utility-Administrator-Guide.html** → Troubleshooting section for complete guide.

---

## 📜 Logging

All operations are logged with timestamps:

```powershell
# Default log location
.\NetworkSecurityUtility.log

# Custom log file
.\Network-Security-Utility.ps1 -LogFile "C:\Logs\IPsec-$(Get-Date -Format 'yyyyMMdd').log"
```

Log entries include:
- Configuration changes
- Validation results
- Error messages with stack traces
- Backup/restore operations
- GPO creation and linking

---

## 🔐 Security Considerations

- **Credentials**: Script never stores credentials; uses current user context
- **Backup Files**: Stored locally with timestamp; contain sensitive configuration
- **Domain Admin Rights**: Required for ENTERPRISE mode and AD migration
- **Audit Trail**: All changes logged for compliance and auditing
- **GPO Permissions**: Follows principle of least privilege

---

## 🤝 Contributing

This is an enterprise utility. Changes should be:
1. Tested in lab environment
2. Validated with `Validate-Config.ps1`
3. Documented in administrator guide
4. Logged in change history

---

## 📞 Support

### Before Requesting Support

1. Run configuration validation: `.\Validate-Config.ps1`
2. Review logs: `.\NetworkSecurityUtility.log`
3. Check administrator guide: `Network-Security-Utility-Administrator-Guide.html`
4. Verify prerequisites and module availability

### Information to Include

- PowerShell version: `$PSVersionTable`
- Windows version: `Get-ComputerInfo -Property WindowsVersion`
- Error messages from logs
- Configuration file (sanitized)
- Deployment mode (LOCAL or ENTERPRISE)

---

## 📄 License

Enterprise Internal Use - Check with your organization's policies.

---

## 🗓️ Version History

- **v2.0** (2025-11-13) - Added AD IPsec Migration features (Options 21-23), enhanced validation, updated documentation
- **v1.x** - Initial release with LOCAL and ENTERPRISE modes

---

## ⚡ Quick Reference

### File Sizes (Approximate)
- Network-Security-Utility.ps1: ~265 KB (6,383 lines)
- Network-Security-Utility-Administrator-Guide.html: ~90 KB (2,110 lines)
- AD-IPsec-Migration-Guide.md: ~15 KB (300+ lines)
- Validate-Config.ps1: ~30 KB
- Config.xml: ~25 KB (sample)

### Essential Commands

```powershell
# Validate configuration
.\Validate-Config.ps1 -ConfigFile ".\Config.xml"

# Run utility
.\Network-Security-Utility.ps1

# Run with pre-loaded config and custom log
.\Network-Security-Utility.ps1 -ConfigFile ".\Config.xml" -LogFile ".\custom.log"

# Check PowerShell version
$PSVersionTable.PSVersion

# Check required modules
Get-Module -ListAvailable ActiveDirectory, GroupPolicy, NetSecurity
```

---

**Remember: Always backup before deployment!** ⚠️

For detailed workflows and examples, see **Network-Security-Utility-Administrator-Guide.html**
