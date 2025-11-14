# Active Directory IPsec Migration Guide

## Overview

The **Network Security Utility** now includes domain-to-domain IPsec migration capabilities that allow you to:

1. **Export** IPsec configuration from the source domain's Active Directory IP Security container
2. **Analyze** the exported configuration
3. **Compare** IPsec settings between two domains
4. **Import** (preview mode) settings to a target domain

These features address the scenario where you need to replicate IPsec configuration from a working domain to a new domain that doesn't currently have matching settings.

---

## New Features (Menu Options 21-23)

### **Option 21: Export IPsec from AD IP Security Container**

**Purpose:** Reads all IPsec-related objects from Active Directory and exports them to XML format.

**What it exports:**
- IPsec Policies (`ipsecPolicy`)
- IPsec Filters (`ipsecFilter`)
- IPsec Negotiation Policies (`ipsecNegotiationPolicy`)
- IPsec NFAs (Network Filter Actions) (`ipsecNFA`)
- IPsec ISAKMP Policies (`ipsecISAKMPPolicy`)

**Usage:**
1. Run the script in **Enterprise mode** (on a Domain Controller or with AD access)
2. Select **Option 21** from the main menu
3. Specify source domain (or press Enter to use current domain)
4. Specify output file path (or use default with timestamp)
5. Review export results

**Output:** XML file containing complete IPsec AD configuration

**Example:**
```
ADIPsec-Export-contoso.com-20251113-143022.xml
```

---

### **Option 22: Import IPsec to AD IP Security Container**

**Purpose:** Analyzes exported IPsec configuration and prepares for import to target domain.

**Current Status:** ⚠️ **PREVIEW MODE**
- Currently provides analysis and validation
- Shows what would be imported
- Full object creation pending implementation

**Usage:**
1. First export from source domain using Option 21
2. Select **Option 22** from menu
3. Specify path to exported XML file
4. Specify target domain
5. Review import plan (WhatIf mode)

**Why Preview Mode?**
Creating IPsec objects in Active Directory requires careful handling of:
- Binary attributes (ipsecData, ipsecNegotiationPolicyAction)
- Object relationships and references
- Proper DN construction
- GUID management

**Recommended Approach:**
Use the exported XML to understand source configuration, then:
- Manually create policies via Group Policy Management Console
- Use `netsh ipsec` commands to script creation
- Contact Microsoft Support for migration assistance

---

### **Option 23: Compare IPsec Between Domains**

**Purpose:** Identifies differences in IPsec configuration between two domains.

**What it compares:**
- Object counts by type
- Missing objects in target domain
- Extra objects not in source
- Highlights mismatches

**Usage:**
1. Select **Option 23**
2. Enter source domain FQDN (working/reference domain)
3. Enter target domain FQDN (domain to compare)
4. Review comparison report

**Output:**
```
Object Count by Type:

  ipsecPolicy : Source=3, Target=0 [DIFFERENT]
  ipsecFilter : Source=12, Target=2 [DIFFERENT]
  ipsecNegotiationPolicy : Source=8, Target=8 [MATCH]
  ipsecNFA : Source=15, Target=5 [DIFFERENT]
  ipsecISAKMPPolicy : Source=2, Target=2 [MATCH]
```

---

## Workflow: Domain-to-Domain Migration

### **Recommended Steps:**

#### **Phase 1: Analysis**
1. Run **Option 23** (Compare) to understand current differences
2. Document what needs to be migrated

#### **Phase 2: Export**
1. Run **Option 21** (Export) on source domain
2. Save the export XML file
3. Review XML to understand configuration structure

#### **Phase 3: Planning**
1. Analyze exported configuration
2. Identify Quick Mode vs Main Mode settings
3. Note certificate requirements (CAPath, etc.)
4. Plan GPO structure for target domain

#### **Phase 4: Manual Configuration** (Current Approach)
Since full import is not yet available, use one of these methods:

**Method A: Group Policy Management Console**
1. Open GPMC on target domain controller
2. Create new GPO
3. Navigate to: Computer Config → Windows Settings → Security Settings → IP Security Policies
4. Manually create policies matching export XML

**Method B: NetSh Commands**
1. Use exported XML as reference
2. Create netsh ipsec scripts:
   ```powershell
   netsh ipsec static add policy name="MyIPsecPolicy"
   netsh ipsec static add filterlist name="MyFilter"
   netsh ipsec static add filter filterlist="MyFilter" ...
   ```

**Method C: Network Security Utility XML Import** (Alternative)
1. Convert AD export to the utility's XML format
2. Use existing import functions (Options 10-13)
3. Apply via GPO deployment

---

## Prerequisites

### **Required Permissions:**
- Domain Admin or equivalent rights in both domains
- Access to Active Directory Administrative Tools
- Rights to query AD containers

### **Required Modules:**
```powershell
# Check module availability
Get-Module -Name ActiveDirectory -ListAvailable
Get-Module -Name GroupPolicy -ListAvailable

# Install if missing (on Domain Controller or RSAT-equipped system)
Install-WindowsFeature RSAT-AD-PowerShell
Install-WindowsFeature GPMC
```

### **Network Requirements:**
- Network connectivity to both domain controllers
- DNS resolution for both domains
- Appropriate firewall rules for AD replication ports

---

## Troubleshooting

### **"Cannot access IP Security container"**
**Cause:** Container doesn't exist or insufficient permissions

**Solution:**
```powershell
# Verify container exists
Import-Module ActiveDirectory
$domain = (Get-ADDomain).DistinguishedName
Get-ADObject -Identity "CN=IP Security,CN=System,$domain"
```

### **"No IPsec objects found"**
**Cause:** Domain has no IPsec policies defined in AD

**Solution:**
- This is normal for newly created domains
- Check Group Policy objects for IPsec policies
- May need to create policies first

### **"Export completed but file is large"**
**Cause:** Many IPsec objects or verbose AD attributes

**Solution:**
- This is normal - AD exports include all object properties
- File compression recommended for transfer
- Consider filtering specific object types if needed

---

## Security Considerations

### **Exported Files Contain:**
- Complete IPsec policy configuration
- Filter lists and rules
- Cryptographic settings (algorithms, key exchange methods)
- Object GUIDs and Distinguished Names

⚠️ **Security Recommendations:**
- Store export files securely (encrypted folder/share)
- Limit access to domain administrators only
- Delete export files after migration complete
- Do not commit to source control repositories

---

## Limitations & Known Issues

### **Current Limitations:**
1. **Import function is preview-only**
   - Does not create actual AD objects yet
   - Requires manual policy creation

2. **Binary Attributes**
   - Some IPsec data stored as binary blobs
   - XML export shows base64-encoded data
   - Difficult to interpret without AD tools

3. **Cross-Domain References**
   - GUIDs and DNs are domain-specific
   - Must be remapped for target domain

4. **Certificate References**
   - CA paths may differ between domains
   - Requires manual adjustment

### **Planned Enhancements:**
- Full AD object creation in import function
- Automated DN/GUID remapping
- Certificate path translation
- Validation and conflict resolution

---

## Alternative Approaches

If the built-in migration functions don't meet your needs:

### **1. Microsoft IPSEC Migration Tools**
Check for official Microsoft tools:
- Windows Server Migration Tools
- Active Directory Migration Tool (ADMT)

### **2. Third-Party Solutions**
- Quest Migration Suite
- ENow Software Active Directory tools

### **3. Manual Export/Import via GPO**
1. Export GPO from source domain
2. Import GPO to target domain
3. Adjust settings as needed

### **4. Microsoft Support**
For complex migrations, engage Microsoft CSS:
- Premier Support incident
- FastTrack (if eligible)
- Partner support channels

---

## Examples

### **Example 1: Quick Comparison**
```powershell
# Run script
.\Network-Security-Utility.ps1 -Mode Enterprise

# Select Option 23 (Compare)
# Source: workingdomain.com
# Target: newdomain.com

# Review output to identify gaps
```

### **Example 2: Full Export**
```powershell
# Run script
.\Network-Security-Utility.ps1 -Mode Enterprise

# Select Option 21 (Export)
# Press Enter for current domain
# Press Enter for default output path

# Result: ADIPsec-Export-workingdomain.com-20251113.xml
```

### **Example 3: Analysis Workflow**
```powershell
# 1. Compare first
Select Option 23
Source: domain1.local
Target: domain2.local

# 2. Export from source
Select Option 21
Domain: domain1.local
Output: C:\Temp\domain1-ipsec.xml

# 3. Review XML
notepad C:\Temp\domain1-ipsec.xml

# 4. Plan migration using XML as reference
```

---

## Support & Documentation

### **Related Documentation:**
- `Network-Security-Utility-Administrator-Guide.html` - Main utility guide
- `Config.xml` - Configuration file format
- Microsoft Docs: [IPsec Policies in Active Directory](https://docs.microsoft.com/windows/security/threat-protection/windows-firewall/ipsec-policies)

### **Getting Help:**
1. Review this guide and main administrator guide
2. Check PowerShell script comments
3. Enable detailed logging in script
4. Contact Microsoft Support with log files

---

## Changelog

### **Version 1.1 - November 13, 2025**
- ✅ Added Export-ADIPsecConfiguration function
- ✅ Added Import-ADIPsecConfiguration function (preview mode)
- ✅ Added Compare-ADIPsecConfiguration function
- ✅ Added menu options 21-23 for AD migration
- ✅ Added user-friendly wrapper functions with prompts
- ✅ Fixed ampersand syntax errors in menu display

### **Version 1.0 - November 3, 2025**
- Initial release with local and GPO IPsec management

---

## Quick Reference Card

| Option | Function | Input Required | Output |
|--------|----------|----------------|--------|
| 21 | Export AD IPsec | Source domain (optional) | XML file |
| 22 | Import AD IPsec | XML file, Target domain | Preview report |
| 23 | Compare Domains | Source domain, Target domain | Comparison report |

**Typical Workflow:**
```
Compare (23) → Export (21) → Analyze XML → Manual Import → Verify
```

---

*For questions or issues, please contact your Microsoft support team or domain administrator.*
