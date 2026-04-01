# MedPro Nucleus Remediation Engine
## Automated Vulnerability Remediation for Windows Endpoints

**Version:** 1.0  
**Last Updated:** April 2026  
**Owner:** MedPro Healthcare Staffing IT Infrastructure  

---

## Overview

`Invoke-NucleusRemediation.ps1` is MedPro's enterprise-grade automated vulnerability remediation engine designed to run locally on Windows endpoints. It eliminates manual patch management by converting Nucleus vulnerability scan findings into actionable, safe remediation operations across your entire fleet.

**Key capabilities:**
- Automatic Windows patching (including Dell BIOS via Windows Update)
- Safe application upgrades via winget (skip if not installed)
- Idempotent registry security hardening (pre-checked, already-compliant items skipped)
- Deferred reboot scheduling
- Comprehensive per-machine logging with consolidated audit trails
- Zero configuration needed on endpoints — import the global vulnerability list once weekly

---

## Deployment Models

### 1. **GPO Startup Script** (Recommended for Managed Fleet)
Runs with `SYSTEM` privileges at machine startup; automatically re-runs on reboot.

```powershell
# Add to GPO Computer Configuration > Windows Settings > Scripts > Startup
# Runs as SYSTEM, automatically retried on restart if failures occur
```

### 2. **Scheduled Task**
Deploy via `PSExec`, `Group Policy`, or configuration management:

```powershell
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\MedPro\NucleusRemediation\Invoke-NucleusRemediation.ps1"

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 2:00AM

Register-ScheduledTask -TaskName 'MedPro-NucleusRemediation' `
  -Action $action -Trigger $trigger -RunLevel Highest -Force
```

### 3. **PSExec / Configuration Management**
Deploy on-demand or via immediate execution:

```bash
psexec.exe \\TARGET-HOST -s -h -d powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "C:\MedPro\NucleusRemediation\Invoke-NucleusRemediation.ps1"
```

---

## Configuration

### Initial Setup

1. **Create the script directory:**
   ```powershell
   New-Item -ItemType Directory -Path 'C:\MedPro\NucleusRemediation' -Force
   ```

2. **Place the script:**
   ```powershell
   Copy-Item 'Invoke-NucleusRemediation.ps1' -Destination 'C:\MedPro\NucleusRemediation\'
   ```

3. **Update the global vulnerability list:**
   - Open your latest Nucleus CSV export
   - Extract the unique **Vulnerability Title** column
   - Replace the `$GlobalVulnerabilityList` array in the script with your list
   - Re-deploy to all endpoints (typically done Monday morning)

### Runtime Configuration

Edit these variables at the top of the script to customize behavior:

| Variable | Default | Purpose |
|----------|---------|---------|
| `$DryRun` | `$false` | Set `$true` to plan without making changes; useful for testing |
| `$ScheduleReboot` | `$false` | Set `$true` to schedule a deferred reboot if patches are applied |
| `$RebootDelayMinutes` | `60` | Minutes to wait before automatic restart fires |
| `$LogPath` | `C:\MedPro\NucleusRemediation\Logs` | Central log directory (per-run subdirectories created automatically) |

**Example: Test mode on a single machine**
```powershell
$DryRun = $true
$ScheduleReboot = $false
# Run script to see what *would* be done
```

---

## How It Works

### Phase 1: Plan Builder
The script evaluates each vulnerability title against:
- **Skip patterns:** Non-Windows assets (Cisco, Schneider, etc.) → logged, never touched
- **Manual patterns:** Adobe Creative Suite, EOL OS, account policies → flagged for human review
- **Registry patterns:** Cryptographic, SMB, LDAP config → mapped to registry fixes
- **Winget patterns:** Applications and frameworks → mapped to package IDs
- **Windows Update:** All remaining Microsoft OS/component CVEs

### Phase 2: Execution
1. **Windows Update**: Install applicable patches (PSWindowsUpdate module auto-installed on first run)
2. **Winget Upgrades**: Upgrade installed applications to latest version
3. **Registry Fixes**: Apply security hardening (idempotent — pre-checks skip already-compliant settings)
4. **Reboot Scheduling**: Optionally schedule a deferred restart

### Phase 3: Logging
- **Per-machine log**: `C:\MedPro\NucleusRemediation\Logs\<YYYYMMDD_HHMMSS>\<HOSTNAME>_<YYYYMMDD_HHMMSS>.log`
- **Per-run summaries**: WU patches, Winget updates, Registry fixes applied, manual items flagged
- **Status codes**: `Applied`, `AlreadyConfigured`, `Failed`, `NotInstalled-Skipped`, `UpdateAvailable-DryRun`

---

## Registry Hardening Fixes

The script provides idempotent registry hardening for these security controls:

| Fix ID | Purpose | Typical CVE(s) |
|--------|---------|---|
| `Disable-SMBv1` | Disable legacy SMB v1 protocol | EternalBlue family |
| `Enable-SMBSigning` | Require SMB message signing | Man-in-the-middle attacks |
| `Disable-TLS10` | Disable TLS 1.0 | POODLE, protocol downgrade |
| `Disable-TLS11` | Disable TLS 1.1 | Weak cipher suite attacks |
| `Disable-3DES` | Disable Triple-DES cipher | Sweet32 |
| `Disable-RC4` | Disable RC4 cipher | RC4 weaknesses |
| `Fix-WeakDH` | Enforce 2048-bit Diffie-Hellman minimum | Logjam |
| `Disable-LLMNR` | Disable Link-Local Multicast Name Resolution | Poisoning attacks |
| `Enable-LDAPClientSigning` | Require LDAP signing | Man-in-the-middle attacks |
| `Enable-LDAPChannelBinding` | Enforce LDAP channel binding | Credential relay |
| `Disable-AutoPlay` | Disable AutoPlay for all drive types | Malware distribution |
| `Disable-AutoRun` | Disable autorun.inf execution | USB-based malware |
| `Fix-UnquotedServicePaths` | Quote all unquoted service image paths | Privilege escalation |
| `Disable-NetBIOS` | Disable NetBIOS on all interfaces | Network reconnaissance |
| `Restrict-NullSessions` | Block anonymous network access | Information disclosure |
| `Disable-DisplayLastUsername` | Hide last logged-in user | Credential enumeration |
| `Limit-CachedLogons` | Limit cached credential count to 2 | Offline credential attacks |
| `Apply-KerberosRegistryFix` | Set Kerberos PAC signature (DC only) | CVE-2026-20833 |
| `Apply-DNSSpoofingFix` | Enforce DNS UDP packet size limit | DNS spoofing attacks |

Each fix includes a **pre-check** that detects whether the setting is already compliant, logging it as `[AlreadyConfigured]` and skipping application. This ensures idempotency across repeated runs.

---

## Application Upgrade Mappings

Winget packages are matched using regex patterns. Multiple CVEs for the same product (e.g., "Chrome Prior to 135.0" + "Chrome Prior to 146.0") both match the same package ID and deduplicate to one install:

| Vulnerability Pattern | Winget Package ID |
|----------------------|-------------------|
| Google Chrome | `Google.Chrome` |
| Microsoft Edge | `Microsoft.Edge` |
| Microsoft Teams | `Microsoft.Teams` |
| Visual Studio Code | `Microsoft.VisualStudioCode` |
| 7-Zip | `7zip.7-Zip` |
| FileZilla Client | `TimKosse.FileZilla.Client` |
| KeePass | `DominikReichl.KeePass` |
| Adobe Reader/Acrobat | `Adobe.Acrobat.Reader.64-bit` |
| Ghostscript | `ArtifexSoftware.GhostScript` |
| Node.js LTS | `OpenJS.NodeJS.LTS` |
| Oracle JDK | `Oracle.JDK.21` |
| Azul Zulu JDK | `Azul.Zulu.21.JDK` |
| NVIDIA GeForce Experience | `Nvidia.GeForceExperience` |
| Visual C++ Runtime 2022 x64 | `Microsoft.VCRedist.2022.x64` |
| TechSmith Snagit | `TechSmith.Snagit` |
| JetBrains PyCharm | `JetBrains.PyCharm.Community` |
| Beyond Compare 5 | `ScooterSoftware.BeyondCompare5` |
| PuTTY | `PuTTY.PuTTY` |
| AnyDesk | `AnyDesk.AnyDesk` |
| Dell SupportAssist | `Dell.SupportAssistforBusinessPCs` |
| Microsoft 3D Viewer | `Microsoft.Microsoft3DViewer` |
| .NET Runtime 8 | `Microsoft.DotNet.Runtime.8` |
| .NET SDK 8 | `Microsoft.DotNet.SDK.8` |

**Note:** Winget exit code `-1978335217` ("no applicable update") is logged as `AlreadyUpToDate`, not a failure.

---

## Handling Special Cases

### Non-Installed Applications
Winget safely skips packages not installed on the target machine. No error is logged — status shows `NotInstalled-Skipped`.

### Pending Reboot Detection
The script checks for pending reboots before remediation and can schedule a deferred restart after fixes are applied if `$ScheduleReboot = $true`.

### Manual Review Items
These are **never** touched automatically:
- Adobe Creative Suite (Illustrator, Photoshop, Premiere Pro, InDesign, After Effects)
- EOL Operating Systems (Windows 11 23H2, etc.)
- EOL SQL Server
- Account policy issues (password expiration, guest account rename, unused accounts)
- KeePass master password vulnerability (requires user credential change)
- PostgreSQL (database upgrade requires downtime planning)
- Logitech wireless, Intel chipset, Ricoh printer drivers
- CrowdStrike (requires vendor-specific deployment)
- SSL certificate management

Manual items are logged with reason codes:
- `[MANUAL]` — Human review required
- `[MANUAL-DB]` — Database upgrade (e.g., PostgreSQL)
- `[NO-HANDLER]` — No remediation rule exists for this vulnerability

---

## Windows Update & Dell BIOS

**Windows Update integration:**
- PSWindowsUpdate module is auto-installed on first run (requires NuGet provider)
- Patches are downloaded and installed in one step
- Reboot is **not** automatic — controlled by `$ScheduleReboot`

**Dell BIOS/firmware on managed endpoints:**
- Dell BIOS updates are distributed through Windows Update for managed machines
- The script has been updated to use Windows Update instead of Dell Command Update
- Legacy Dell Command Update is no longer supported; remove if present on endpoints

---

## Logging and Audit Trail

### Log Structure
```
C:\MedPro\NucleusRemediation\Logs\
  ├── 20260324_145030/                    # Run ID (date_time)
  │   ├── DESKTOP-ABC123_20260324_145030.log
  │   ├── DESKTOP-XYZ789_20260324_145030.log
  │   └── ...
  ├── 20260331_145000/
  │   └── ...
```

### Log Entry Format
```
2026-03-24 14:50:30 [SUCCESS] [DESKTOP-ABC123] WU patches: 5
2026-03-24 14:50:31 [INFO] [DESKTOP-ABC123] [WU] KB5038224  March 2026 Security Update -> Installed
2026-03-24 14:50:45 [INFO] [DESKTOP-ABC123] [WINGET] Google.Chrome -> Updated
2026-03-24 14:50:46 [SUCCESS] [DESKTOP-ABC123] [REG] Enable-SMBSigning -> Applied
2026-03-24 14:50:47 [INFO] [DESKTOP-ABC123] [REG] Disable-SMBv1 -> AlreadyConfigured
```

### Retention Policy
- Logs are retained per-run in timestamped directories
- Implement external archival (SIEM, centralized logging) for compliance

---

## Security Best Practices

### Script Deployment
1. **Sign the script** with a trusted code-signing certificate before deployment
2. **Store in read-only location** on endpoints (e.g., `C:\MedPro\NucleusRemediation\` via GPO)
3. **Run as SYSTEM** only (via GPO Startup, Scheduled Task at highest privilege, or PSExec `-s`)
4. **Never** pass credentials or API keys as script parameters

### Vulnerability List Management
1. **Extract from Nucleus weekly** — pull unique vulnerability titles from the official scan export
2. **Version control** the list in your IT change management system
3. **Test in pilot group** before deploying to production (set `$DryRun = $true` first)
4. **Document changes** in your change management system

### Network and Winget
1. Ensure endpoints have internet connectivity to download packages and patches
2. Winget sources are updated automatically; consider network egress policies
3. Windows Update uses WSUS if configured (no changes needed)

### Registry Hardening
1. Registry fixes are **idempotent** — safe to run repeatedly
2. Pre-checks on each fix ensure already-compliant settings are logged as `[AlreadyConfigured]`
3. Some fixes are role-specific (e.g., Kerberos PAC applies only on domain controllers)

### Reboot Scheduling
1. Deferred reboot respects `$RebootDelayMinutes` (default 60 minutes)
2. Shutdown is triggered with `/f` flag (force applications closed) and 30-second warning
3. Scheduled task is auto-deleted after 2 hours if reboot hasn't occurred

---

## Troubleshooting

### Script Won't Run: "Administrator Required"
- Ensure you run PowerShell as Administrator
- For scheduled deployment, verify the task runs at **Highest** privilege level
- When using PSExec, include `-s` flag to run as SYSTEM

### Windows Update Fails
- Check internet connectivity and proxy settings
- Verify `PSWindowsUpdate` module can be installed (NuGet provider required)
- Review Windows Update logs: `Get-WindowsUpdateLog` (Windows 10/11)

### Winget Returns "Not Found" or "Access Denied"
- Verify the target application is installed (script checks before upgrading)
- For SYSTEM account execution, winget path is auto-resolved from AppX directory
- Ensure endpoint has internet access to winget sources

### Registry Fix Returns "Failed"
- Review error message in log file
- Check that script runs with Administrator privileges
- Some fixes require reboot to take effect (scheduled reboot will apply them)

### Manual Items Appear in Plan but Should be Auto-Remediated
- Update `$ManualPatterns` array in the script to remove matching rule
- Re-test in dry-run mode: set `$DryRun = $true`
- Re-deploy updated script to all endpoints

---

## Weekly Update Process

**Every Monday morning (or after new Nucleus scans):**

1. **Export Nucleus vulnerability list** as CSV
2. **Extract unique Vulnerability Title column**
3. **Replace `$GlobalVulnerabilityList` array** in the script
4. **Test in dry-run mode** on a pilot group:
   ```powershell
   $DryRun = $true
   # Run and verify plan output
   ```
5. **Deploy updated script** to all endpoints via GPO or scheduled task
6. **Monitor logs** for success/failure counts
7. **Escalate manual items** to relevant teams (database, account management, etc.)

---

## Support & Escalation

For issues or questions:
- **Log location**: `C:\MedPro\NucleusRemediation\Logs\`
- **Errors flagged**: Look for `[ERROR]` entries in logs
- **Manual items**: Review `[MANUAL]` entries for required human action
- **Escalation**: Forward logs and error details to IT Infrastructure team

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | April 2026 | Initial release; Windows Update for Dell BIOS; idempotent registry fixes; deferred reboot scheduling |

---

**MedPro Healthcare Staffing — IT Infrastructure**  
*Secure. Scalable. Automated.*
