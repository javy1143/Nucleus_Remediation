#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Invoke-NucleusRemediation.ps1
    MedPro Healthcare Staffing -- Automated Vulnerability Remediation Engine

.DESCRIPTION
    Runs LOCALLY on each machine. No WinRM, no remoting, no parameters needed.

    Deploy via GPO startup script, scheduled task, or PSExec. The script reads
    a global master list of vulnerabilities, builds a remediation plan, and safely
    attempts to remediate them. Winget will safely skip apps that are not installed,
    Windows Update will only install applicable missing patches, and registry fixes
    are idempotent -- pre-checked before applying so already-compliant settings are
    logged as [AlreadyConfigured] and skipped.

    Each Monday: Extract the unique "Vulnerability Title" column from the new
    Nucleus CSV and paste it into the $GlobalVulnerabilityList block -> redeploy.

    Remediation categories:
      [WIN_UPDATE]  Windows patches via PSWindowsUpdate (includes Dell BIOS via WU)
      [WINGET]      App upgrades via winget (only if app is already installed)
      [REGISTRY]    Security config: SMBv1, TLS 1.0/1.1, LLMNR, cipher suites, etc.
      [REBOOT]      Deferred scheduled restart after remediation
      [MANUAL]      Logged for human review -- never touched automatically
      [SKIP]        Network gear / non-Windows assets -- logged and ignored

.NOTES
    Set-StrictMode is intentionally NOT used. It causes PropertyNotFoundException
    on missing registry keys, breaks .Count on single-object pipeline returns, and
    blanks out summary counters. All .Count calls use @() wrapping instead.

    Dell Command Update has been removed from the environment. Dell BIOS/firmware
    vulnerabilities are remediated via Windows Update (Dell BIOS updates are
    distributed through WU for managed endpoints).

    NetBIOS disable uses registry path fallback rather than CIM/WMI, which fails
    on Realtek USB GbE adapters.

    Winget exit code -1978335217 means "no applicable update" -- logged as
    AlreadyUpToDate, not a failure.
#>

# -- StrictMode intentionally omitted -- see .NOTES above --------------------
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ==============================================================================
#  CONFIGURATION
# ==============================================================================

$DryRun             = $false   # $true = plan only, zero changes made
$ScheduleReboot     = $false   # Schedule a deferred restart when one is needed
$RebootDelayMinutes = 60       # Minutes to wait before the restart fires
$LogPath            = 'C:\MedPro\NucleusRemediation\Logs'

# --- MASTER VULNERABILITY LIST -----------------------------------------------
# Paste the unique list of vulnerability names from your Nucleus CSV here.
# The script evaluates this entire list on every machine and skips anything
# that is not installed, already configured correctly, or not applicable.
$GlobalVulnerabilityList = @(
    '7-Zip Arbitrary File Write Vulnerability (CVE-2025-55188)',
    '7-Zip Multiple Security Vulnerabilities',
    "Administrator Account's Password Does Not Expire",
    'Adobe Acrobat and Reader Arbitrary Code Execution Vulnerability (APSB25-119)',
    'Adobe After Effects Arbitrary Code Execution Vulnerability (APSB26-15)',
    'Adobe Illustrator Arbitrary Code Execution Vulnerability (APSB26-03)',
    'Adobe InDesign Arbitrary Code Execution Vulnerability (APSB26-02)',
    'Adobe Photoshop Arbitrary Code Execution Vulnerability (APSB25-108)',
    'Adobe Premiere Pro Arbitrary Code Execution Vulnerability (APSB25-87)',
    'Allowed Null Session',
    'Artifex Ghostscript Multiple Vulnerabilities (gs10.03.1)',
    'Azul Java Vulnerability Security Update January 2026',
    'Beyond Compare DLL Hijacking Vulnerability',
    'Built-in Guest Account Not Renamed at Windows Target System',
    'Default Windows Administrator Account Name Present',
    'Dell Client Security Update for BIOS Vulnerabilities (DSA-2024-030)',
    'Dell SupportAssist Multiple Security Vulnerabilities (DSA-2025-296)',
    'EOL/Obsolete Operating System: Microsoft Windows 11 23H2 (Home|Pro|Pro Education|Pro for Workstations|SE) Detected',
    'EOL/Obsolete Software: Adobe Reader/Acrobat 2017 Detected',
    'EOL/Obsolete Software: Microsoft .Net Version 6 Detected',
    'Enabled Cached Logon Credential',
    'FileZilla Client DLL Hijacking Vulnerability (CVE-2023-53959)',
    'Ghostscript Code Execution Vulnerability',
    'Google Chrome Prior to 146.0.7680.164 Multiple Vulnerabilities',
    'Intel Chipset Device Software Privilege Escalation Vulnerabilities (INTEL-SA-00870, INTEL-SA-01032)',
    'JetBrains PyCharm DOM Based Cross-Site Scripting (XSS) Vulnerability (PY-85539)',
    'KeePass 2.X Master Password Retrieval Vulnerability (CVE-2023-32784)',
    'Logitech Wireless USB dongles (Unifying Receivers) Multiple Vulnerabilities',
    'Microsoft .NET Framework Update for October 2025',
    'Microsoft 3D Viewer Multiple Vulnerabilities - June 2021',
    'Microsoft ASP.NET Core Security Update for March 2026',
    'Microsoft Desktop Window Manager Elevation of Privilege Vulnerability (February 2026)',
    'Microsoft Edge Based on Chromium Prior to 146.0.3856.72 Multiple Vulnerabilities',
    'Microsoft Teams Heap Buffer Overflow Vulnerability for Sep 2023',
    'Microsoft Visual Studio Code Security Update for February 2026',
    'Microsoft Windows DNS Resolver Addressing Spoofing Vulnerability (ADV200013)',
    'Microsoft Windows Explorer AutoPlay Not Disabled',
    'Microsoft Windows Kerberos Protocol Changes Related to CVE-2026-20833 Missing',
    'Microsoft Windows Security App Spoofing Vulnerability (June 2025) (CVE-2025-47956)',
    'NVIDIA GeForce Experience Privilege Escalation Vulnerability',
    'NetBIOS Name Accessible',
    'Node.js Multiple Security Vulnerabilities',
    'Oracle Java Standard Edition (SE) Critical Patch Update - January 2026 (CPUJAN2026)',
    'Pending Reboot Detected',
    'PostgreSQL Multiple Security Vulnerabilities',
    'Ricoh Printer Drivers for Windows Local Privilege Escalation Vulnerability',
    'SMB Signing Disabled or SMB Signing Not Required',
    'SMBv2 Signing Not Required',
    'TechSmith Snagit XML External Entity (XXE) injection Vulnerability',
    'Unused Active Windows Accounts Found',
    'Visual Studio Code Extension Live Server Data Exfiltration Vulnerability (CVE-2025-65717)',
    'Windows Explorer Autoplay Not Disabled for Default User',
    'Windows SMB Version 1 (SMBv1) Detected',
    'Windows Service Weak Permissions detected',
    'Windows Unquoted/Trusted Service Paths Privilege Escalation Security Issue',
    'Windows User Accounts With Unchanged Passwords',
    'Zoom VDI Client - External Control of File Name or Path Vulnerability (ZSB-26005)'
)

# ==============================================================================
#  REMEDIATION MAPPINGS
# ==============================================================================

# Map vulnerability title patterns -> winget package IDs.
# When multiple CVEs reference different versions of the same product
# (e.g. "Chrome Prior to 135.0" and "Chrome Prior to 146.0"), both will
# match the same pattern and deduplicate to one package ID. Winget always
# installs the latest available version, covering all version-specific CVEs
# for that product in one shot.
$WingetPackageMap = [ordered]@{
    'Google Chrome'                          = 'Google.Chrome'
    'Microsoft Edge'                         = 'Microsoft.Edge'
    'Microsoft Teams'                        = 'Microsoft.Teams'
    'Visual Studio Code'                     = 'Microsoft.VisualStudioCode'
    'Zoom VDI'                               = 'Zoom.Zoom'
    'Zoom'                                   = 'Zoom.Zoom'
    '7-Zip'                                  = '7zip.7-Zip'
    'FileZilla'                              = 'TimKosse.FileZilla.Client'
    'KeePass'                                = 'DominikReichl.KeePass'
    'Adobe Acrobat and Reader'               = 'Adobe.Acrobat.Reader.64-bit'
    'EOL.*Adobe Reader'                      = 'Adobe.Acrobat.Reader.64-bit'
    'EOL.*Adobe Acrobat'                     = 'Adobe.Acrobat.Reader.64-bit'
    'Ghostscript'                            = 'ArtifexSoftware.GhostScript'
    'Node\.js'                               = 'OpenJS.NodeJS.LTS'
    'Oracle Java Standard Edition'           = 'Oracle.JDK.21'
    'Azul Java'                              = 'Azul.Zulu.21.JDK'
    'NVIDIA GeForce'                         = 'Nvidia.GeForceExperience'
    'Microsoft Visual C\+\+'                 = 'Microsoft.VCRedist.2022.x64'
    'TechSmith Snagit'                       = 'TechSmith.Snagit'
    'JetBrains PyCharm'                      = 'JetBrains.PyCharm.Community'
    'Beyond Compare'                         = 'ScooterSoftware.BeyondCompare5'
    'PuTTY'                                  = 'PuTTY.PuTTY'
    'AnyDesk'                                = 'AnyDesk.AnyDesk'
    'Dell SupportAssist'                     = 'Dell.SupportAssistforBusinessPCs'
    'Microsoft 3D Viewer'                    = 'Microsoft.Microsoft3DViewer'
    'EOL.*Microsoft \.Net Version 6'         = 'Microsoft.DotNet.Runtime.8'
    'EOL.*Microsoft \.Net Core Version 5'    = 'Microsoft.DotNet.Runtime.8'
    'EOL.*Microsoft \.Net Core Version 7'    = 'Microsoft.DotNet.Runtime.8'
    'Microsoft \.NET'                        = 'Microsoft.DotNet.Runtime.8'
    'Microsoft ASP\.NET'                     = 'Microsoft.DotNet.SDK.8'
    'PostgreSQL'                             = $null   # DB upgrade -- manual track
}

$RegistryFixMap = [ordered]@{
    'Windows SMB Version 1'                  = 'Disable-SMBv1'
    'SMB Signing Disabled'                   = 'Enable-SMBSigning'
    'SMBv2 Signing Not Required'             = 'Enable-SMBSigning'
    'TLSv1\.1'                               = 'Disable-TLS11'
    'TLSv1\.0'                               = 'Disable-TLS10'
    'Sweet32'                                = 'Disable-3DES'
    'RC4'                                    = 'Disable-RC4'
    'Weak SSL/TLS Key Exchange'              = 'Fix-WeakDH'
    'LLMNR'                                  = 'Disable-LLMNR'
    'LDAP.*Signing'                          = 'Enable-LDAPClientSigning'
    'LDAP.*Channel Binding'                  = 'Enable-LDAPChannelBinding'
    'AutoPlay'                               = 'Disable-AutoPlay'
    'AutoRun'                                = 'Disable-AutoRun'
    'Autoplay Not Disabled for Default'      = 'Disable-AutoRun'
    'Unquoted.*Service'                      = 'Fix-UnquotedServicePaths'
    'Cached Logon'                           = 'Limit-CachedLogons'
    'Display.*Last.*User'                    = 'Disable-DisplayLastUsername'
    'Null Session'                           = 'Restrict-NullSessions'
    'NetBIOS'                                = 'Disable-NetBIOS'
    'Kerberos Protocol Changes'              = 'Apply-KerberosRegistryFix'
    'DNS Resolver.*Spoofing'                 = 'Apply-DNSSpoofingFix'
}

# These are never touched automatically -- always logged for human action.
$ManualPatterns = @(
    'Adobe Illustrator', 'Adobe Photoshop', 'Adobe Premiere Pro',
    'Adobe InDesign', 'Adobe After Effects',
    'EOL.*SQL Server',
    'EOL.*Operating System.*23H2',
    'CrowdStrike',
    'Logitech',
    'Ricoh Printer',
    'SSL Certificate',
    'Intel.*Smart Sound',
    'Intel.*RST',
    'Intel.*Chipset',
    'KeePass.*Password Retrieval',
    'PostgreSQL',
    'Guest Account Not Renamed',
    'Password Does Not Expire',
    'Default.*Administrator Account',
    'User Accounts.*Unchanged',
    'Built-in.*Guest',
    'Unused Active Windows Accounts',         # Account lifecycle -- manual review required
    'Windows Service Weak Permissions'        # ACL remediation -- manual audit required
)

# These are non-Windows assets -- logged as SKIP when encountered on Windows endpoints.
$SkipPatterns = @(
    'Cisco IOS', 'Cisco Internetwork', 'Cisco Router',
    'Schneider Modicon', 'Predictable TCP', 'ICMP',
    'RPC Portmapper', 'NTP Information'
)

# ==============================================================================
#  LOGGING
# ==============================================================================

$ThisHost  = $env:COMPUTERNAME.ToUpper()
$RunId     = Get-Date -Format 'yyyyMMdd_HHmmss'
$RunLogDir = Join-Path $LogPath $RunId
$MasterLog = Join-Path $RunLogDir "${ThisHost}_${RunId}.log"

function Initialize-Logging {
    if (-not (Test-Path $RunLogDir)) {
        New-Item -ItemType Directory -Path $RunLogDir -Force | Out-Null
    }
    "=== MedPro Nucleus Remediation | Host: $ThisHost | Run: $RunId | Mode: $(if($DryRun){'DRY-RUN'}else{'LIVE'}) ===" |
        Out-File -FilePath $MasterLog -Encoding UTF8
}

function Write-NLog {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','SKIP','PLAN')]
        [string]$Level = 'INFO'
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$ts [$Level] [$ThisHost] $Message"
    Add-Content -Path $MasterLog -Value $line -ErrorAction SilentlyContinue
    $color = switch ($Level) {
        'ERROR'   { 'Red' }
        'WARN'    { 'Yellow' }
        'SUCCESS' { 'Green' }
        'SKIP'    { 'DarkGray' }
        'PLAN'    { 'Cyan' }
        default   { 'White' }
    }
    Write-Host $line -ForegroundColor $color
}

# ==============================================================================
#  PLAN BUILDER
# ==============================================================================

function Build-Plan {
    param([string[]]$Vulns)

    $plan = [PSCustomObject]@{
        NeedsWindowsUpdate = $false
        WingetPackages     = [System.Collections.Generic.List[string]]::new()
        RegistryFixes      = [System.Collections.Generic.List[string]]::new()
        ManualItems        = [System.Collections.Generic.List[string]]::new()
        SkippedItems       = [System.Collections.Generic.List[string]]::new()
    }

    foreach ($vuln in $Vulns) {
        if ([string]::IsNullOrWhiteSpace($vuln)) { continue }

        # -- Skip non-Windows assets entirely ----------------------------------
        $skipped = $false
        foreach ($pat in $SkipPatterns) {
            if ($vuln -match $pat) {
                if (-not $plan.SkippedItems.Contains("[SKIP] $vuln")) {
                    $plan.SkippedItems.Add("[SKIP] $vuln")
                }
                $skipped = $true; break
            }
        }
        if ($skipped) { continue }

        # -- Manual-only items -------------------------------------------------
        $isManual = $false
        foreach ($pat in $ManualPatterns) {
            if ($vuln -match $pat) {
                if (-not $plan.ManualItems.Contains("[MANUAL] $vuln")) {
                    $plan.ManualItems.Add("[MANUAL] $vuln")
                }
                $isManual = $true; break
            }
        }
        if ($isManual) { continue }

        # -- Pending reboot: handled dynamically by OS check at runtime --------
        if ($vuln -match 'Pending Reboot') { continue }

        # -- Dell BIOS/firmware: delivered via Windows Update on managed fleet -
        if ($vuln -match 'Dell.*BIOS|Dell Client Security Update') {
            $plan.NeedsWindowsUpdate = $true
            continue
        }

        # -- Registry fixes ----------------------------------------------------
        $regMatched = $false
        foreach ($pat in $RegistryFixMap.Keys) {
            if ($vuln -match $pat) {
                $fixId = $RegistryFixMap[$pat]
                if (-not $plan.RegistryFixes.Contains($fixId)) {
                    $plan.RegistryFixes.Add($fixId)
                }
                $regMatched = $true; break
            }
        }
        if ($regMatched) { continue }

        # -- Winget package upgrades -------------------------------------------
        # Multiple CVEs referencing different versions of the same product
        # (e.g. "Chrome Prior to 135.0" and "Chrome Prior to 146.0") will both
        # match the same key and deduplicate to one package ID. Winget always
        # upgrades to the latest available version, covering all version-specific
        # CVEs for that product in a single pass.
        $wgMatched = $false
        foreach ($pat in $WingetPackageMap.Keys) {
            if ($vuln -match $pat) {
                $pkgId = $WingetPackageMap[$pat]
                if ($null -eq $pkgId) {
                    if (-not $plan.ManualItems.Contains("[MANUAL-DB] $vuln")) {
                        $plan.ManualItems.Add("[MANUAL-DB] $vuln")
                    }
                } elseif (-not $plan.WingetPackages.Contains($pkgId)) {
                    $plan.WingetPackages.Add($pkgId)
                }
                $wgMatched = $true; break
            }
        }
        if ($wgMatched) { continue }

        # -- Windows Update catch-all for Microsoft OS/component CVEs ----------
        if ($vuln -match 'Microsoft Windows Security Update|Microsoft Windows.*Vulnerability|Microsoft Desktop Window|Microsoft \.NET|Microsoft ASP\.NET|Microsoft Windows Subsystem') {
            $plan.NeedsWindowsUpdate = $true
            continue
        }

        # -- Nothing matched ---------------------------------------------------
        if (-not $plan.ManualItems.Contains("[NO-HANDLER] $vuln")) {
            $plan.ManualItems.Add("[NO-HANDLER] $vuln")
        }
    }

    return $plan
}

# ==============================================================================
#  REMEDIATION FUNCTIONS
# ==============================================================================

function Test-PendingReboot {
    $reboot = $false
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reboot = $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reboot = $true }
    if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue) { $reboot = $true }
    return $reboot
}

function Invoke-WindowsUpdate {
    param([bool]$Dry)
    $results = [System.Collections.Generic.List[object]]::new()
    try {
        if (-not (Get-Module -ListAvailable PSWindowsUpdate -ErrorAction SilentlyContinue)) {
            Write-NLog '  [WU] Installing PSWindowsUpdate module...'
            Install-PackageProvider NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -EA Stop | Out-Null
            Install-Module PSWindowsUpdate -Force -Scope AllUsers -AllowClobber -EA Stop | Out-Null
        }
        Import-Module PSWindowsUpdate -Force -EA Stop

        if ($Dry) {
            $pending = Get-WindowsUpdate -AcceptAll -IgnoreReboot -EA SilentlyContinue
            if ($pending) {
                foreach ($u in $pending) {
                    $results.Add([PSCustomObject]@{ KB=$u.KB; Title=$u.Title; Status='Pending-DryRun'; NeedsReboot=$false })
                }
            } else {
                $results.Add([PSCustomObject]@{ KB='-'; Title='Already up to date'; Status='AlreadyUpToDate'; NeedsReboot=$false })
            }
        } else {
            $updates = Install-WindowsUpdate -AcceptAll -AutoReboot:$false -IgnoreReboot -Confirm:$false -EA SilentlyContinue
            if ($updates) {
                foreach ($u in $updates) {
                    $results.Add([PSCustomObject]@{ KB=$u.KB; Title=$u.Title; Status=$u.Result; NeedsReboot=[bool]$u.RebootRequired })
                }
            } else {
                $results.Add([PSCustomObject]@{ KB='-'; Title='Already up to date'; Status='AlreadyUpToDate'; NeedsReboot=$false })
            }
        }
    } catch {
        $results.Add([PSCustomObject]@{ KB='ERROR'; Title=$_.Exception.Message; Status='Failed'; NeedsReboot=$false })
    }
    return $results
}

function Invoke-WingetUpgrades {
    param([string[]]$PackageIds, [bool]$Dry)
    $results = [System.Collections.Generic.List[object]]::new()

    # Locate winget -- may not be on PATH when running as SYSTEM
    $wgCmd = 'winget.exe'
    $test  = cmd.exe /c "$wgCmd --version" 2>&1
    if ($test -match 'is not recognized') {
        $appxExe = Get-Item 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe' `
            -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1 -ExpandProperty FullName
        if ($appxExe) {
            $wgCmd = "`"$appxExe`""
        } else {
            Write-NLog '  [WINGET] winget not found or access denied for SYSTEM account.' WARN
            return $results
        }
    }

    cmd.exe /c "$wgCmd source update --accept-source-agreements" 2>&1 | Out-Null

    foreach ($pkgId in $PackageIds) {
        if ([string]::IsNullOrWhiteSpace($pkgId)) { continue }
        try {
            # Check if package is installed before attempting upgrade
            $listOut = cmd.exe /c "$wgCmd list --id $pkgId --exact --accept-source-agreements" 2>&1 | Out-String
            if ($listOut -notmatch [regex]::Escape($pkgId)) {
                $results.Add([PSCustomObject]@{ PackageId=$pkgId; Status='NotInstalled-Skipped'; Updated=$false })
                continue
            }

            if ($Dry) {
                $upOut = cmd.exe /c "$wgCmd upgrade --id $pkgId --exact --accept-source-agreements" 2>&1 | Out-String
                $st    = if ($upOut -match 'No applicable update') { 'UpToDate' } else { 'UpdateAvailable-DryRun' }
                $results.Add([PSCustomObject]@{ PackageId=$pkgId; Status=$st; Updated=$false })
            } else {
                # --force intentionally omitted: without it, winget reports exit code
                # -1978335217 ("no applicable update") when already at latest version
                # rather than reinstalling unnecessarily.
                $upOut = cmd.exe /c "$wgCmd upgrade --id $pkgId --exact --silent --accept-package-agreements --accept-source-agreements" 2>&1 | Out-String
                $ec    = $LASTEXITCODE

                $st = if     ($ec -eq 0 -or $upOut -match 'Successfully installed') { 'Updated' }
                      elseif ($ec -eq -1978335217 -or $upOut -match 'No applicable update') { 'AlreadyUpToDate' }
                      elseif ($upOut -match 'failed|error') { 'Failed' }
                      else                                  { "Completed-Exit$ec" }

                $results.Add([PSCustomObject]@{ PackageId=$pkgId; Status=$st; Updated=($st -eq 'Updated') })
            }
        } catch {
            $results.Add([PSCustomObject]@{ PackageId=$pkgId; Status="Error: $($_.Exception.Message)"; Updated=$false })
        }
    }
    return $results
}

function Invoke-RegistryFixes {
    param([string[]]$FixIds, [bool]$Dry)
    $results = [System.Collections.Generic.List[object]]::new()

    # Apply helper: optional $Check scriptblock runs first.
    # If $Check returns $true, the setting is already compliant -> AlreadyConfigured.
    # Errors inside $Check are swallowed so a bad check never blocks the actual fix.
    function Apply {
        param(
            [string]$Id,
            [bool]$Dry,
            [scriptblock]$Action,
            [scriptblock]$Check = $null
        )
        if ($null -ne $Check) {
            try {
                if (& $Check) {
                    return [PSCustomObject]@{ Fix=$Id; Status='AlreadyConfigured'; Error='' }
                }
            } catch { <# check failed -- proceed with fix anyway #> }
        }
        if ($Dry) { return [PSCustomObject]@{ Fix=$Id; Status='DryRun'; Error='' } }
        try   { & $Action; return [PSCustomObject]@{ Fix=$Id; Status='Applied'; Error='' } }
        catch { return [PSCustomObject]@{ Fix=$Id; Status='Failed'; Error=$_.Exception.Message } }
    }

    foreach ($fix in $FixIds) {
        if ([string]::IsNullOrWhiteSpace($fix)) { continue }
        switch ($fix) {

            'Disable-SMBv1' {
                $results.Add((Apply $fix $Dry `
                    -Check  { -not (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol } `
                    -Action {
                        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false -Force
                        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 -Type DWord -Force
                    }
                ))
            }

            'Enable-SMBSigning' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $c = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                        $c -and $c.RequireSecuritySignature -and $c.EnableSecuritySignature
                    } `
                    -Action {
                        Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Confirm:$false -Force
                        Set-SmbClientConfiguration -EnableSecuritySignature $true -Confirm:$false -Force
                    }
                ))
            }

            'Disable-TLS10' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $ok = $true
                        foreach ($role in 'Server','Client') {
                            $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\$role"
                            $v = Get-ItemProperty $p -ErrorAction SilentlyContinue
                            if (-not $v -or $v.Enabled -ne 0 -or $v.DisabledByDefault -ne 1) { $ok = $false; break }
                        }
                        $ok
                    } `
                    -Action {
                        foreach ($role in 'Server','Client') {
                            $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\$role"
                            New-Item $p -Force | Out-Null
                            Set-ItemProperty $p 'Enabled' 0 -Type DWord -Force
                            Set-ItemProperty $p 'DisabledByDefault' 1 -Type DWord -Force
                        }
                    }
                ))
            }

            'Disable-TLS11' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $ok = $true
                        foreach ($role in 'Server','Client') {
                            $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\$role"
                            $v = Get-ItemProperty $p -ErrorAction SilentlyContinue
                            if (-not $v -or $v.Enabled -ne 0 -or $v.DisabledByDefault -ne 1) { $ok = $false; break }
                        }
                        $ok
                    } `
                    -Action {
                        foreach ($role in 'Server','Client') {
                            $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\$role"
                            New-Item $p -Force | Out-Null
                            Set-ItemProperty $p 'Enabled' 0 -Type DWord -Force
                            Set-ItemProperty $p 'DisabledByDefault' 1 -Type DWord -Force
                        }
                    }
                ))
            }

            'Disable-3DES' {
                $results.Add((Apply $fix $Dry `
                    -Action {
                        $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168'
                        New-Item $p -Force | Out-Null
                        Set-ItemProperty $p 'Enabled' 0 -Type DWord -Force
                    }
                ))
            }

            'Disable-RC4' {
                $results.Add((Apply $fix $Dry `
                    -Action {
                        foreach ($v in 'RC4 40/128','RC4 56/128','RC4 128/128') {
                            $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$v"
                            New-Item $p -Force | Out-Null
                            Set-ItemProperty $p 'Enabled' 0 -Type DWord -Force
                        }
                    }
                ))
            }

            'Fix-WeakDH' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'
                        $v = Get-ItemProperty $p -ErrorAction SilentlyContinue
                        $v -and ($v.ServerMinKeyBitLength -ge 2048)
                    } `
                    -Action {
                        $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman'
                        New-Item $p -Force | Out-Null
                        Set-ItemProperty $p 'ServerMinKeyBitLength' 2048 -Type DWord -Force
                    }
                ))
            }

            'Disable-LLMNR' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
                        $v = Get-ItemProperty $p -ErrorAction SilentlyContinue
                        $v -and ($v.EnableMulticast -eq 0)
                    } `
                    -Action {
                        $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
                        New-Item $p -Force | Out-Null
                        Set-ItemProperty $p 'EnableMulticast' 0 -Type DWord -Force
                    }
                ))
            }

            'Enable-LDAPClientSigning' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' -Name 'LDAPClientIntegrity' -ErrorAction SilentlyContinue
                        $v -and ($v.LDAPClientIntegrity -eq 2)
                    } `
                    -Action {
                        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\ldap' 'LDAPClientIntegrity' 2 -Type DWord -Force
                    }
                ))
            }

            'Enable-LDAPChannelBinding' {
                $results.Add((Apply $fix $Dry `
                    -Action {
                        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
                        if (Test-Path $p) { Set-ItemProperty $p 'LdapEnforceChannelBinding' 2 -Type DWord -Force }
                        $p2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0'
                        New-Item $p2 -Force | Out-Null
                        Set-ItemProperty $p2 'SealSecureChannel' 1 -Type DWord -Force
                    }
                ))
            }

            'Disable-AutoPlay' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                        $v = Get-ItemProperty $p -ErrorAction SilentlyContinue
                        $v -and ($v.NoDriveTypeAutoRun -eq 0xFF) -and ($v.NoAutorun -eq 1)
                    } `
                    -Action {
                        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                        New-Item $p -Force | Out-Null
                        Set-ItemProperty $p 'NoDriveTypeAutoRun' 0xFF -Type DWord -Force
                        Set-ItemProperty $p 'NoAutorun' 1 -Type DWord -Force
                    }
                ))
            }

            'Disable-AutoRun' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                        $v = Get-ItemProperty $p -ErrorAction SilentlyContinue
                        $v -and ($v.NoDriveTypeAutoRun -eq 0xFF)
                    } `
                    -Action {
                        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
                        New-Item $p -Force | Out-Null
                        Set-ItemProperty $p 'NoDriveTypeAutoRun' 0xFF -Type DWord -Force
                    }
                ))
            }

            'Restrict-NullSessions' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
                        $v -and ($v.RestrictAnonymous -eq 1) -and ($v.RestrictAnonymousSAM -eq 1) -and ($v.EveryoneIncludesAnonymous -eq 0)
                    } `
                    -Action {
                        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                        Set-ItemProperty $lsa 'RestrictAnonymous' 1 -Type DWord -Force
                        Set-ItemProperty $lsa 'RestrictAnonymousSAM' 1 -Type DWord -Force
                        Set-ItemProperty $lsa 'EveryoneIncludesAnonymous' 0 -Type DWord -Force
                    }
                ))
            }

            'Disable-DisplayLastUsername' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                        $v = Get-ItemProperty $p -ErrorAction SilentlyContinue
                        $v -and ($v.DontDisplayLastUserName -eq 1)
                    } `
                    -Action {
                        $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                        New-Item $p -Force | Out-Null
                        Set-ItemProperty $p 'DontDisplayLastUserName' 1 -Type DWord -Force
                    }
                ))
            }

            'Limit-CachedLogons' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
                            -Name 'CachedLogonsCount' -ErrorAction SilentlyContinue).CachedLogonsCount
                        $v -and ([int]$v -le 2)
                    } `
                    -Action {
                        Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
                            'CachedLogonsCount' '2' -Type String -Force
                    }
                ))
            }

            'Fix-UnquotedServicePaths' {
                $results.Add((Apply $fix $Dry `
                    -Action {
                        $base = 'HKLM:\SYSTEM\CurrentControlSet\Services'
                        foreach ($svc in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
                            try {
                                $img = (Get-ItemProperty $svc.PSPath 'ImagePath' -EA SilentlyContinue).ImagePath
                                if (-not $img) { continue }
                                if ($img -match ' ' -and $img -notmatch '^"' -and $img -notmatch '^svchost') {
                                    if ($img -match '^([^"]+\.exe)(.*)$') {
                                        $exe    = $Matches[1].Trim()
                                        $args   = $Matches[2].Trim()
                                        $quoted = if ($args) { "`"$exe`" $args" } else { "`"$exe`"" }
                                        Set-ItemProperty $svc.PSPath 'ImagePath' $quoted -Force
                                    }
                                }
                            } catch { continue }
                        }
                    }
                ))
            }

            'Disable-NetBIOS' {
                # Uses registry path fallback -- CIM/WMI SetTcpipNetbios is unreliable
                # on USB NICs (Realtek USB GbE adapters fail the WMI call silently).
                # NetbiosOptions values: 0=Default, 1=Enabled, 2=Disabled
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $allDisabled = $true
                        $ifaceKey = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
                        if ($ifaceKey) {
                            foreach ($sub in $ifaceKey.GetSubKeyNames()) {
                                $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$sub" `
                                    -Name 'NetbiosOptions' -ErrorAction SilentlyContinue).NetbiosOptions
                                if ($val -ne 2) { $allDisabled = $false; break }
                            }
                        }
                        $allDisabled
                    } `
                    -Action {
                        $ifaceKey = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
                        if ($ifaceKey) {
                            foreach ($sub in $ifaceKey.GetSubKeyNames()) {
                                Set-ItemProperty `
                                    "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$sub" `
                                    'NetbiosOptions' 2 -Type DWord -Force
                            }
                        }
                    }
                ))
            }

            'Apply-KerberosRegistryFix' {
                # Only applies on domain controllers where the Kdc service key exists.
                # Silently skips (AlreadyConfigured) on workstations and member servers.
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
                        if (-not (Test-Path $p)) { return $true }   # Not a DC -- treat as already handled
                        $v = Get-ItemProperty $p -Name 'KrbtgtFullPacSignature' -ErrorAction SilentlyContinue
                        $v -and ($v.KrbtgtFullPacSignature -eq 2)
                    } `
                    -Action {
                        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
                        if (Test-Path $p) { Set-ItemProperty $p 'KrbtgtFullPacSignature' 2 -Type DWord -Force }
                    }
                ))
            }

            'Apply-DNSSpoofingFix' {
                $results.Add((Apply $fix $Dry `
                    -Check  {
                        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters'
                        $v = Get-ItemProperty $p -ErrorAction SilentlyContinue
                        $v -and ($v.MaximumUdpPacketSize -eq 1221)
                    } `
                    -Action {
                        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters'
                        New-Item $p -Force | Out-Null
                        Set-ItemProperty $p 'MaximumUdpPacketSize' 1221 -Type DWord -Force
                    }
                ))
            }

            default {
                $results.Add([PSCustomObject]@{ Fix=$fix; Status='NoHandlerFound'; Error='' })
            }
        }
    }
    return $results
}

function Set-DeferredReboot {
    param([int]$DelayMin)
    $at  = (Get-Date).AddMinutes($DelayMin)
    $act = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/r /t 30 /c "MedPro Nucleus Remediation reboot" /f'
    $trg = New-ScheduledTaskTrigger -Once -At $at
    $cfg = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -DeleteExpiredTaskAfter (New-TimeSpan -Hours 2)
    Register-ScheduledTask -TaskName 'MedPro_NucleusRemediation_Reboot' `
        -Action $act -Trigger $trg -Settings $cfg -RunLevel Highest -Force | Out-Null
    Write-NLog "  [REBOOT] Scheduled for $($at.ToString('HH:mm')) (+$DelayMin min)" SUCCESS
    return $true
}

# ==============================================================================
#  MAIN
# ==============================================================================

Initialize-Logging

Write-NLog '=== MedPro Nucleus Remediation Engine starting ==='
Write-NLog "Host : $ThisHost"
Write-NLog "Mode : $(if($DryRun){'DRY-RUN -- no changes will be made'}else{'LIVE EXECUTION'})"

Write-NLog 'Compiling execution plan from global vulnerability list...'
$Plan = Build-Plan -Vulns $GlobalVulnerabilityList

Write-NLog ''
Write-NLog ("PLAN | WU={0} | Winget={1} pkg(s) | Reg={2} fix(es) | Manual={3}" -f
    $Plan.NeedsWindowsUpdate,
    $Plan.WingetPackages.Count,
    $Plan.RegistryFixes.Count,
    $Plan.ManualItems.Count) PLAN

if ($DryRun) { Write-NLog 'DRY-RUN active -- no changes will be made.' WARN }
Write-NLog ''

$errs            = [System.Collections.Generic.List[string]]::new()
$wuCount         = 0
$wgCount         = 0
$regCount        = 0
$rebootScheduled = $false

# -- 1. Windows Update (includes Dell BIOS via WU) ----------------------------
if ($Plan.NeedsWindowsUpdate) {
    Write-NLog '--- Windows Update'
    try {
        $wuRes   = Invoke-WindowsUpdate -Dry $DryRun
        $wuCount = @($wuRes | Where-Object { $_.Status -notin @('AlreadyUpToDate','DryRun') }).Count
        foreach ($u in $wuRes) {
            Write-NLog "  [WU] $($u.KB)  $($u.Title) -> $($u.Status)"
        }
    } catch {
        $errs.Add("WU: $($_.Exception.Message)")
        Write-NLog "  [WU] ERROR: $($_.Exception.Message)" ERROR
    }
}

# -- 2. Winget upgrades -------------------------------------------------------
if ($Plan.WingetPackages.Count -gt 0) {
    Write-NLog "--- Winget ($($Plan.WingetPackages.Count) package(s))"
    try {
        $wgRes   = Invoke-WingetUpgrades -PackageIds $Plan.WingetPackages -Dry $DryRun
        $wgCount = @($wgRes | Where-Object { $_.Updated }).Count
        foreach ($w in $wgRes) {
            Write-NLog "  [WINGET] $($w.PackageId) -> $($w.Status)"
        }
    } catch {
        $errs.Add("Winget: $($_.Exception.Message)")
        Write-NLog "  [WINGET] ERROR: $($_.Exception.Message)" ERROR
    }
}

# -- 3. Registry fixes --------------------------------------------------------
if ($Plan.RegistryFixes.Count -gt 0) {
    Write-NLog "--- Registry fixes ($($Plan.RegistryFixes.Count))"
    try {
        $regRes   = Invoke-RegistryFixes -FixIds $Plan.RegistryFixes -Dry $DryRun
        $regCount = @($regRes | Where-Object { $_.Status -eq 'Applied' }).Count
        foreach ($r in $regRes) {
            $suffix = if ($r.Error) { " -- $($r.Error)" } else { '' }
            $lvl    = switch ($r.Status) {
                'Applied'           { 'SUCCESS' }
                'AlreadyConfigured' { 'INFO' }
                'Failed'            { 'ERROR' }
                default             { 'INFO' }
            }
            Write-NLog "  [REG] $($r.Fix) -> $($r.Status)$suffix" $lvl
        }
    } catch {
        $errs.Add("Registry: $($_.Exception.Message)")
        Write-NLog "  [REG] ERROR: $($_.Exception.Message)" ERROR
    }
}

# -- 4. Manual items ----------------------------------------------------------
if ($Plan.ManualItems.Count -gt 0) {
    Write-NLog '--- Manual review required'
    foreach ($item in $Plan.ManualItems) { Write-NLog "  $item" WARN }
}

# -- 5. Skipped items (non-Windows assets) ------------------------------------
foreach ($item in $Plan.SkippedItems) { Write-NLog "  $item" SKIP }

# -- 6. Schedule reboot if needed ---------------------------------------------
$osPendingReboot = Test-PendingReboot
$rebootNeeded    = $osPendingReboot -or ($wuCount -gt 0) -or ($regCount -gt 0) -or ($wgCount -gt 0)

if ($rebootNeeded -and $ScheduleReboot -and -not $DryRun) {
    Write-NLog "--- Scheduling reboot (OS-pending: $osPendingReboot | WU: $wuCount | Reg: $regCount | Winget: $wgCount)"
    try {
        $rebootScheduled = Set-DeferredReboot -DelayMin $RebootDelayMinutes
    } catch {
        $errs.Add("Reboot: $($_.Exception.Message)")
        Write-NLog "  [REBOOT] ERROR: $($_.Exception.Message)" ERROR
    }
}

# -- Final summary -------------------------------------------------------------
$finalStatus = if ($errs.Count -eq 0) {
    if ($DryRun) { 'DryRun-Complete' } else { 'Success' }
} else { 'CompletedWithErrors' }

Write-NLog ''
Write-NLog '=== DONE ==='
Write-NLog "Status          : $finalStatus" $(if ($finalStatus -eq 'Success') { 'SUCCESS' } else { 'WARN' })
Write-NLog "WU patches      : $wuCount"
Write-NLog "Winget updates  : $wgCount"
Write-NLog "Registry fixes  : $regCount"
Write-NLog "Reboot scheduled: $rebootScheduled"
Write-NLog "Manual items    : $($Plan.ManualItems.Count)"
if ($errs.Count -gt 0) {
    Write-NLog 'Errors:' ERROR
    foreach ($e in $errs) { Write-NLog "  $e" ERROR }
}
Write-NLog "Log: $MasterLog"
