#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Invoke-MedProVulnRemediation.ps1
    Standalone Nucleus vulnerability remediation script for MedPro Healthcare Staffing.

.DESCRIPTION
    Remediates findings from the May 4, 2026 Nucleus report
    (VulnerabilityScanner-20260504.xlsx / 170 populated findings).
    Designed to run locally on any Windows endpoint without parameters or a
    machine map. Covers:

      * Windows Monthly Security Updates (Dec 2025 through May 2026)
      * Microsoft .NET / ASP.NET Core (Feb/Mar/Apr 2026 + Apr 2026 OOB CVE-2026-40372)
        EOL .NET 5/6/7 forced uninstall
      * Microsoft Office (Apr 2026 security update -- C2R + MSI)
      * Browsers: Microsoft Edge (up to 147.0.3912.86), Google Chrome (up to 147.0.7727.137)
      * Java: Oracle JRE/JDK (through CPUAPR2026)
      * 7-Zip (CVE-2024-11477, CVE-2025-0411, CVE-2025-53816/53817, CVE-2025-55188)
      * Beyond Compare (CVE-2022-36414)
      * NVIDIA GeForce Experience (CVE-2021-1073, CVE-2020-5964)
      * Zoom VDI (ZSB-25047, ZSB-25044, ZSB-25041, ZSB-26005, ZSB-26004)
      * TechSmith Snagit (LPE + XXE CVE-2020-11541)
      * Visual Studio Code (CVE-2025-62453, CVE-2025-64660, CVE-2026-21518/21523), Live Server, Copilot Chat
      * Visual C++ Redistributable (CVE-2024-43590)
      * Microsoft Teams, Ghostscript, Node.js, FileZilla, KeePass, PyCharm, PostgreSQL, Git, Microsoft 3D Viewer
      * Adobe Genuine Service, Acrobat/Reader (APSB25-57/85/119, APSB26-43/44),
        Photoshop (APSB25-30/40/75/108, APSB26-40), Illustrator (APSB25-109)
        EOL Adobe Reader/Acrobat XI / DC 2015 / 2017 forced uninstall
      * Dell SupportAssist (uninstall) -- DSA-2025-445, DSA-2025-296, DSA-2024-470, DSA-2023-468, DSA-2021-163
      * Dell BIOS/Firmware (dcu-cli) + manual guidance for all active DSAs:
        DSA-2026-010, DSA-2025-206, DSA-2025-203, DSA-2025-048, DSA-2025-021,
        DSA-2025-020, DSA-2025-016, DSA-2025-088, DSA-2025-044, DSA-2025-153,
        DSA-2025-005, DSA-2025-002, DSA-2024-351, DSA-2024-373, DSA-2024-297,
        DSA-2024-231, DSA-2024-168, DSA-2024-113, DSA-2024-066, DSA-2024-030,
        DSA-2021-216
      * CrowdStrike Falcon Sensor (CVE-2025-42701, CVE-2025-42706)
      * Ricoh Printer Drivers (Windows Update scan + manual guidance)
      * Registry & System Hardening:
          - Null Sessions (CVE-2002-1117, CVE-2000-1200)
          - Built-in Admin rename (CVE-1999-0585)
          - Guest Account disable/rename
          - RRAS disable (CVE-2026-21221)
          - SMB Signing enforcement (CVSS 7.3)
          - Windows AutoPlay disable
          - LDAP Channel Binding and Signing (ADV190023)
          - NetBIOS disable over TCP/IP
          - Windows Unquoted Service Paths auto-fix
          - Logitech firmware -- manual
          - Intel Chipset/RST/Smart Sound Technology -- manual or Dell Command Update
      * Windows Defender signature update (RedSun Zero Day EoP, CVSS 7.8)
      * EOL Windows 11 23H2 -- manual upgrade guidance

    After every software upgrade, old-version Program Files folders and
    uninstall entries are detected and removed.

.PARAMETER LogPath
    Directory for log transcript and CSV report. Default: C:\MedPro\Logs

.PARAMETER NewAdminName
    Replacement name for the built-in Administrator account (SID *-500).
    Default: MPAdmin

.PARAMETER SkipWindowsUpdate
    Bypass the PSWindowsUpdate pass. Use when WU is managed by WSUS/Intune.

.PARAMETER WindowsUpdateMode
    Install, ScanOnly, or Skip. Default: Install.

.PARAMETER Section
    All or WindowsUpdate. Use WindowsUpdate for a non-destructive scan-only or
    patch-only run without launching the third-party remediation sections.

.NOTES
    Requirements  : Windows 10/11, PowerShell 5.1+, Administrator/SYSTEM context
                    winget 1.4+ (Windows Package Manager)
                    Internet access or WSUS for Windows Updates
                    Adobe Remote Update Manager (auto-detected, CC installs only)
                    Dell Command Update / dcu-cli (auto-detected, Dell hardware only)
    Version       : 5.0
    Report Source : VulnerabilityScanner-20260504.xlsx (170 populated findings)
    Organization  : MedPro Healthcare Staffing
    Generated     : May 4, 2026
    Prior Version : 4.0 (April 27, 2026 scan)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$LogPath      = 'C:\MedPro\Logs',
    [string]$NewAdminName = 'MPAdmin',
    [ValidateSet('Install','ScanOnly','Skip')]
    [string]$WindowsUpdateMode = 'Install',
    [ValidateSet('All','WindowsUpdate')]
    [string]$Section = 'All',
    [switch]$SkipWindowsUpdate
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:RebootRequired = $false
$script:ManualItems    = [System.Collections.Generic.List[string]]::new()
$script:Results        = [System.Collections.Generic.List[hashtable]]::new()
$script:StartTime      = Get-Date

# --- Logging -----------------------------------------------------------------
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}
$LogFile   = Join-Path $LogPath "VulnRemediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ReportCsv = Join-Path $LogPath "VulnRemediation_Report_$(Get-Date -Format 'yyyyMMdd').csv"

Start-Transcript -Path $LogFile -Append | Out-Null

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','OK','WARN','ERROR','SKIP','MANUAL','SECTION')]
        [string]$Level = 'INFO'
    )
    $ts     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $padded = $Level.PadRight(7)
    $line   = "[$ts][$padded] $Message"
    $color  = switch ($Level) {
        'OK'      { 'Green'    }
        'WARN'    { 'Yellow'   }
        'ERROR'   { 'Red'      }
        'SKIP'    { 'DarkCyan' }
        'MANUAL'  { 'Magenta'  }
        'SECTION' { 'White'    }
        default   { 'Gray'     }
    }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Add-Result {
    param(
        [string]$Category,
        [string]$Item,
        [string]$Status,
        [string]$Detail = ''
    )
    $script:Results.Add(@{
        Computer  = $env:COMPUTERNAME
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Category  = $Category
        Item      = $Item
        Status    = $Status
        Detail    = $Detail
    })
}

function Add-Manual {
    param([string]$Item)
    $script:ManualItems.Add($Item)
    Write-Log "MANUAL REQUIRED: $Item" MANUAL
    Add-Result 'Manual Review' $Item 'Needs Manual Action'
}

# --- Helper Functions ---------------------------------------------------------

function Test-WingetAvailable {
    # Check PATH first, then fall back to the known WindowsApps location
    if (Get-Command winget.exe -ErrorAction SilentlyContinue) { return $true }
    $fallback = "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe"
    if (Test-Path $fallback) {
        # Add to session PATH so subsequent calls work
        $env:PATH = "$env:LOCALAPPDATA\Microsoft\WindowsApps;$env:PATH"
        return $true
    }
    return $false
}

function Install-WingetIfMissing {
    <#
    .SYNOPSIS
        Ensures winget (Windows Package Manager) is installed before the
        remediation script continues. Downloads and installs the required
        dependency packages (VCLibs, Microsoft.UI.Xaml) and the App Installer
        MSIX bundle from the official Microsoft/GitHub release if winget is
        absent. Refreshes the session PATH and verifies availability.
    #>

    if (Test-WingetAvailable) {
        Write-Log '[OK] winget is already installed and available.' OK
        Add-Result 'Winget Bootstrap' 'winget.exe' 'Already Present'
        return $true
    }

    Write-Log 'winget not found -- attempting automatic installation...' WARN
    Add-Result 'Winget Bootstrap' 'winget.exe' 'Not Present -- Installing'

    $tmpDir = Join-Path $env:TEMP 'WingetBootstrap'
    try {
        if (-not (Test-Path $tmpDir)) {
            New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        }

        # ---- Helper: download a file with retry --------------------------------
        function Get-FileWithRetry {
            param([string]$Url, [string]$Dest, [string]$Label)
            $maxTries = 3
            for ($t = 1; $t -le $maxTries; $t++) {
                try {
                    Write-Log "  Downloading $Label (attempt $t/$maxTries)..." INFO
                    $wc = New-Object System.Net.WebClient
                    $wc.Headers.Add('User-Agent', 'Mozilla/5.0 MedProWingetBootstrap/1.0')
                    $wc.DownloadFile($Url, $Dest)
                    Write-Log "  [OK] Downloaded: $Label" OK
                    return $true
                } catch {
                    Write-Log "  Download attempt $t failed: $_" WARN
                    Start-Sleep -Seconds (5 * $t)
                }
            }
            Write-Log "  [FAIL] Could not download $Label after $maxTries attempts." ERROR
            return $false
        }

        # ---- 1. VCLibs Desktop (required dependency) ---------------------------
        $vcLibsPath = Join-Path $tmpDir 'Microsoft.VCLibs.x64.14.00.Desktop.appx'
        $vcLibsUrl  = 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'
        if (-not (Get-FileWithRetry -Url $vcLibsUrl -Dest $vcLibsPath -Label 'VCLibs x64 14.00')) {
            throw 'VCLibs download failed.'
        }
        Write-Log '  Installing VCLibs dependency...' INFO
        Add-AppxPackage -Path $vcLibsPath -ErrorAction Stop
        Write-Log '  [OK] VCLibs installed.' OK

        # ---- 2. Microsoft.UI.Xaml (required dependency, from NuGet nupkg) ------
        # The nupkg is a ZIP archive; the appx lives at tools/AppX/x64/Release/
        $uiXamlNupkg = Join-Path $tmpDir 'Microsoft.UI.Xaml.nupkg.zip'
        $uiXamlDir   = Join-Path $tmpDir 'UIXaml'
        $uiXamlUrl   = 'https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.8.6'
        if (-not (Get-FileWithRetry -Url $uiXamlUrl -Dest $uiXamlNupkg -Label 'Microsoft.UI.Xaml 2.8.6')) {
            throw 'Microsoft.UI.Xaml download failed.'
        }
        Write-Log '  Extracting Microsoft.UI.Xaml...' INFO
        if (Test-Path $uiXamlDir) { Remove-Item $uiXamlDir -Recurse -Force }
        Expand-Archive -Path $uiXamlNupkg -DestinationPath $uiXamlDir -Force -ErrorAction Stop
        $uiXamlAppx = Get-ChildItem -Path $uiXamlDir -Recurse -Filter '*.appx' |
                      Where-Object { $_.FullName -like '*x64*' } |
                      Select-Object -First 1
        if (-not $uiXamlAppx) {
            # Fallback: any appx in the package
            $uiXamlAppx = Get-ChildItem -Path $uiXamlDir -Recurse -Filter '*.appx' |
                          Select-Object -First 1
        }
        if (-not $uiXamlAppx) { throw 'Microsoft.UI.Xaml appx not found inside nupkg.' }
        Write-Log "  Installing Microsoft.UI.Xaml from: $($uiXamlAppx.FullName)" INFO
        Add-AppxPackage -Path $uiXamlAppx.FullName -ErrorAction Stop
        Write-Log '  [OK] Microsoft.UI.Xaml installed.' OK

        # ---- 3. winget (Microsoft.DesktopAppInstaller) -------------------------
        # Resolve the latest release URL from the GitHub API
        Write-Log '  Resolving latest winget release from GitHub...' INFO
        $apiUrl     = 'https://api.github.com/repos/microsoft/winget-cli/releases/latest'
        $wc2        = New-Object System.Net.WebClient
        $wc2.Headers.Add('User-Agent', 'MedProWingetBootstrap/1.0')
        $releaseJson = $wc2.DownloadString($apiUrl) | ConvertFrom-Json
        $msixAsset   = $releaseJson.assets |
                       Where-Object { $_.name -like '*.msixbundle' } |
                       Select-Object -First 1
        if (-not $msixAsset) {
            # Hard-coded fallback URL if GitHub API is unavailable
            $wingetUrl = 'https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
            Write-Log '  GitHub API did not return asset list -- using fallback URL.' WARN
        } else {
            $wingetUrl = $msixAsset.browser_download_url
            Write-Log "  Latest winget release: $($releaseJson.tag_name)" INFO
        }

        $wingetPath = Join-Path $tmpDir 'Microsoft.DesktopAppInstaller.msixbundle'
        if (-not (Get-FileWithRetry -Url $wingetUrl -Dest $wingetPath -Label 'winget App Installer')) {
            throw 'winget msixbundle download failed.'
        }

        Write-Log '  Installing winget (App Installer)...' INFO
        Add-AppxPackage -Path $wingetPath -ErrorAction Stop
        Write-Log '  [OK] winget (App Installer) installed.' OK

        # ---- 4. Refresh PATH and verify ----------------------------------------
        # Appx packages install to WindowsApps; refresh session PATH
        $appsPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps"
        if ($env:PATH -notlike "*$appsPath*") {
            $env:PATH = "$appsPath;$env:PATH"
        }

        # Give the app registration a moment to complete
        Start-Sleep -Seconds 5

        if (Test-WingetAvailable) {
            Write-Log '[OK] winget installation verified -- proceeding with remediation.' OK
            Add-Result 'Winget Bootstrap' 'winget.exe' 'Installed Successfully'
            return $true
        } else {
            throw 'winget installed but still not detectable in PATH. A reboot may be required.'
        }

    } catch {
        Write-Log "[FAIL] winget auto-install failed: $_" ERROR
        Write-Log '  winget-dependent remediations will be skipped this run.' WARN
        Add-Result 'Winget Bootstrap' 'winget.exe' 'Auto-Install FAILED' "$_"
        Add-Manual "winget (Windows Package Manager) could not be installed automatically. Install manually: open Microsoft Store > search 'App Installer' > Install. Then re-run this script. Error: $_"
        return $false
    } finally {
        # Clean up temp downloads
        if (Test-Path $tmpDir) {
            Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Returns all installed apps from 32-bit and 64-bit uninstall registry hives
function Get-InstalledApps {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName -ne '' }
    }
}

# Upgrade-only via winget (never silently installs software that isn't present)
function Invoke-WingetUpgrade {
    param(
        [string]$PackageId,
        [string]$DisplayName,
        [switch]$InstallIfMissing,
        [string]$Category = 'App Update'
    )
    Write-Log "  winget upgrade -> $DisplayName  [$PackageId]"

    $out = & winget upgrade --id $PackageId --silent `
                            --accept-package-agreements `
                            --accept-source-agreements `
                            --source winget `
                            --scope machine 2>&1 | Out-String
    $ec = $LASTEXITCODE

    # Winget exit codes:
    #   0            = Success (updated)
    #   -1978335212  = 0x8A150014 -- No applicable update (already latest)
    #   -1978335189  = 0x8A15002B -- No available upgrade found
    #   -1978335211  = 0x8A150015 -- Package not found / not installed
    #   -1978334965  = 0x8A15010B -- Reboot required

    if ($ec -eq 0) {
        Write-Log "  OK $DisplayName updated." OK
        Add-Result $Category $DisplayName 'Updated'
        $script:RebootRequired = $true
    }
    elseif ($ec -eq -1978335212 -or $ec -eq -1978335189) {
        Write-Log "  OK $DisplayName already at latest version." SKIP
        Add-Result $Category $DisplayName 'Already Current'
    }
    elseif ($ec -eq -1978335211) {
        if ($InstallIfMissing) {
            Write-Log "  $DisplayName not found; installing..." WARN
            $out2 = & winget install --id $PackageId --silent `
                                     --accept-package-agreements `
                                     --accept-source-agreements `
                                     --source winget `
                                     --scope machine 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                Write-Log "  OK $DisplayName installed." OK
                Add-Result $Category $DisplayName 'Installed'
                $script:RebootRequired = $true
            }
            else {
                Write-Log "  FAIL $DisplayName install failed (exit $LASTEXITCODE)." ERROR
                Add-Result $Category $DisplayName 'Install FAILED' $out2
            }
        }
        else {
            Write-Log "  $DisplayName not installed on this machine - skipped." SKIP
            Add-Result $Category $DisplayName 'Not Present / Skipped'
        }
    }
    elseif ($ec -eq -1978334965) {
        Write-Log "  $DisplayName updated - reboot required to complete." WARN
        Add-Result $Category $DisplayName 'Updated (Reboot Required)'
        $script:RebootRequired = $true
    }
    else {
        Write-Log "  FAIL $DisplayName upgrade failed (exit $ec)." ERROR
        $detail = "exit=$ec"
        Add-Result $Category $DisplayName 'Upgrade FAILED' $detail
    }
}

# Uninstall a specific installed app by display name (with optional version to keep)
function Uninstall-AppByDisplayName {
    param(
        [string]$DisplayNamePattern,
        [string]$KeepVersionPrefix = ''
    )
    $apps = Get-InstalledApps | Where-Object { $_.DisplayName -like $DisplayNamePattern }
    foreach ($app in $apps) {
        if ($KeepVersionPrefix -and $app.DisplayVersion -like "$KeepVersionPrefix*") {
            Write-Log "  Keeping: $($app.DisplayName) $($app.DisplayVersion)" SKIP
            continue
        }
        Write-Log "  Uninstalling: $($app.DisplayName) $($app.DisplayVersion)"
        try {
            if ($app.UninstallString -match 'MsiExec|msiexec') {
                $guid = [regex]::Match($app.UninstallString, '\{[0-9A-Fa-f\-]+\}').Value
                if ($guid) {
                    $p = Start-Process msiexec.exe `
                             -ArgumentList "/x `"$guid`" /qn /norestart" `
                             -Wait -PassThru -ErrorAction Stop
                    if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010) {
                        Write-Log "  [OK] Removed: $($app.DisplayName) $($app.DisplayVersion)" OK
                    } else {
                        Write-Log "  [FAIL] msiexec exit $($p.ExitCode) for $($app.DisplayName)" ERROR
                    }
                }
            } else {
                $cmd = ($app.UninstallString -replace '"', '').Trim()
                Start-Process cmd.exe -ArgumentList "/c `"$cmd`" /S /NORESTART" `
                              -Wait -ErrorAction SilentlyContinue
                Write-Log "  [OK] Uninstall invoked for $($app.DisplayName)" OK
            }
        } catch {
            Write-Log "  [FAIL] Uninstall failed for $($app.DisplayName): $_" ERROR
        }
    }
}

# Remove leftover install folders under a given root
function Remove-OldInstallFolders {
    param(
        [string]  $Root,
        [string]  $Filter,
        [string[]]$KeepWildcards
    )
    if (-not (Test-Path $Root)) { return }
    $dirs = Get-ChildItem $Root -Directory -Filter $Filter -ErrorAction SilentlyContinue
    foreach ($dir in $dirs) {
        $keep = $false
        foreach ($kp in $KeepWildcards) {
            if ($dir.Name -like $kp) { $keep = $true; break }
        }
        if ($keep) {
            Write-Log "  Keeping folder: $($dir.FullName)" SKIP
        } else {
            Write-Log "  Removing old folder: $($dir.FullName)"
            Remove-Item $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $dir.FullName)) {
                Write-Log "  [OK] Removed: $($dir.FullName)" OK
            } else {
                Write-Log "  [FAIL] Could not fully remove: $($dir.FullName) (files may be in use)" WARN
            }
        }
    }
}

# Set a registry DWORD/String safely (creates path if missing)
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = 'DWord'
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        Write-Log "  [OK] $Path\$Name = $Value" OK
        Add-Result 'Registry Hardening' "$Name" "Set=$Value at $Path"
    } catch {
        Write-Log "  [FAIL] Failed: $Path\$Name -- $_" ERROR
        Add-Result 'Registry Hardening' "$Name" 'FAILED' "$_"
    }
}

# Disable an SCHANNEL cipher by setting Enabled=0 (creates key tree if missing)
function Disable-SchannelCipher {
    param([string]$CipherName)
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$CipherName"
    try {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $path -Name 'Enabled' -Value 0 -Type DWord -Force -ErrorAction Stop
        Write-Log "  [OK] SCHANNEL cipher disabled: $CipherName" OK
        Add-Result 'Registry Hardening' "SCHANNEL Cipher Disabled: $CipherName" 'Enabled=0'
    } catch {
        Write-Log "  [FAIL] Failed to disable cipher $CipherName : $_" ERROR
        Add-Result 'Registry Hardening' "SCHANNEL Cipher: $CipherName" 'FAILED' "$_"
    }
}

# --- Windows Update Helpers Begin ---------------------------------------------
function Resolve-WindowsUpdateExecution {
    param(
        [ValidateSet('Install','ScanOnly','Skip')]
        [string]$WindowsUpdateMode = 'Install',
        [ValidateSet('All','WindowsUpdate')]
        [string]$Section = 'All',
        [bool]$SkipWindowsUpdate = $false
    )

    $messages = @()
    if ($SkipWindowsUpdate -and $WindowsUpdateMode -ne 'Skip') {
        $WindowsUpdateMode = 'Skip'
        $messages += 'SkipWindowsUpdate was supplied; WindowsUpdateMode normalized to Skip.'
    }

    [pscustomobject]@{
        WindowsUpdateMode = $WindowsUpdateMode
        Section           = $Section
        RunAllSections    = ($Section -eq 'All')
        Messages          = $messages
    }
}

function Ensure-PSWindowsUpdate {
    param([switch]$AllowInstall)

    if (Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue) {
        Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
        return $true
    }

    if (-not $AllowInstall) {
        Write-Log 'PSWindowsUpdate not found and install is disabled for this mode.' WARN
        return $false
    }

    Write-Log 'PSWindowsUpdate not found -- installing...'
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 `
                                -Force -Scope AllUsers -ErrorAction Stop | Out-Null
        Install-Module PSWindowsUpdate -Force -Scope AllUsers `
                       -SkipPublisherCheck -ErrorAction Stop | Out-Null
        Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
        Write-Log '[OK] PSWindowsUpdate module installed.' OK
        return $true
    } catch {
        Write-Log "[FAIL] Could not install PSWindowsUpdate: $_" ERROR
        Add-Result 'Windows Update' 'PSWindowsUpdate Module' 'Install FAILED' "$_"
        return $false
    }
}

function Get-WindowsUpdateEventSignal {
    param(
        [string]$Kb,
        [string]$Title,
        [datetime]$Since = (Get-Date).AddHours(-2)
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            ProviderName = 'Microsoft-Windows-WindowsUpdateClient'
            StartTime = $Since
        } -ErrorAction SilentlyContinue
    } catch {
        $events = @()
    }

    $escapedKb = [regex]::Escape($Kb)
    $escapedTitle = [regex]::Escape($Title)
    $events |
        Where-Object {
            ($Kb -and $_.Message -match $escapedKb) -or
            ($Title -and $_.Message -match $escapedTitle)
        } |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 1
}

function Invoke-WindowsUpdateSection {
    param(
        [ValidateSet('Install','ScanOnly','Skip')]
        [string]$Mode = 'Install'
    )

    if ($Mode -eq 'Skip') {
        Write-Log 'Skipped -- WindowsUpdateMode is Skip.' SKIP
        Add-Result 'Windows Update' 'All KB Patches' 'Skipped by Parameter'
        return [pscustomobject]@{
            Outcome         = 'SkippedByParameter'
            ModuleAvailable = $false
            PendingCount    = 0
            InstalledCount  = 0
            FailedCount     = 0
        }
    }

    $allowInstall = ($Mode -eq 'Install')
    if (-not (Ensure-PSWindowsUpdate -AllowInstall:$allowInstall)) {
        $outcome = if ($Mode -eq 'ScanOnly') { 'ScanOnlyUnavailable' } else { 'InstallUnavailable' }
        Add-Result 'Windows Update' 'PSWindowsUpdate Module' $outcome
        return [pscustomobject]@{
            Outcome         = $outcome
            ModuleAvailable = $false
            PendingCount    = 0
            InstalledCount  = 0
            FailedCount     = 0
        }
    }

    Write-Log 'Scanning for pending Windows Updates...'
    $pendingUpdates = @()
    $scanSuccess = $false
    for ($attempt = 1; $attempt -le 3 -and -not $scanSuccess; $attempt++) {
        try {
            $pendingUpdates = @(Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Verbose:$false -ErrorAction Stop)
            $scanSuccess = $true
        } catch {
            Write-Log ("  WU scan attempt {0}/3 failed: {1}" -f $attempt, $_) WARN
            if ($attempt -lt 3) {
                Start-Sleep -Seconds 15
                & wuauclt.exe /detectnow 2>$null
                Start-Sleep -Seconds 5
            }
        }
    }

    if (-not $scanSuccess) {
        Write-Log '[FAIL] Windows Update scan failed after 3 attempts.' ERROR
        Add-Result 'Windows Update' 'Monthly Security Updates' 'Scan FAILED -- Manual Run Required'
        return [pscustomobject]@{
            Outcome         = 'ScanFailed'
            ModuleAvailable = $true
            PendingCount    = 0
            InstalledCount  = 0
            FailedCount     = 0
        }
    }

    $totalUpdates = ($pendingUpdates | Measure-Object).Count
    if ($totalUpdates -eq 0) {
        Write-Log '[OK] Windows Update: no pending updates found.' SKIP
        Add-Result 'Windows Update' 'Monthly Security Updates' 'Already Current'
        return [pscustomobject]@{
            Outcome         = 'NoPendingUpdates'
            ModuleAvailable = $true
            PendingCount    = 0
            InstalledCount  = 0
            FailedCount     = 0
        }
    }

    Write-Log "Found $totalUpdates pending update(s):" INFO
    $idx = 0
    foreach ($u in $pendingUpdates) {
        $idx++
        $kb = if ($u.KBArticleIDs) { "KB$($u.KBArticleIDs -join ', KB')" } else { 'No KB' }
        $size = if ($u.MaxDownloadSize) { '{0:N1} MB' -f ($u.MaxDownloadSize / 1MB) } else { '? MB' }
        Write-Log ("  [{0,2}/{1}] {2}  ({3})  {4}" -f $idx, $totalUpdates, $kb, $size, $u.Title) INFO
    }

    if ($Mode -eq 'ScanOnly') {
        Add-Result 'Windows Update' 'Monthly Security Updates' "ScanOnly -- $totalUpdates pending"
        return [pscustomobject]@{
            Outcome         = 'ScanOnlyPending'
            ModuleAvailable = $true
            PendingCount    = $totalUpdates
            InstalledCount  = 0
            FailedCount     = 0
        }
    }

    Write-Log 'Installing updates one by one -- each KB will be reported as it completes...' INFO
    $installed = 0
    $failed = 0
    $updateIdx = 0

    foreach ($u in $pendingUpdates) {
        $updateIdx++
        $kb = if ($u.KBArticleIDs) { "KB$($u.KBArticleIDs -join ', KB')" } else { 'No KB' }
        $title = $u.Title
        $pct = [int](($updateIdx - 1) / $totalUpdates * 100)
        Write-Progress -Activity 'Windows Update' -Status "[$updateIdx/$totalUpdates] Installing $kb" -CurrentOperation $title -PercentComplete $pct

        try {
            $installStarted = Get-Date
            $result = Install-WindowsUpdate -MicrosoftUpdate `
                                            -KBArticleID $u.KBArticleIDs `
                                            -AcceptAll -IgnoreReboot `
                                            -Verbose:$false -ErrorAction Stop
            $resultStatus = if ($result -and $result.Result) { $result.Result } else { 'Installed' }
            Write-Log ("  [OK] [{0}/{1}] Done: {2} -- {3} (Status={4})" -f $updateIdx, $totalUpdates, $kb, $title, $resultStatus) OK
            Add-Result 'Windows Update' $kb "Installed -- $title"
            $installed++
            $script:RebootRequired = $true
        } catch {
            $signal = Get-WindowsUpdateEventSignal -Kb $kb -Title $title -Since $installStarted.AddMinutes(-1)
            $detail = if ($signal) { "$_ | Event $($signal.Id): $($signal.Message)" } else { "$_" }
            Write-Log ("  [FAIL] [{0}/{1}] FAILED: {2} -- {3} | Error: {4}" -f $updateIdx, $totalUpdates, $kb, $title, $detail) ERROR
            Add-Result 'Windows Update' $kb "FAILED -- $title" $detail
            $failed++
        }
    }

    Write-Progress -Activity 'Windows Update' -Completed
    $outcome = if ($failed -gt 0) { 'CompletedWithFailures' } else { 'Completed' }
    Write-Log ("Windows Update complete -- {0} installed, {1} failed (of {2} total)." -f $installed, $failed, $totalUpdates) $(if ($failed -gt 0) { 'WARN' } else { 'OK' })
    Add-Result 'Windows Update' 'Monthly Security Updates' "Done: $installed installed, $failed failed"

    [pscustomobject]@{
        Outcome         = $outcome
        ModuleAvailable = $true
        PendingCount    = $totalUpdates
        InstalledCount  = $installed
        FailedCount     = $failed
    }
}
# --- Windows Update Helpers End -----------------------------------------------

# --- Banner -------------------------------------------------------------------
try {
    $currentProc = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -ErrorAction Stop
    $parentProc  = if ($currentProc.ParentProcessId) {
        Get-Process -Id $currentProc.ParentProcessId -ErrorAction SilentlyContinue
    }
    $parentLabel = if ($parentProc) {
        "$($parentProc.ProcessName) (PID $($parentProc.Id))"
    } elseif ($currentProc.ParentProcessId) {
        "PID $($currentProc.ParentProcessId)"
    } else {
        'Unknown'
    }
} catch {
    $parentLabel = 'Unavailable'
}

$launchMode = if ($env:MEDPRO_BACKGROUND_LAUNCH -eq '1') {
    'Background hidden'
} else {
    'Direct launch'
}

Write-Log ('=' * 72) SECTION
Write-Log '  MedPro Healthcare Staffing | Nucleus Vulnerability Remediation'  SECTION
Write-Log "  Source   : VulnerabilityScanner-20260504.xlsx (170 populated findings)" SECTION
Write-Log "  Host     : $env:COMPUTERNAME  |  User: $env:USERNAME"            SECTION
Write-Log "  Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"            SECTION
Write-Log "  Launch   : $launchMode  |  PID: $PID  |  Host: $($Host.Name)"   SECTION
Write-Log "  Parent   : $parentLabel"                                          SECTION
if ($env:MEDPRO_LAUNCHER_PATH) {
    Write-Log "  Launcher : $env:MEDPRO_LAUNCHER_PATH" SECTION
}
if ($env:MEDPRO_LAUNCH_REQUESTED_AT) {
    Write-Log "  Queued   : $env:MEDPRO_LAUNCH_REQUESTED_AT" SECTION
}
Write-Log ('=' * 72) SECTION

$execution = Resolve-WindowsUpdateExecution `
    -WindowsUpdateMode $WindowsUpdateMode `
    -Section $Section `
    -SkipWindowsUpdate ([bool]$SkipWindowsUpdate)

foreach ($msg in $execution.Messages) {
    Write-Log $msg WARN
}

if (-not $execution.RunAllSections) {
    Write-Log '' INFO
    Write-Log '--- SECTION 1: Windows Security Updates ------------------------------' SECTION
    $wuOnlyResult = Invoke-WindowsUpdateSection -Mode $execution.WindowsUpdateMode

    try {
        $script:Results | ForEach-Object { [pscustomobject]$_ } |
            Export-Csv -Path $ReportCsv -NoTypeInformation -Append -ErrorAction Stop
        Write-Log "Report CSV   : $ReportCsv"
    } catch {
        Write-Log "Could not write report CSV: $_" WARN
    }

    Write-Log "Windows Update outcome: $($wuOnlyResult.Outcome)"
    Write-Log "Log file     : $LogFile"
    Stop-Transcript | Out-Null

    if ($script:RebootRequired) {
        Write-Host ''
        Write-Host '[WARN] A reboot is required to complete remediation. Please restart this machine manually.' -ForegroundColor Yellow
    } else {
        Write-Host ''
        Write-Host '[DONE] Windows Update section complete. No reboot required.' -ForegroundColor Green
    }
    return
}

$wingetOK = Install-WingetIfMissing

if ($wingetOK) {
    Write-Log 'Resetting winget source index (prevents 0x8A15000F failures)...'
    & winget source reset --force 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    $addOut    = & winget source add --name winget `
                                     --arg 'https://winget.azureedge.net/cache' `
                                     --type 'Microsoft.PreIndexed.Package' 2>&1 | Out-String
    $updateOut = & winget source update --name winget 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
        Write-Log '  [OK] winget source reset and updated successfully.' OK
    } else {
        Write-Log '  winget source update returned non-zero after reset -- upgrades may still fail.' WARN
        Write-Log "  Detail: $($updateOut.Trim())" WARN
    }
} else {
    Write-Log 'winget unavailable -- all winget-based remediations will be skipped this run.' WARN
}

# ==============================================================================
#  SECTION 1 -- Windows Monthly Security Updates
#  Covers: Windows Security Updates Dec 2025 through Apr 2026;
#          Windows Server Security Update Apr 2026; .NET Framework Apr 2026;
#          WSL GUI Nov 2025; WSL2 Kernel Aug 2025; VBS Enclave EoP Oct 2025;
#          Notepad RCE Feb 2026 (CVE-2026-20841);
#          Windows Security App Spoofing Jun 2025 (CVE-2025-47956);
#          RRAS RCE Jan 2026 (CVE-2026-21221);
#          Apr 2026: CVE-2026-27907, CVE-2026-26165, CVE-2026-32077,
#                    CVE-2026-32219, CVE-2026-32157 (121+ CVEs)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 1: Windows Security Updates ------------------------------' SECTION
$wuResult = Invoke-WindowsUpdateSection -Mode $execution.WindowsUpdateMode
Write-Log "Windows Update outcome: $($wuResult.Outcome)"

# ==============================================================================
#  SECTION 2 -- Microsoft .NET / ASP.NET Core
#  Covers: .NET / ASP.NET Core Feb, Mar, Apr 2026 update cycles; and
#          ASP.NET Core Apr 2026 Out-of-Band (CVE-2026-40372, CVSS 9.1).
#  Note: Windows Update (Section 1) handles .NET Framework patches delivered
#        via WU. This section handles SDK/runtime installs via winget.
#  EOL uninstall: .NET 5 (EOL, CVSS 9.8, Count=25), .NET 6 (EOL, CVSS 9.8,
#                 Count=43), .NET 7 (EOL, CVSS 9.8, Count=18) -- all removed.
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 2: Microsoft .NET / ASP.NET Core -------------------------' SECTION

if ($wingetOK) {
    $dotnetRuntimes = Get-InstalledApps | Where-Object {
        ($_.DisplayName -like 'Microsoft .NET*Runtime*' -or
         $_.DisplayName -like 'Microsoft ASP.NET*') -and
        $_.DisplayName -notlike '*Security Update*' -and
        $_.DisplayName -notlike '*Update for*' -and
        $_.DisplayName -notlike '*(KB*'
    }

    $dotnetMajors = $dotnetRuntimes | ForEach-Object {
        if ($_.DisplayVersion -match '^(\d+)\.') {
            $v = [int]$Matches[1]
            if ($v -ge 5 -and $v -le 20) { "$v" }
        }
    } | Select-Object -Unique | Sort-Object

    if ($dotnetMajors) {
        Write-Log "Detected .NET major versions on this machine: $($dotnetMajors -join ', ')"

        $dotnetPkgs = @(
            [pscustomobject]@{ Id='Microsoft.DotNet.Runtime.8';     Major='8'; Name='.NET 8 Runtime' },
            [pscustomobject]@{ Id='Microsoft.DotNet.Runtime.9';     Major='9'; Name='.NET 9 Runtime' },
            [pscustomobject]@{ Id='Microsoft.DotNet.AspNetCore.8';  Major='8'; Name='ASP.NET Core 8' },
            [pscustomobject]@{ Id='Microsoft.DotNet.AspNetCore.9';  Major='9'; Name='ASP.NET Core 9' }
        )
        foreach ($pkg in $dotnetPkgs) {
            if ($dotnetMajors -contains $pkg.Major) {
                Invoke-WingetUpgrade -PackageId $pkg.Id -DisplayName $pkg.Name -Category '.NET'
            }
        }

        # -- Force-uninstall EOL .NET versions (5, 6, 7) -------------------------
        # .NET 5 EOL (CVSS 9.8, Count=25), .NET 6 EOL (CVSS 9.8, Count=43),
        # .NET 7 EOL (CVSS 9.8, Count=18) -- no further security updates available.
        Write-Log '  Uninstalling EOL .NET runtimes (5, 6, 7) -- no security updates available...'
        $eolDotnetPkgs = @(
            [pscustomobject]@{ WingetId='Microsoft.DotNet.Runtime.5';    AspId='Microsoft.DotNet.AspNetCore.5'; Major='5'; Name='.NET 5' },
            [pscustomobject]@{ WingetId='Microsoft.DotNet.Runtime.6';    AspId='Microsoft.DotNet.AspNetCore.6'; Major='6'; Name='.NET 6' },
            [pscustomobject]@{ WingetId='Microsoft.DotNet.Runtime.7';    AspId='Microsoft.DotNet.AspNetCore.7'; Major='7'; Name='.NET 7' }
        )
        foreach ($eolPkg in $eolDotnetPkgs) {
            $eolInstalled = Get-InstalledApps | Where-Object {
                ($_.DisplayName -like "Microsoft .NET*Runtime*" -or $_.DisplayName -like 'Microsoft ASP.NET*') -and
                $_.DisplayVersion -like "$($eolPkg.Major).*"
            }
            if ($eolInstalled) {
                Write-Log "  EOL $($eolPkg.Name) detected -- uninstalling..." WARN
                foreach ($app in $eolInstalled) {
                    Uninstall-AppByDisplayName -DisplayNamePattern $app.DisplayName
                }
                if ($wingetOK) {
                    & winget uninstall --id $eolPkg.WingetId --silent --accept-source-agreements 2>&1 | Out-Null
                    & winget uninstall --id $eolPkg.AspId    --silent --accept-source-agreements 2>&1 | Out-Null
                }
                Add-Result '.NET' "EOL $($eolPkg.Name) Uninstall" 'Removal Invoked'
            } else {
                Write-Log "  EOL $($eolPkg.Name) not detected on this machine." SKIP
            }
        }
    } else {
        Write-Log '.NET runtimes not detected via registry -- relying on Windows Update (Section 1).' SKIP
        Add-Result '.NET' '.NET Runtime Upgrade' 'Handled by Windows Update'
    }
} else {
    Add-Manual '.NET/ASP.NET Core -- update manually: https://dotnet.microsoft.com/en-us/download/dotnet'
    Add-Manual 'EOL .NET 5/6/7 -- uninstall manually via Settings > Apps. .NET 5 (CVE series CVSS 9.8), .NET 6 (CVSS 9.8), .NET 7 (CVSS 9.8) receive no further security patches.'
}

# ==============================================================================
#  SECTION 3 -- Browser: Microsoft Edge
#  Covers: Edge <147.0.3912.86 (CVE-2026-6919, CVE-2026-6921 + prior series);
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 3: Browser (Microsoft Edge) ------------------------------' SECTION

if ($wingetOK) {
    Invoke-WingetUpgrade -PackageId 'Microsoft.Edge' -DisplayName 'Microsoft Edge' -Category 'Browser'
} else {
    Add-Manual 'Microsoft Edge -- update manually to 147.0.3912.86+ (CVE-2026-6919, CVE-2026-6921 series)'
}

# ==============================================================================
#  SECTION 3a -- Browser: Google Chrome
#  Covers: Chrome <147.0.7727.137 (CVE-2026-7333 through CVE-2026-7363,
#          CVSS 9.6, Count=8)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 3a: Browser (Google Chrome) ------------------------------' SECTION

$chromeInstalled = Get-InstalledApps | Where-Object {
    $_.DisplayName -like 'Google Chrome*'
}
if ($chromeInstalled) {
    Write-Log "Found Google Chrome: $($chromeInstalled.DisplayVersion)"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'Google.Chrome' -DisplayName 'Google Chrome' -Category 'Browser'
    } else {
        Add-Manual 'Google Chrome -- update manually to 147.0.7727.137+ (CVE-2026-7333 through CVE-2026-7363 series, CVSS 9.6)'
    }
} else {
    Write-Log 'Google Chrome not installed on this machine.' SKIP
    Add-Result 'Browser' 'Google Chrome' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 4 -- Oracle Java JRE/JDK
#  Covers: Oracle Java CPU cycles through CPUAPR2026.
#  Action: Upgrade each installed major version, uninstall old entries, remove
#          leftover Program Files\Java folders.
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 4: Oracle Java JRE/JDK ----------------------------------' SECTION

$oracleJava = Get-InstalledApps | Where-Object {
    $_.DisplayName -like 'Java *'          -or
    $_.DisplayName -like 'Java(TM)*'       -or
    $_.DisplayName -like 'Oracle Java *'   -or
    $_.DisplayName -like 'Java SE *'       -or
    ($_.DisplayName -like 'Java*' -and $_.Publisher -like '*Oracle*')
}

if ($oracleJava) {
    $oracleNames = ($oracleJava | Select-Object -ExpandProperty DisplayName | Sort-Object -Unique) -join '; '
    Write-Log "Found Oracle Java: $oracleNames"

    if ($wingetOK) {
        $oraclePkgs = @(
            [pscustomobject]@{ Id='Oracle.JavaRuntimeEnvironment'; Name='Oracle JRE 8';  MajorHint='8'  },
            [pscustomobject]@{ Id='Oracle.JDK.11';                 Name='Oracle JDK 11'; MajorHint='11' },
            [pscustomobject]@{ Id='Oracle.JDK.17';                 Name='Oracle JDK 17'; MajorHint='17' },
            [pscustomobject]@{ Id='Oracle.JDK.21';                 Name='Oracle JDK 21'; MajorHint='21' }
        )
        foreach ($pkg in $oraclePkgs) {
            $hasMajor = $oracleJava | Where-Object {
                $_.DisplayVersion -like "$($pkg.MajorHint).*" -or
                $_.DisplayName    -like "*$($pkg.MajorHint)*"
            }
            if ($hasMajor) {
                Invoke-WingetUpgrade -PackageId $pkg.Id -DisplayName $pkg.Name -Category 'Java'
            }
        }

        # Remove old Oracle Java versions -- keep the latest patch per major
        Write-Log 'Cleaning up old Oracle Java versions...'
        $allOracle = Get-InstalledApps | Where-Object {
            $_.DisplayName -like 'Java *' -or $_.DisplayName -like 'Java(TM)*' -or
            $_.DisplayName -like 'Java SE *' -or $_.DisplayName -like 'Oracle Java *'
        }
        $byMajor = $allOracle | Group-Object {
            if ($_.DisplayVersion -match '^(\d+)') { $Matches[1] }
            elseif ($_.DisplayName -match '(\d+)') { $Matches[1] }
            else { '0' }
        }
        foreach ($grp in $byMajor) {
            $sorted = $grp.Group | Sort-Object {
                try { [version]($_.DisplayVersion -replace '[^0-9\.]','') }
                catch { [version]'0.0' }
            } -Descending
            foreach ($old in ($sorted | Select-Object -Skip 1)) {
                Write-Log "  Removing old Oracle Java: $($old.DisplayName) $($old.DisplayVersion)"
                Uninstall-AppByDisplayName -DisplayNamePattern $old.DisplayName
            }
        }

        # Remove leftover Java directories in Program Files
        foreach ($root in @($env:ProgramFiles, "${env:ProgramFiles(x86)}")) {
            $javaRoot = Join-Path $root 'Java'
            if (Test-Path $javaRoot) {
                $allDirs = Get-ChildItem $javaRoot -Directory -ErrorAction SilentlyContinue
                foreach ($dir in $allDirs) {
                    $inUse = Get-InstalledApps | Where-Object {
                        $_.InstallLocation -and $dir.FullName.StartsWith($_.InstallLocation, 'OrdinalIgnoreCase')
                    }
                    if (-not $inUse) {
                        Write-Log "  Removing leftover Java folder: $($dir.FullName)"
                        Remove-Item $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
                        if (-not (Test-Path $dir.FullName)) { Write-Log '  [OK] Removed' OK }
                    }
                }
            }
        }
        Add-Result 'Java' 'Oracle Java -- upgrade + cleanup' 'Completed'
    } else {
        Add-Manual 'Oracle Java -- update manually to the latest CPUAPR2026 or newer JRE/JDK build for each installed major version.'
    }
} else {
    Write-Log 'Oracle Java not installed on this machine.' SKIP
    Add-Result 'Java' 'Oracle Java' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 5 -- 7-Zip
#  Covers: CVE-2024-11477 (RCE), CVE-2025-0411 (MotW bypass),
#          CVE-2023-52168/52169 (heap buffer overflow),
#          CVE-2023-40481/31102 (RCE), CVE-2024-11612 (DoS),
#          CVE-2025-53816/53817 (NEW), CVE-2025-11001/11002 (NEW),
#          CVE-2025-55188 (Arbitrary File Write -- NEW)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 5: 7-Zip -------------------------------------------------' SECTION

$szInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like '7-Zip*' }
if ($szInstalled) {
    Write-Log "Found 7-Zip: $($szInstalled.DisplayName -join ', ')"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId '7zip.7zip' -DisplayName '7-Zip' -Category 'App Update'

        Write-Log 'Checking for old 7-Zip versions to remove...'
        $all7z = Get-InstalledApps | Where-Object { $_.DisplayName -like '7-Zip*' }
        if (($all7z | Measure-Object).Count -gt 1) {
            $keepVer = ($all7z | Sort-Object DisplayVersion -Descending |
                        Select-Object -First 1).DisplayVersion
            Uninstall-AppByDisplayName -DisplayNamePattern '7-Zip*' -KeepVersionPrefix $keepVer
        }

        foreach ($root in @($env:ProgramFiles, "${env:ProgramFiles(x86)}")) {
            $szDirs = Get-ChildItem $root -Directory -Filter '7-Zip*' -ErrorAction SilentlyContinue |
                      Sort-Object Name -Descending
            if ($szDirs.Count -gt 1) {
                foreach ($old in ($szDirs | Select-Object -Skip 1)) {
                    Write-Log "  Removing old 7-Zip folder: $($old.FullName)"
                    Remove-Item $old.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } else {
        Add-Manual '7-Zip -- update manually to latest from 7-zip.org (CVE-2025-55188, CVE-2025-53816/53817, CVE-2025-11001/11002)'
    }
} else {
    Write-Log '7-Zip not installed on this machine.' SKIP
    Add-Result 'App Update' '7-Zip' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 6 -- Beyond Compare
#  Covers: CVE-2022-36414 (Privilege Breakout)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 6: Beyond Compare ----------------------------------------' SECTION

$bcInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like 'Beyond Compare*' }
if ($bcInstalled) {
    Write-Log "Found Beyond Compare: $($bcInstalled.DisplayName -join ', ')"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'ScooterSoftware.BeyondCompare5' `
                             -DisplayName 'Beyond Compare 5' -Category 'App Update'
        Invoke-WingetUpgrade -PackageId 'ScooterSoftware.BeyondCompare4' `
                             -DisplayName 'Beyond Compare 4' -Category 'App Update'

        foreach ($root in @($env:ProgramFiles, "${env:ProgramFiles(x86)}")) {
            $bcDirs = Get-ChildItem $root -Directory -Filter 'Beyond Compare*' -ErrorAction SilentlyContinue |
                      Sort-Object Name -Descending
            if ($bcDirs.Count -gt 1) {
                foreach ($old in ($bcDirs | Select-Object -Skip 1)) {
                    Write-Log "  Removing old Beyond Compare folder: $($old.FullName)"
                    Remove-Item $old.FullName -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } else {
        Add-Manual 'Beyond Compare -- update manually from scootersoftware.com (CVE-2022-36414)'
    }
} else {
    Write-Log 'Beyond Compare not installed on this machine.' SKIP
    Add-Result 'App Update' 'Beyond Compare' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 7 -- NVIDIA GeForce Experience
#  Covers: CVE-2021-1073 (Privilege Escalation), CVE-2020-5964 (Privilege Escalation)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 7: NVIDIA GeForce Experience -----------------------------' SECTION

$nvInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like '*GeForce Experience*' }
if ($nvInstalled) {
    Write-Log "Found NVIDIA GeForce Experience: $($nvInstalled.DisplayVersion)"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'Nvidia.GeForceExperience' `
                             -DisplayName 'NVIDIA GeForce Experience' -Category 'App Update'
    } else {
        Add-Manual 'NVIDIA GeForce Experience -- update manually to 3.23+ from nvidia.com/geforce-experience (CVE-2021-1073, CVE-2020-5964)'
    }
} else {
    Write-Log 'NVIDIA GeForce Experience not installed on this machine.' SKIP
    Add-Result 'App Update' 'NVIDIA GeForce Experience' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 8 -- Zoom VDI Client
#  Covers: ZSB-25047 (Sensitive Info Removal -- CVE-2025-62483),
#          ZSB-25044 (Cert Validation -- CVE-2025-30669),
#          ZSB-25041 (External Control File Path -- CVE-2025-64739),
#          ZSB-26005 (External Control File Path),
#          ZSB-26004 (Improper Privilege Management)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 8: Zoom VDI Client ---------------------------------------' SECTION

$zoomInstalled = Get-InstalledApps | Where-Object {
    $_.DisplayName -like 'Zoom*' -or $_.DisplayName -like 'Zoom VDI*'
}
if ($zoomInstalled) {
    Write-Log "Found Zoom: $($zoomInstalled.DisplayName -join ', ')"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'Zoom.Zoom' `
                             -DisplayName 'Zoom' -Category 'App Update'
        Invoke-WingetUpgrade -PackageId 'Zoom.ZoomInstallerFull' `
                             -DisplayName 'Zoom (Full Installer)' -Category 'App Update'
    } else {
        Add-Manual 'Zoom VDI -- update manually from zoom.us/vdi (ZSB-25047, ZSB-25044, ZSB-25041, ZSB-26005, ZSB-26004)'
    }
} else {
    Write-Log 'Zoom not installed on this machine.' SKIP
    Add-Result 'App Update' 'Zoom VDI Client' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 9 -- TechSmith Snagit
#  Covers: CVE-2019-13382 (Local Privilege Escalation);
#          CVE-2020-11541 (XML External Entity XXE Injection)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 9: TechSmith Snagit --------------------------------------' SECTION

$snagitInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like '*Snagit*' }
if ($snagitInstalled) {
    Write-Log "Found Snagit: $($snagitInstalled.DisplayName) $($snagitInstalled.DisplayVersion)"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'TechSmith.Snagit' `
                             -DisplayName 'TechSmith Snagit' -Category 'App Update'
    } else {
        Add-Manual 'TechSmith Snagit -- update manually from techsmith.com (CVE-2019-13382 LPE, CVE-2020-11541 XXE)'
    }
} else {
    Write-Log 'TechSmith Snagit not installed on this machine.' SKIP
    Add-Result 'App Update' 'TechSmith Snagit' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 10 -- Visual Studio Code
#  Covers: CVE-2025-62453 (Nov 2025 security update, CVSS 5.0);
#          CVE-2025-64660 (Nov 2025 security update, CVSS 8.0);
#          CVE-2026-21518, CVE-2026-21523 (Feb 2026 security update, CVSS 8.8);
#          CVE-2025-65717 (Live Server extension Data Exfiltration)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 10: Visual Studio Code -----------------------------------' SECTION

$vscInstalled = Get-InstalledApps | Where-Object {
    $_.DisplayName -like 'Microsoft Visual Studio Code*' -or
    $_.DisplayName -eq 'Visual Studio Code'
}
if ($vscInstalled) {
    Write-Log "Found VS Code: $($vscInstalled.DisplayVersion)"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'Microsoft.VisualStudioCode' `
                             -DisplayName 'Visual Studio Code' -Category 'App Update'
    } else {
        Add-Manual 'Visual Studio Code -- update manually from code.visualstudio.com (CVE-2025-62453, CVE-2025-64660, CVE-2026-21518, CVE-2026-21523)'
    }
    Add-Manual 'VS Code Live Server extension (CVE-2025-65717) -- open VS Code > Extensions, search "Live Server" and update or uninstall it.'
} else {
    Write-Log 'Visual Studio Code not installed on this machine.' SKIP
    Add-Result 'App Update' 'Visual Studio Code' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 10a -- May 4, 2026 Application Findings
#  Covers: Teams, Ghostscript, Node.js, FileZilla, KeePass, PyCharm, PostgreSQL,
#          Git, Microsoft 3D Viewer, and VS Code Copilot Chat.
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 10a: May 4 Application Findings --------------------------' SECTION

# Microsoft Teams: modern Teams should be current; classic Teams is removed when detected.
$teamsInstalled = Get-InstalledApps | Where-Object {
    $_.DisplayName -like 'Microsoft Teams*' -or
    $_.DisplayName -like 'Teams Machine-Wide Installer*'
}
if ($teamsInstalled) {
    Write-Log "Found Microsoft Teams component(s): $($teamsInstalled.DisplayName -join ', ')"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'Microsoft.Teams' -DisplayName 'Microsoft Teams' -Category 'App Update'
        $teamsClassic = $teamsInstalled | Where-Object {
            $_.DisplayName -like '*classic*' -or $_.DisplayName -like '*Machine-Wide Installer*'
        }
        if ($teamsClassic) {
            Write-Log '  Removing Microsoft Teams classic / machine-wide installer components...'
            & winget uninstall --id 'Microsoft.Teams.Classic' --silent --accept-source-agreements 2>&1 | Out-String | Out-Null
            Uninstall-AppByDisplayName -DisplayNamePattern 'Microsoft Teams classic*'
            Uninstall-AppByDisplayName -DisplayNamePattern 'Teams Machine-Wide Installer*'
            Add-Result 'App Update' 'Microsoft Teams Classic' 'Removal Invoked'
        }
    } else {
        Add-Manual 'Microsoft Teams -- update modern Teams to the latest release and remove Teams classic / Machine-Wide Installer if present.'
    }
} else {
    Write-Log 'Microsoft Teams not installed on this machine.' SKIP
    Add-Result 'App Update' 'Microsoft Teams' 'Not Present / Skipped'
}

$ghostscriptInstalled = Get-InstalledApps | Where-Object {
    $_.DisplayName -like '*Ghostscript*' -or $_.DisplayName -like '*Artifex*'
}
if ($ghostscriptInstalled) {
    Write-Log "Found Ghostscript: $($ghostscriptInstalled.DisplayName -join ', ')"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'ArtifexSoftware.GhostScript' `
                             -DisplayName 'Ghostscript' -Category 'App Update'
    } else {
        Add-Manual 'Ghostscript / Artifex Ghostscript -- update to the latest release or remove if no business need. Current scan: CVE-2023-36664, CVE-2024-33869, CVE-2024-29510 series.'
    }
    Add-Manual 'Ghostscript -- verify version post-upgrade; remove if no business need exists (CVE-2023-36664, CVE-2024-33869/33870/33871, CVE-2024-29510).'
    Add-Result 'App Update' 'Ghostscript' 'Upgrade Attempted'
} else {
    Write-Log 'Ghostscript not installed on this machine.' SKIP
    Add-Result 'App Update' 'Ghostscript' 'Not Present / Skipped'
}

$nodeInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like 'Node.js*' }
if ($nodeInstalled) {
    Write-Log "Found Node.js: $($nodeInstalled.DisplayName -join ', ')"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'OpenJS.NodeJS' -DisplayName 'Node.js Current' -Category 'App Update'
        Invoke-WingetUpgrade -PackageId 'OpenJS.NodeJS.LTS' -DisplayName 'Node.js LTS' -Category 'App Update'
    } else {
        Add-Manual 'Node.js -- update all installed Current/LTS releases from nodejs.org to address current scan Node.js and OpenSSL findings.'
    }
} else {
    Write-Log 'Node.js not installed on this machine.' SKIP
    Add-Result 'App Update' 'Node.js' 'Not Present / Skipped'
}

$fileZillaInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like 'FileZilla Client*' }
if ($fileZillaInstalled) {
    Write-Log "Found FileZilla Client: $($fileZillaInstalled.DisplayVersion -join ', ')"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'TimKosse.FileZilla.Client' `
                             -DisplayName 'FileZilla Client' -Category 'App Update'
    } else {
        Add-Manual 'FileZilla Client -- update to latest from filezilla-project.org or remove if not required (CVE-2024-31497, CVE-2023-53959).'
    }
} else {
    Write-Log 'FileZilla Client not installed on this machine.' SKIP
    Add-Result 'App Update' 'FileZilla Client' 'Not Present / Skipped'
}

$keepassInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like 'KeePass*' }
if ($keepassInstalled) {
    Write-Log "Found KeePass: $($keepassInstalled.DisplayName -join ', ')"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'DominikReichl.KeePass' -DisplayName 'KeePass' -Category 'App Update'
    } else {
        Add-Manual 'KeePass 2.x -- update to the latest KeePass 2.x release or remove if not required (CVE-2023-32784).'
    }
} else {
    Write-Log 'KeePass not installed on this machine.' SKIP
    Add-Result 'App Update' 'KeePass' 'Not Present / Skipped'
}

$pyCharmInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like '*PyCharm*' }
if ($pyCharmInstalled) {
    Write-Log "Found JetBrains PyCharm: $($pyCharmInstalled.DisplayName -join ', ')"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'JetBrains.PyCharm' -DisplayName 'PyCharm Toolbox package' -Category 'App Update'
        Invoke-WingetUpgrade -PackageId 'JetBrains.PyCharm.Community' -DisplayName 'PyCharm Community' -Category 'App Update'
        Invoke-WingetUpgrade -PackageId 'JetBrains.PyCharm.Professional' -DisplayName 'PyCharm Professional' -Category 'App Update'
    } else {
        Add-Manual 'JetBrains PyCharm -- update through JetBrains Toolbox or the PyCharm installer to address PY-85539.'
    }
} else {
    Write-Log 'JetBrains PyCharm not installed on this machine.' SKIP
    Add-Result 'App Update' 'JetBrains PyCharm' 'Not Present / Skipped'
}

$postgresInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like 'PostgreSQL*' }
if ($postgresInstalled) {
    Write-Log "Found PostgreSQL: $($postgresInstalled.DisplayName -join ', ')"
    if ($wingetOK) {
        foreach ($major in 9..18) {
            if ($postgresInstalled | Where-Object { $_.DisplayName -match "PostgreSQL\s+$major\b" }) {
                Invoke-WingetUpgrade -PackageId "PostgreSQL.PostgreSQL.$major" -DisplayName "PostgreSQL $major" -Category 'App Update'
            }
        }
    }
    Add-Manual 'PostgreSQL -- verify database backup, extension compatibility, and server version after package update. Scan references PostgreSQL 18.2, 17.8, 16.12, 15.16, and 14.21 or newer.'
} else {
    Write-Log 'PostgreSQL not installed on this machine.' SKIP
    Add-Result 'App Update' 'PostgreSQL' 'Not Present / Skipped'
}


$gitInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like 'Git*' -and $_.Publisher -like '*Git*' }
if ($gitInstalled) {
    Write-Log "Found Git: $($gitInstalled.DisplayVersion -join ', ')"
    if ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'Git.Git' -DisplayName 'Git' -Category 'App Update'
    } else {
        Add-Manual 'Git -- update to the latest Git for Windows release (GHSA-hv9c-4jm9-jh3x).'
    }
} else {
    Write-Log 'Git not installed on this machine.' SKIP
    Add-Result 'App Update' 'Git' 'Not Present / Skipped'
}

try {
    $viewerPackages = Get-AppxPackage -AllUsers -Name 'Microsoft.Microsoft3DViewer' -ErrorAction SilentlyContinue
    if ($viewerPackages) {
        Write-Log 'Found Microsoft 3D Viewer AppX package -- removing vulnerable legacy app.'
        foreach ($pkg in $viewerPackages) {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                Add-Result 'App Update' 'Microsoft 3D Viewer' 'Removed AppX Package'
            } catch {
                Write-Log "  Microsoft 3D Viewer removal failed for $($pkg.PackageFullName): $_" WARN
                Add-Manual 'Microsoft 3D Viewer -- remove the app from affected users or update via Microsoft Store.'
            }
        }
    } else {
        Write-Log 'Microsoft 3D Viewer AppX package not installed.' SKIP
        Add-Result 'App Update' 'Microsoft 3D Viewer' 'Not Present / Skipped'
    }

    $viewerProvisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                         Where-Object { $_.DisplayName -eq 'Microsoft.Microsoft3DViewer' }
    foreach ($prov in $viewerProvisioned) {
        Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue | Out-Null
        Add-Result 'App Update' 'Microsoft 3D Viewer Provisioned Package' 'Removal Invoked'
    }
} catch {
    Write-Log "Microsoft 3D Viewer detection/removal error: $_" WARN
}

if ($vscInstalled) {
    Add-Manual 'Visual Studio Copilot Chat extension (CVE-2026-23653) -- update or remove the extension from VS Code for all affected user profiles.'
}

# ==============================================================================
#  SECTION 10b -- Microsoft Office (April 2026 Security Update)
#  Covers: CVE-2026-32188 through CVE-2026-33115/33822 series
#          (CVE-2026-32189, CVE-2026-32190, CVE-2026-32197, CVE-2026-32198,
#           CVE-2026-32199, CVE-2026-32200, CVE-2026-33095, CVE-2026-33114,
#           CVE-2026-33115, CVE-2026-23657, CVE-2026-33822)
#  Strategy: Office Click-to-Run / Microsoft 365 Apps auto-update preferred.
#            MSI installs use winget upgrade.
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 10b: Microsoft Office (Apr 2026 Security Update) ---------' SECTION

$officeInstalled = Get-InstalledApps | Where-Object {
    $_.DisplayName -like 'Microsoft Office*'      -or
    $_.DisplayName -like 'Microsoft 365*'          -or
    $_.DisplayName -like 'Microsoft Word*'         -or
    $_.DisplayName -like 'Microsoft Excel*'        -or
    $_.DisplayName -like 'Microsoft PowerPoint*'   -or
    $_.DisplayName -like 'Microsoft Outlook*'
}

if ($officeInstalled) {
    $officeNames = ($officeInstalled | Select-Object -ExpandProperty DisplayName | Sort-Object -Unique) -join '; '
    Write-Log "Found Microsoft Office: $officeNames"

    $c2rExe   = "$env:ProgramFiles\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe"
    $c2rExe86 = "${env:ProgramFiles(x86)}\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe"
    $c2r      = if (Test-Path $c2rExe) { $c2rExe } elseif (Test-Path $c2rExe86) { $c2rExe86 } else { $null }

    if ($c2r) {
        Write-Log "  Click-to-Run detected at: $c2r -- triggering update channel check"
        try {
            Start-Process $c2r -ArgumentList '/update user displaylevel=false forceappshutdown=false' `
                          -Wait -ErrorAction Stop
            Write-Log '  [OK] Office C2R update command invoked.' OK
            Add-Result 'App Update' 'Microsoft Office (C2R)' 'Update Command Sent'
        } catch {
            Write-Log "  [FAIL] Office C2R update failed: $_" ERROR
            Add-Result 'App Update' 'Microsoft Office (C2R)' 'FAILED' "$_"
        }
        Add-Manual "Microsoft Office Apr 2026 patches (CVE-2026-32188 through CVE-2026-33822 series) -- C2R update was triggered. Verify Office apps are on build 2504+ or apply required KBs for MSI installs. See https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates"
    } elseif ($wingetOK) {
        Invoke-WingetUpgrade -PackageId 'Microsoft.Office' `
                             -DisplayName 'Microsoft Office' -Category 'App Update'
        Add-Manual "Microsoft Office Apr 2026 patches (CVE-2026-32188/33822 series) -- verify update applied. For Click-to-Run, open any Office app > File > Account > Update Options > Update Now."
    } else {
        Add-Manual 'Microsoft Office Apr 2026 Security Update -- update via Office > File > Account > Update Now. CVEs: CVE-2026-32188 through CVE-2026-33822.'
    }
} else {
    Write-Log 'Microsoft Office not installed on this machine.' SKIP
    Add-Result 'App Update' 'Microsoft Office' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 11 -- Adobe Products
#  Covers: Adobe Genuine Service APSB20-42;
#          Acrobat/Reader: APSB25-57 (CVE-2025-43550 series),
#            APSB25-85 (CVE-2025-54255/54257), APSB25-119 (CVE-2025-64785-64899),
#            APSB26-43 (CVE-2026-34621), APSB26-44 (CVE-2026-34622/34626);
#          Photoshop: APSB25-30 (CVE-2025-27198), APSB25-40, APSB25-75,
#            APSB25-108 (CVE-2025-61819), APSB26-40 (CVE-2026-27289);
#          Illustrator: APSB25-109 (CVE-2025-61820/61831).
#  Strategy: Adobe Remote Update Manager (RUM) -- silent, updates all CC apps.
#            Reader uses winget when available.
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 11: Adobe Products ---------------------------------------' SECTION

$adobeInstalled = Get-InstalledApps | Where-Object {
    $_.DisplayName -like 'Adobe Genuine*'     -or
    $_.DisplayName -like 'Adobe Acrobat*'     -or
    $_.DisplayName -like 'Adobe Reader*'      -or
    $_.DisplayName -like 'Adobe Photoshop*'   -or
    $_.DisplayName -like 'Adobe Illustrator*'
}

if ($adobeInstalled) {
    Write-Log "Found Adobe product(s): $($adobeInstalled.DisplayName -join ', ')"

    $adobeReader = $adobeInstalled | Where-Object {
        $_.DisplayName -like 'Adobe Acrobat*' -or $_.DisplayName -like 'Adobe Reader*'
    }
    if ($adobeReader -and $wingetOK) {
        Invoke-WingetUpgrade -PackageId 'Adobe.Acrobat.Reader.64-bit' `
                             -DisplayName 'Adobe Acrobat Reader (64-bit)' -Category 'Adobe'
    } elseif ($adobeReader) {
        Add-Manual 'Adobe Acrobat/Reader -- update to the latest APSB25/APSB26-secured release from Adobe or Creative Cloud.'
    }

    $rumPaths = @(
        "${env:ProgramFiles(x86)}\Common Files\Adobe\OOBE\PDApp\UWA\RemoteUpdateManager.exe",
        "$env:ProgramFiles\Common Files\Adobe\OOBE\PDApp\UWA\RemoteUpdateManager.exe",
        "${env:ProgramFiles(x86)}\Adobe\Adobe Creative Cloud\ACC\RemoteUpdateManager.exe"
    )
    $rum = $rumPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($rum) {
        Write-Log "Running Adobe Remote Update Manager: $rum"
        try {
            $proc = Start-Process $rum -Wait -PassThru -ErrorAction Stop
            $ec   = $proc.ExitCode
            if ($ec -in 0, 7) {
                Write-Log "[OK] Adobe RUM completed successfully (exit $ec)." OK
                Add-Result 'Adobe' 'Adobe Products (RUM)' "Success (exit $ec)"
            } else {
                Write-Log "Adobe RUM completed with exit $ec -- verify updates in Adobe CC app." WARN
                Add-Result 'Adobe' 'Adobe Products (RUM)' "Exit $ec -- Review Required"
                Add-Manual "Adobe RUM returned exit code $ec. Open Adobe Creative Cloud app and check for pending Acrobat/Reader, Photoshop, Illustrator, and Genuine Service updates."
            }
        } catch {
            Write-Log "Adobe RUM failed to launch: $_" ERROR
            Add-Manual 'Adobe products -- RUM failed; open Adobe Creative Cloud desktop app and install all pending security updates manually.'
        }
    } else {
        $accExe = "$env:ProgramFiles\Adobe\Adobe Creative Cloud\ACC\ACC.exe"
        if (Test-Path $accExe) {
            Write-Log "Adobe RUM not found; launching ACC.exe in silent mode as fallback..."
            try {
                Start-Process $accExe -ArgumentList '--startupMode=silent' -Wait -ErrorAction SilentlyContinue
                Add-Result 'Adobe' 'Adobe Products (ACC)' 'ACC Silent Launch Attempted'
                Add-Manual 'Adobe products -- ACC.exe was launched silently. Verify Acrobat/Reader, Photoshop, Illustrator, and Genuine Service updates via Adobe Creative Cloud desktop app.'
            } catch {
                Write-Log "ACC.exe launch failed: $_" ERROR
                Add-Manual 'Adobe products -- Adobe Creative Cloud / RUM not detected. Install Adobe CC desktop app and update manually.'
            }
        } else {
            Add-Manual 'Adobe products -- Adobe CC/RUM not detected. Update Acrobat/Reader, Photoshop, Illustrator, and Genuine Service manually from Adobe.'
        }
    }
} else {
    Write-Log 'Adobe scan-target products not found on this machine.' SKIP
    Add-Result 'Adobe' 'Adobe Products' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 11a -- EOL Adobe Reader / Acrobat Uninstall
#  Covers: EOL Adobe Reader/Acrobat XI (v11.x, CVSS 9.3, Count=1),
#          EOL Adobe Acrobat DC 2015 (v15.x, CVSS 9.8, Count=1),
#          EOL Adobe Reader/Acrobat 2017 (v17.x, CVSS 9.8, Count=26)
#          These versions receive no further security patches and must be removed.
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 11a: EOL Adobe Reader/Acrobat Uninstall ------------------' SECTION

$eolAdobeApps = Get-InstalledApps | Where-Object {
    ($_.DisplayName -like 'Adobe Acrobat*' -or $_.DisplayName -like 'Adobe Reader*') -and
    ($_.DisplayVersion -like '11.*' -or $_.DisplayVersion -like '15.*' -or $_.DisplayVersion -like '17.*')
}
if ($eolAdobeApps) {
    foreach ($app in $eolAdobeApps) {
        $label = "$($app.DisplayName) $($app.DisplayVersion)"
        Write-Log "  Found EOL Adobe product: $label -- uninstalling..." WARN
        try {
            if ($app.UninstallString -match 'MsiExec|msiexec') {
                $guid = [regex]::Match($app.UninstallString, '\{[0-9A-Fa-f\-]+\}').Value
                if ($guid) {
                    $p = Start-Process msiexec.exe `
                             -ArgumentList "/x `"$guid`" /qn /norestart" `
                             -Wait -PassThru -ErrorAction Stop
                    if ($p.ExitCode -in 0, 3010) {
                        Write-Log "  [OK] Uninstalled EOL Adobe: $label" OK
                        Add-Result 'Adobe' "EOL Uninstall: $label" 'Removed'
                        if ($p.ExitCode -eq 3010) { $script:RebootRequired = $true }
                    } else {
                        Write-Log "  [FAIL] msiexec exit $($p.ExitCode) for $label" ERROR
                        Add-Result 'Adobe' "EOL Uninstall: $label" "FAILED (exit $($p.ExitCode))"
                        Add-Manual "EOL Adobe uninstall failed for $label -- remove manually via Settings > Apps."
                    }
                }
            } elseif ($app.UninstallString) {
                $cmd = ($app.UninstallString -replace '"', '').Trim()
                Start-Process cmd.exe -ArgumentList "/c `"$cmd`" /S /NORESTART" `
                              -Wait -ErrorAction SilentlyContinue
                Write-Log "  [OK] Uninstall invoked for EOL Adobe: $label" OK
                Add-Result 'Adobe' "EOL Uninstall: $label" 'Removal Invoked'
            } else {
                Add-Manual "EOL Adobe product has no uninstall string: $label -- remove manually via Settings > Apps."
                Add-Result 'Adobe' "EOL Uninstall: $label" 'No Uninstall String -- Manual Required'
            }
        } catch {
            Write-Log "  [FAIL] EOL Adobe uninstall error for $label : $_" ERROR
            Add-Result 'Adobe' "EOL Uninstall: $label" 'FAILED' "$_"
        }
    }
} else {
    Write-Log 'No EOL Adobe Reader/Acrobat versions (XI/2015/2017) detected.' SKIP
    Add-Result 'Adobe' 'EOL Adobe Reader/Acrobat' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 11b -- EOL Windows 11 23H2 Upgrade Guidance
#  Covers: EOL Windows 11 23H2 (CVSS 9.6, Count=4)
#          23H2 reached end of service; must upgrade to 24H2+.
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 11b: EOL Windows 11 23H2 Upgrade Guidance ----------------' SECTION

try {
    $osBuild = [System.Environment]::OSVersion.Version.Build
    $osName   = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                     -Name 'ProductName','DisplayVersion' -ErrorAction SilentlyContinue)
    $displayVer = if ($osName.DisplayVersion) { $osName.DisplayVersion } else { 'Unknown' }
    Write-Log "  OS build: $osBuild  |  Display version: $displayVer"
    if ($osBuild -lt 26100 -and $osBuild -ge 22000) {
        Write-Log "  WARNING: Windows 11 $displayVer (build $osBuild) is EOL (23H2 or earlier)." WARN
        Add-Manual "EOL Windows 11 $displayVer detected (build $osBuild). Windows 11 23H2 has reached end of service (CVSS 9.6). Upgrade to Windows 11 24H2+ immediately: Settings > Windows Update > Check for updates (feature update), or run: winget upgrade --id Microsoft.Windows --accept-package-agreements --accept-source-agreements"
        Add-Result 'OS' "EOL Windows 11 $displayVer" 'Manual Upgrade Required'
    } else {
        Write-Log "  OS version (build $osBuild, $displayVer) is current or non-Windows-11." SKIP
        Add-Result 'OS' "Windows $displayVer" 'Version Current / Skipped'
    }
} catch {
    Write-Log "  OS version check error: $_" WARN
}

# ==============================================================================
#  SECTION 12 -- Dell SupportAssist (UNINSTALL)
#  Covers: DSA-2025-445, DSA-2025-296, DSA-2024-470, DSA-2023-468,
#          and DSA-2021-163 SupportAssist vulnerabilities.
#  Action: Fully uninstall Dell SupportAssist and any PC-Doctor components.
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 12: Dell SupportAssist (Uninstall) -----------------------' SECTION

$saPatterns = @(
    'Dell SupportAssist*',
    'SupportAssist*',
    'PC-Doctor*'
)

$saFound = $false
$saAppsAll = foreach ($pattern in $saPatterns) {
    Get-InstalledApps | Where-Object { $_.DisplayName -like $pattern }
}
$saAppsUnique = $saAppsAll | Sort-Object PSPath -Unique
foreach ($app in $saAppsUnique) {
    if ($app) {
        $saFound = $true
        Write-Log "  Uninstalling: $($app.DisplayName) $($app.DisplayVersion)"
        try {
            if ($app.UninstallString -match 'MsiExec|msiexec') {
                $guid = [regex]::Match($app.UninstallString, '\{[0-9A-Fa-f\-]+\}').Value
                if ($guid) {
                    $p = Start-Process msiexec.exe `
                             -ArgumentList "/x `"$guid`" /qn /norestart" `
                             -Wait -PassThru -ErrorAction Stop
                    if ($p.ExitCode -in 0, 3010) {
                        Write-Log "  [OK] Uninstalled: $($app.DisplayName)" OK
                        Add-Result 'Dell' "Uninstall: $($app.DisplayName)" 'Removed'
                        if ($p.ExitCode -eq 3010) { $script:RebootRequired = $true }
                    } else {
                        Write-Log "  [FAIL] msiexec exit $($p.ExitCode) for $($app.DisplayName)" ERROR
                        Add-Result 'Dell' "Uninstall: $($app.DisplayName)" "FAILED (exit $($p.ExitCode))"
                    }
                }
            } else {
                $cmd = ($app.UninstallString -replace '"', '').Trim()
                Start-Process cmd.exe -ArgumentList "/c `"$cmd`" /S /NORESTART" `
                              -Wait -ErrorAction SilentlyContinue
                Write-Log "  [OK] Uninstall invoked: $($app.DisplayName)" OK
                Add-Result 'Dell' "Uninstall: $($app.DisplayName)" 'Removal Invoked'
            }
        } catch {
            Write-Log "  [FAIL] Uninstall failed for $($app.DisplayName): $_" ERROR
            Add-Result 'Dell' "Uninstall: $($app.DisplayName)" 'FAILED' "$_"
        }
    }
}

if (-not $saFound) {
    Write-Log 'Dell SupportAssist not installed on this machine.' SKIP
    Add-Result 'Dell' 'Dell SupportAssist' 'Not Present / Skipped'
} else {
    if ($wingetOK) {
        $out = & winget uninstall --id 'Dell.SupportAssist' --silent `
                                  --accept-source-agreements 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            Write-Log '  [OK] winget uninstall of Dell.SupportAssist completed.' OK
        }
    }
}

# ==============================================================================
#  SECTION 12a -- Dell BIOS / Firmware Updates (dcu-cli)
#  BIOS updates are maintained as MANUAL per policy.
#  dcu-cli is invoked for driver updates only; BIOS guidance is manual.
#
#  Active DSAs requiring BIOS update (ALL MANUAL):
#    DSA-2026-010  -- BIOS vulnerability (new)
#    DSA-2025-206  -- CVE-2025-20064/20068/20105/20028/20027/20073
#    DSA-2025-203  -- CVE-2024-13176, CVE-2024-9143
#    DSA-2025-048  -- BIOS vulnerability
#    DSA-2025-021  -- BIOS vulnerabilities
#    DSA-2025-088  -- CVE-2025-29988
#    DSA-2025-044  -- CVE-2024-38796
#    DSA-2025-153  -- CVE-2025-36579 (Weak Password Recovery)
#    DSA-2025-016  -- CVE-2025-29989
#    DSA-2025-020  -- CVE-2024-5535, CVE-2024-4741, CVE-2024-2511
#    DSA-2025-005  -- CVE-2024-30211 + 12 more (Intel Platform)
#    DSA-2025-002  -- BIOS vulnerability
#    DSA-2024-351  -- CVE-2024-52537
#    DSA-2024-373  -- CVE-2024-31068
#    DSA-2024-297  -- CVE-2023-5678, CVE-2024-0727
#    DSA-2024-231  -- BIOS vulnerability
#    DSA-2024-168  -- CVE-2024-28970
#    DSA-2024-113  -- CVE-2023-45733, CVE-2023-46103
#    DSA-2024-066  -- CVE-2024-22448
#    DSA-2024-030  -- CVE-2024-0158
#    DSA-2021-216  -- CVE-2021-36323, CVE-2021-36234, CVE-2021-36325
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 12a: Dell BIOS / Firmware (dcu-cli -- Drivers Only) -------' SECTION

$dcuHardware = $false
try {
    $biosVendor = (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue).Manufacturer
    if ($biosVendor -like '*Dell*') {
        $dcuHardware = $true
        Write-Log "Dell hardware detected (BIOS Manufacturer: $biosVendor)"
    }
} catch { }

if (-not $dcuHardware) {
    Write-Log 'Non-Dell hardware -- Dell BIOS/firmware section skipped.' SKIP
    Add-Result 'Dell' 'Dell BIOS / Firmware (dcu-cli)' 'Non-Dell Hardware / Skipped'
} else {
    $dcuCandidates = @(
        "$env:ProgramFiles\Dell\CommandUpdate\dcu-cli.exe",
        "${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe",
        "$env:ProgramFiles\Dell\Dell Command Update\dcu-cli.exe"
    )
    $dcuCli = $dcuCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($dcuCli) {
        Write-Log "Dell Command Update CLI found: $dcuCli"
        Write-Log '  Running dcu-cli /applyUpdates for DRIVERS only (BIOS is manual per policy)...'
        try {
            # -updateType=driver only -- BIOS is intentionally excluded (manual per policy)
            $proc = Start-Process $dcuCli `
                        -ArgumentList '/applyUpdates -reboot=disable -updateType=driver -silent' `
                        -Wait -PassThru -ErrorAction Stop
            $ec = $proc.ExitCode
            switch ($ec) {
                0 {
                    Write-Log '  [OK] dcu-cli: Driver updates applied successfully.' OK
                    Add-Result 'Dell' 'Dell Drivers (dcu-cli)' 'Updated'
                    $script:RebootRequired = $true
                }
                1 {
                    Write-Log '  [OK] dcu-cli: Driver updates applied -- reboot required.' WARN
                    Add-Result 'Dell' 'Dell Drivers (dcu-cli)' 'Updated (Reboot Required)'
                    $script:RebootRequired = $true
                }
                5 {
                    Write-Log '  [OK] dcu-cli: No applicable driver updates found.' SKIP
                    Add-Result 'Dell' 'Dell Drivers (dcu-cli)' 'Already Current'
                }
                default {
                    Write-Log "  [FAIL] dcu-cli exit $ec -- review C:\ProgramData\Dell\UpdateService\Log" ERROR
                    Add-Result 'Dell' 'Dell Drivers (dcu-cli)' "FAILED (exit $ec)"
                }
            }
        } catch {
            Write-Log "  [FAIL] dcu-cli launch failed: $_" ERROR
            Add-Result 'Dell' 'Dell Drivers (dcu-cli)' 'FAILED' "$_"
        }
    } else {
        Write-Log '  Dell Command Update CLI (dcu-cli.exe) not found.' WARN
        Add-Result 'Dell' 'Dell Drivers (dcu-cli)' 'dcu-cli Not Found'
    }

    # All BIOS DSAs are MANUAL per policy
    Add-Manual @"
DELL BIOS UPDATES REQUIRED (manual -- all DSAs below must be applied via Dell.com/support or Dell Command Update BIOS update):
  DSA-2026-010 | BIOS vulnerability (new)
  DSA-2025-206 | CVE-2025-20064, CVE-2025-20068, CVE-2025-20105, CVE-2025-20028, CVE-2025-20027, CVE-2025-20073
  DSA-2025-203 | CVE-2024-13176, CVE-2024-9143
  DSA-2025-048 | BIOS vulnerability
  DSA-2025-021 | BIOS vulnerabilities
  DSA-2025-088 | CVE-2025-29988
  DSA-2025-044 | CVE-2024-38796
  DSA-2025-153 | CVE-2025-36579 (Weak Password Recovery)
  DSA-2025-016 | CVE-2025-29989
  DSA-2025-020 | CVE-2024-5535, CVE-2024-4741, CVE-2024-2511
  DSA-2025-005 | CVE-2024-30211 + 12 Intel Platform CVEs
  DSA-2025-002 | BIOS vulnerability
  DSA-2024-351 | CVE-2024-52537
  DSA-2024-373 | CVE-2024-31068
  DSA-2024-297 | CVE-2023-5678, CVE-2024-0727
  DSA-2024-231 | BIOS vulnerability
  DSA-2024-168 | CVE-2024-28970
  DSA-2024-113 | CVE-2023-45733, CVE-2023-46103
  DSA-2024-066 | CVE-2024-22448
  DSA-2024-030 | CVE-2024-0158
  DSA-2021-216 | CVE-2021-36323, CVE-2021-36234, CVE-2021-36325
  Reference: https://www.dell.com/support/security/en-us
"@

    # Intel Chipset Device Software (INTEL-SA-00870, INTEL-SA-01032)
    # Driver-level -- dcu-cli driver pass above may resolve; flag for verification
    Add-Manual 'Intel Chipset Device Software -- INTEL-SA-00870 (CVE-2023-28388) and INTEL-SA-01032 (CVE-2024-21814) Privilege Escalation. Update to version 10.1.19444.8378+. Dell Command Update driver pass (above) should resolve this on Dell hardware; verify driver version post-run. Non-Dell: download from intel.com/content/www/us/en/download/19347.'
    Add-Manual 'Intel Rapid Storage Technology (INTEL-SA-00324) -- update Intel RST driver/software from Dell Command Update or Intel/OEM support if present.'
    Add-Manual 'Intel Smart Sound Technology (INTEL-SA-00354) -- update Intel SST audio driver from Dell Command Update or Intel/OEM support if present.'
}

# ==============================================================================
#  SECTION 13 -- CrowdStrike Falcon Sensor
#  Covers: CVE-2025-42701, CVE-2025-42706 (Multiple Vulnerabilities)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 13: CrowdStrike Falcon Sensor ----------------------------' SECTION

$csInstalled = Get-InstalledApps | Where-Object {
    $_.DisplayName -like '*CrowdStrike*' -or $_.DisplayName -like '*Falcon*Sensor*'
}
if ($csInstalled) {
    Write-Log "Found CrowdStrike Falcon: $($csInstalled.DisplayName) $($csInstalled.DisplayVersion)"

    $csUpdated = $false
    if ($wingetOK) {
        Write-Log '  Attempting winget upgrade for CrowdStrike Falcon...'
        $out = & winget upgrade --id 'CrowdStrike.FalconSensor' --silent `
                                --accept-package-agreements --accept-source-agreements 2>&1 | Out-String
        $ec  = $LASTEXITCODE
        if ($ec -eq 0) {
            Write-Log '[OK] CrowdStrike Falcon updated via winget.' OK
            Add-Result 'Security' 'CrowdStrike Falcon Sensor' 'Updated via winget'
            $csUpdated = $true
        } elseif ($ec -in -1978335212, 0x8A150014) {
            Write-Log '[OK] CrowdStrike Falcon already at latest version.' SKIP
            Add-Result 'Security' 'CrowdStrike Falcon Sensor' 'Already Current'
            $csUpdated = $true
        } else {
            Write-Log "  winget returned exit $ec for CrowdStrike -- falling back to manual guidance." WARN
        }
    }

    if (-not $csUpdated) {
        Add-Manual "CrowdStrike Falcon Sensor -- Installed version: $($csInstalled.DisplayVersion). CVE-2025-42701, CVE-2025-42706. Update via Falcon console: Hosts > Sensor Update Policy. Assign machine to 'Latest' or N-1 channel. URL: https://falcon.crowdstrike.com"
        Add-Result 'Security' 'CrowdStrike Falcon Sensor' 'Manual Update Required via Falcon Console'
    }
} else {
    Write-Log 'CrowdStrike Falcon Sensor not installed on this machine.' SKIP
    Add-Result 'Security' 'CrowdStrike Falcon Sensor' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 14 -- Ricoh Printer Drivers
#  Covers: CVE-2019-19363 (Local Privilege Escalation)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 14: Ricoh Printer Drivers --------------------------------' SECTION

try {
    $ricohDrivers = Get-PrinterDriver -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like '*Ricoh*' -or $_.Manufacturer -like '*Ricoh*' }

    if ($ricohDrivers) {
        $driverNames = ($ricohDrivers | Select-Object -ExpandProperty Name) -join '; '
        Write-Log "Found Ricoh printer driver(s): $driverNames"

        Write-Log '  Triggering Windows Update driver scan (pnputil /scan-devices)...'
        try {
            $pnpOut = & pnputil.exe /scan-devices 2>&1 | Out-String
            Write-Log "  pnputil: $($pnpOut.Trim())"
            Add-Result 'Drivers' 'Ricoh Printer Driver -- WU Scan' 'Scan Triggered'
        } catch {
            Write-Log "  pnputil scan failed: $_" WARN
        }

        Add-Manual "Ricoh Printer Driver LPE (CVE-2019-19363) -- Driver(s) on this machine: $driverNames. Download updated drivers from: https://support.ricoh.com/bb/html/dr_ut_e/rc3/model/download.htm and reinstall using 'pnputil /add-driver <inf> /install'."
        Add-Result 'Drivers' 'Ricoh Printer Drivers' 'WU Scan Triggered -- Manual Driver Install Needed'
    } else {
        Write-Log 'No Ricoh printer drivers found on this machine.' SKIP
        Add-Result 'Drivers' 'Ricoh Printer Drivers' 'Not Present / Skipped'
    }
} catch {
    Write-Log "Ricoh driver detection error: $_" WARN
    Add-Result 'Drivers' 'Ricoh Printer Drivers' 'Detection Error' "$_"
}

# ==============================================================================
#  SECTION 19 -- Microsoft Visual C++ Redistributable
#  Covers: CVE-2024-43590 (EoP via installer, CVSS 7.8, Count=1)
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 19: Microsoft Visual C++ Redistributable -----------------' SECTION

$vcInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like 'Microsoft Visual C++*' }
if ($vcInstalled -and $wingetOK) {
    Write-Log "Found Visual C++ component(s): $($vcInstalled.DisplayName -join ', ')"
    $vcVersions = @('2015','2017','2019','2022')
    foreach ($vcVer in $vcVersions) {
        $hasVer = $vcInstalled | Where-Object { $_.DisplayName -like "*$vcVer*" }
        if ($hasVer) {
            Invoke-WingetUpgrade -PackageId "Microsoft.VCRedist.$vcVer.x64" `
                                 -DisplayName "Visual C++ $vcVer x64" -Category 'App Update'
            Invoke-WingetUpgrade -PackageId "Microsoft.VCRedist.$vcVer.x86" `
                                 -DisplayName "Visual C++ $vcVer x86" -Category 'App Update'
        }
    }
} elseif ($vcInstalled) {
    Add-Manual 'Microsoft Visual C++ Redistributable -- update via Windows Update or manually from https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist (CVE-2024-43590 EoP)'
} else {
    Write-Log 'Microsoft Visual C++ Redistributable not detected.' SKIP
    Add-Result 'App Update' 'Visual C++ Redistributable' 'Not Present / Skipped'
}

# ==============================================================================
#  SECTION 20 -- Windows Defender Signature Update
#  Covers: Windows Defender EoP "RedSun Zero Day" (CVSS 7.8, Count=29).
#          Full fix via May 2026 CU (Section 1); this section forces a
#          signature/engine update to ensure Defender is current.
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 20: Windows Defender Signature Update --------------------' SECTION

try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    Write-Log "  Defender antivirus enabled: $($mpStatus.AntivirusEnabled)  |  Engine: $($mpStatus.AMEngineVersion)  |  Signature: $($mpStatus.AntivirusSignatureVersion)"
    if ($mpStatus.AntivirusEnabled) {
        Write-Log '  Triggering Windows Defender signature update...'
        Update-MpSignature -ErrorAction Stop
        Write-Log '  [OK] Windows Defender signature update triggered.' OK
        Add-Result 'Security' 'Windows Defender Signature Update' 'Update Triggered'
        Add-Manual 'Windows Defender RedSun Zero Day (CVSS 7.8) -- signature update was forced. Full EoP fix requires the May 2026 cumulative Windows Update (Section 1). Verify engine version post-reboot.'
    } else {
        Write-Log '  Windows Defender antivirus is not enabled on this machine.' WARN
        Add-Result 'Security' 'Windows Defender' 'Disabled -- Manual Review'
        Add-Manual 'Windows Defender is not enabled. RedSun Zero Day EoP (CVSS 7.8) cannot be mitigated without an active AV engine. Enable Defender or ensure an equivalent AV solution is current.'
    }
} catch {
    $mpCmdPath = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
    if (Test-Path $mpCmdPath) {
        Write-Log '  Falling back to MpCmdRun.exe -SignatureUpdate...'
        & $mpCmdPath -SignatureUpdate 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log '  [OK] MpCmdRun signature update completed.' OK
            Add-Result 'Security' 'Windows Defender Signature Update' 'Update Triggered (MpCmdRun)'
        } else {
            Write-Log "  MpCmdRun -SignatureUpdate returned exit $LASTEXITCODE." WARN
            Add-Result 'Security' 'Windows Defender Signature Update' "MpCmdRun exit $LASTEXITCODE"
        }
    } else {
        Write-Log "  Windows Defender not detected or Get-MpComputerStatus failed: $_" WARN
        Add-Result 'Security' 'Windows Defender' 'Detection Error' "$_"
    }
}

# ==============================================================================
#  SECTION 15 -- Registry & System Hardening
#
#  (A) Null Session Restriction       -- CVE-2002-1117, CVE-2000-1200
#  (B) Built-in Administrator Rename  -- CVE-1999-0585
#  (C) RRAS Service Disable           -- CVE-2026-21221
#  (D) Logitech Firmware              -- Manual
#  (E) Guest Account Disable/Rename
#  (F) SMB Signing Enforcement        -- CVSS 7.3
#  (G) Windows AutoPlay Disable       -- CVSS 5.0, Count=200
#  (H) LDAP Channel Binding / Signing -- ADV190023
#  (I) NetBIOS Disable over TCP/IP
#  (J) Kerberos Protocol Enforcement  -- CVE-2026-20833
#  (K) Windows Unquoted Service Paths -- CVSS 7.8, Count=12
# ==============================================================================
Write-Log '' INFO
Write-Log '--- SECTION 15: Registry & System Hardening --------------------------' SECTION

# -- (A) Null Session Restriction ---------------------------------------------
Write-Log '  [A] Null Session Restriction (CVE-2002-1117, CVE-2000-1200)'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' `
                  'RestrictNullSessAccess'  1
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                  'RestrictAnonymous'       1
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                  'RestrictAnonymousSAM'    1

# -- (B) Rename Built-in Administrator (SID *-500) ----------------------------
Write-Log "  [B] Rename built-in Administrator -> '$NewAdminName' (CVE-1999-0585)"
try {
    $builtIn = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-500$' }
    if ($builtIn) {
        if ($builtIn.Name -eq $NewAdminName) {
            Write-Log "  [OK] Built-in Administrator already named '$NewAdminName'." SKIP
            Add-Result 'Registry Hardening' 'Built-in Admin Name' 'Already Renamed'
        } else {
            Rename-LocalUser -Name $builtIn.Name -NewName $NewAdminName -ErrorAction Stop
            Write-Log "  [OK] Renamed '$($builtIn.Name)' -> '$NewAdminName'" OK
            Add-Result 'Registry Hardening' 'Built-in Admin Name' "Renamed to $NewAdminName"
        }
    } else {
        Write-Log '  Built-in Administrator (SID *-500) not found locally -- may be domain-controlled.' SKIP
        Add-Result 'Registry Hardening' 'Built-in Admin Name' 'Not Found (Domain or Already Removed)'
    }
} catch {
    Write-Log "  [FAIL] Could not rename built-in admin: $_" ERROR
    Add-Result 'Registry Hardening' 'Built-in Admin Name' 'FAILED' "$_"
}

# -- (C) RRAS -- Disable if not in use (CVE-2026-21221) ------------------------
Write-Log '  [C] Routing and Remote Access Service (RRAS) -- disable if unused (CVE-2026-21221)'
try {
    $rras = Get-Service -Name 'RemoteAccess' -ErrorAction SilentlyContinue
    if ($rras) {
        if ($rras.Status -eq 'Running') {
            Write-Log '  WARNING: RRAS service is currently RUNNING -- not disabling automatically.' WARN
            Add-Manual 'RRAS (RemoteAccess service) is running and flagged by RCE CVE-2026-21221. If VPN/dial-up routing is not intentionally in use, disable it: Set-Service RemoteAccess -StartupType Disabled ; Stop-Service RemoteAccess'
        } elseif ($rras.StartType -eq 'Disabled') {
            Write-Log '  [OK] RRAS already Disabled.' SKIP
            Add-Result 'Registry Hardening' 'RRAS Service' 'Already Disabled'
        } else {
            Set-Service -Name 'RemoteAccess' -StartupType Disabled -ErrorAction Stop
            Write-Log '  [OK] RRAS service set to Disabled.' OK
            Add-Result 'Registry Hardening' 'RRAS Service' 'Disabled'
        }
    } else {
        Write-Log '  RRAS (RemoteAccess) service not found on this machine.' SKIP
    }
} catch {
    Write-Log "  [FAIL] RRAS service change failed: $_" ERROR
}

# -- (D) Logitech Unifying Receiver -- Manual ----------------------------------
$logiInstalled = Get-InstalledApps | Where-Object { $_.DisplayName -like '*Logitech*' }
if ($logiInstalled) {
    Add-Manual 'Logitech Unifying Receiver (CVE-2019-13052/13053/13054/13055) -- firmware update required. Run Logitech Firmware Update Tool (FUT): https://support.logi.com/hc/en-us/articles/360025297913'
}

# -- (E) Guest Account Disable / Rename ----------------------------------------
Write-Log '  [E] Guest Account Disable/Rename (Count=266)'
try {
    $guestAcct = Get-LocalUser -ErrorAction Stop |
                 Where-Object { $_.SID.Value -match '-501$' -or $_.Name -eq 'Guest' }
    if ($guestAcct) {
        if ($guestAcct.Enabled) {
            Disable-LocalUser -Name $guestAcct.Name -ErrorAction Stop
            Write-Log "  [OK] Guest account '$($guestAcct.Name)' disabled." OK
            Add-Result 'Registry Hardening' 'Guest Account' "Disabled ($($guestAcct.Name))"
        } else {
            Write-Log "  [OK] Guest account '$($guestAcct.Name)' already disabled." SKIP
            Add-Result 'Registry Hardening' 'Guest Account' 'Already Disabled'
        }
    } else {
        Write-Log '  Built-in Guest account (SID *-501) not found -- may be domain-controlled.' SKIP
        Add-Result 'Registry Hardening' 'Guest Account' 'Not Found (Domain or Already Removed)'
    }
} catch {
    Write-Log "  [FAIL] Guest account check/disable failed: $_" ERROR
    Add-Result 'Registry Hardening' 'Guest Account' 'FAILED' "$_"
}

# -- (F) SMB Signing Enforcement ------------------------------------------------
Write-Log '  [F] SMB Signing Enforcement (CVSS 7.3, Count=24; SMBv2 Count=2)'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                  'RequireSecuritySignature' 1
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                  'EnableSecuritySignature'  1
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
                  'RequireSecuritySignature' 1
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
                  'EnableSecuritySignature'  1

# -- (G) Windows AutoPlay Disable -----------------------------------------------
Write-Log '  [G] Windows AutoPlay Disable (CVSS 5.0, Count=200)'
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
                  'NoDriveTypeAutoRun' 255
Set-RegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
                  'NoAutorun' 1
try {
    if (-not (Test-Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) {
        New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
                 -Force -ErrorAction Stop | Out-Null
    }
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
                     -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord -Force -ErrorAction Stop
    Write-Log '  [OK] HKCU AutoPlay NoDriveTypeAutoRun = 255' OK
    Add-Result 'Registry Hardening' 'AutoPlay (HKCU)' 'NoDriveTypeAutoRun=255'
} catch {
    Write-Log "  [FAIL] HKCU AutoPlay registry failed: $_" ERROR
}

# -- (H) LDAP Channel Binding and Signing (ADV190023) ---------------------------
Write-Log '  [H] LDAP Channel Binding and Signing (ADV190023, CVSS 5.4-6.0, Count=2)'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
                  'LDAPServerIntegrity'      2
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
                  'LdapEnforceChannelBinding' 2

# -- (I) NetBIOS Disable over TCP/IP --------------------------------------------
Write-Log '  [I] NetBIOS Disable over TCP/IP (Count=35 -- NetBIOS Name Accessible)'
try {
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' `
                               -ErrorAction Stop
    $disabledCount = 0
    foreach ($adapter in $adapters) {
        $result = $adapter.SetTcpipNetbios(2)
        if ($result.ReturnValue -eq 0) { $disabledCount++ }
    }
    if ($disabledCount -gt 0) {
        Write-Log "  [OK] NetBIOS disabled on $disabledCount adapter(s)." OK
        Add-Result 'Registry Hardening' 'NetBIOS over TCP/IP' "Disabled on $disabledCount adapter(s)"
    } else {
        Write-Log '  NetBIOS: no adapters modified (already disabled or not applicable).' SKIP
        Add-Result 'Registry Hardening' 'NetBIOS over TCP/IP' 'Already Disabled or Not Applicable'
    }
} catch {
    Write-Log "  [FAIL] NetBIOS disable failed: $_" ERROR
    Add-Result 'Registry Hardening' 'NetBIOS over TCP/IP' 'FAILED' "$_"
}

# -- (J) Kerberos Protocol Enforcement (CVE-2026-20833) -------------------------
Write-Log '  [J] Kerberos Protocol Enforcement (CVE-2026-20833, CVSS 5.5, Count=2)'
Add-Manual 'Kerberos Protocol Changes (CVE-2026-20833) -- Ensure the April 2026 cumulative update is installed (Section 1 covers this via Windows Update). After the update, verify Kerberos enforcement is in Full Enforcement Mode: https://support.microsoft.com/kb/KB5037765'
Add-Result 'Registry Hardening' 'Kerberos CVE-2026-20833' 'Manual Verification Required Post-WU'

# -- (K) Windows Unquoted Service Paths -----------------------------------------
Write-Log '  [K] Windows Unquoted Service Paths (CVSS 7.8, Count=12)'
$unquotedFixed   = 0
$unquotedManual  = 0
try {
    $svcKeys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue
    foreach ($key in $svcKeys) {
        try {
            $props     = Get-ItemProperty $key.PsPath -ErrorAction SilentlyContinue
            $imagePath = $props.ImagePath
            if (-not $imagePath) { continue }
            if ($imagePath -match '^"') { continue }
            if ($imagePath -match '^\\\\\?\\') { continue }
            # Unquoted path with spaces outside Windows directories
            if ($imagePath -match '^[A-Za-z]:\\' -and
                $imagePath -notmatch '^[A-Za-z]:\\Windows\\' -and
                $imagePath -match ' ') {
                $exePath = ($imagePath -split ' ')[0]
                $quoted  = "`"$imagePath`""
                try {
                    Set-ItemProperty $key.PsPath -Name 'ImagePath' -Value $quoted -Force -ErrorAction Stop
                    Write-Log "  [OK] Quoted service path: $($key.PSChildName)" OK
                    Add-Result 'Registry Hardening' "Unquoted Service: $($key.PSChildName)" 'Path Quoted'
                    $unquotedFixed++
                } catch {
                    Write-Log "  Could not quote path for $($key.PSChildName): $_" WARN
                    Add-Manual "Unquoted service path for '$($key.PSChildName)': $imagePath -- quote manually in registry."
                    $unquotedManual++
                }
            }
        } catch { }
    }
    if ($unquotedFixed -eq 0 -and $unquotedManual -eq 0) {
        Write-Log '  [OK] No unquoted service paths detected outside Windows directories.' SKIP
        Add-Result 'Registry Hardening' 'Unquoted Service Paths' 'None Found'
    } else {
        Write-Log "  Unquoted service paths: $unquotedFixed auto-fixed, $unquotedManual require manual attention." $(if ($unquotedManual -gt 0) { 'WARN' } else { 'OK' })
    }
} catch {
    Write-Log "  [FAIL] Unquoted service path scan failed: $_" ERROR
    Add-Result 'Registry Hardening' 'Unquoted Service Paths' 'Scan FAILED' "$_"
}

# ==============================================================================
#  SUMMARY REPORT
# ==============================================================================
Write-Log '' INFO
Write-Log ('=' * 72) SECTION
Write-Log '  REMEDIATION SUMMARY' SECTION
Write-Log ('=' * 72) SECTION

$elapsed = (Get-Date) - $script:StartTime
Write-Log "Computer     : $env:COMPUTERNAME"
Write-Log "OS Version   : $([System.Environment]::OSVersion.VersionString)"
Write-Log "Run Duration : $([int]$elapsed.TotalMinutes) min $($elapsed.Seconds) sec"
Write-Log "Reboot Req   : $($script:RebootRequired)"
Write-Log "Total Items  : $($script:Results.Count)"

# Export results to CSV
try {
    $script:Results | ForEach-Object { [pscustomobject]$_ } |
        Export-Csv -Path $ReportCsv -NoTypeInformation -Append -ErrorAction Stop
    Write-Log "Report CSV   : $ReportCsv"
} catch {
    Write-Log "Could not write report CSV: $_" WARN
}

# Status breakdown
$grouped = $script:Results | ForEach-Object { [pscustomobject]$_ } |
           Group-Object Status | Sort-Object Count -Descending
Write-Log '' INFO
Write-Log 'Status Breakdown:'
foreach ($g in $grouped) {
    Write-Log ("  {0,-38} {1} item(s)" -f $g.Name, $g.Count)
}

# Manual items list
if ($script:ManualItems.Count -gt 0) {
    Write-Log '' INFO
    Write-Log ("ITEMS REQUIRING MANUAL ACTION ({0}):" -f $script:ManualItems.Count) MANUAL
    for ($i = 0; $i -lt $script:ManualItems.Count; $i++) {
        Write-Log ("  [{0}] {1}" -f ($i + 1), $script:ManualItems[$i]) MANUAL
    }
}

Write-Log '' INFO
Write-Log "Log file     : $LogFile"
Write-Log ('=' * 72) SECTION

Stop-Transcript | Out-Null

# ==============================================================================
#  REBOOT
# ==============================================================================
if ($script:RebootRequired) {
    Write-Host ''
    Write-Host '[WARN] A reboot is required to complete remediation. Please restart this machine manually.' `
               -ForegroundColor Yellow
} else {
    Write-Host ''
    Write-Host '[DONE] Remediation complete. No reboot required.' -ForegroundColor Green
}
