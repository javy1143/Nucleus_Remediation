#Requires -Version 5.1
<#
.SYNOPSIS
    MedPro remote remediation push console.

.DESCRIPTION
    Windows Forms operator console for starting Invoke-MedProVulnRemediation.ps1
    on domain-joined endpoints over PowerShell Remoting. The console uses the
    current Windows logon token and does not store credentials.

    The remediation script is expected to live on a secured UNC path. Target
    computers must be able to read that share, commonly by granting read access
    to the appropriate domain computer group.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Edit this default once to match the secured share where the weekly script is maintained.
$script:DefaultRemediationScriptPath = '\\mpc-helpdesk\Share\Vulnerability Cleaner\Invoke-MedProVulnRemediation.ps1'
$script:DefaultRemoteLogPath = 'C:\MedPro\Logs'
$script:RemoteWorkDir = 'C:\MedPro\RemotePush'
$script:RemoteTaskName = 'MedProVulnRemediationPush'
$script:LaunchWaitSeconds = 30

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

function New-DataTable {
    $table = New-Object System.Data.DataTable
    [void]$table.Columns.Add('Target', [string])
    [void]$table.Columns.Add('Status', [string])
    [void]$table.Columns.Add('Message', [string])
    [void]$table.Columns.Add('Updated', [string])
    return ,$table
}

function Add-LogLine {
    param(
        [System.Windows.Forms.TextBox]$LogBox,
        [string]$Message
    )

    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message
    $LogBox.AppendText($line + [Environment]::NewLine)
}

function Set-RowStatus {
    param(
        [System.Data.DataRow]$Row,
        [string]$Status,
        [string]$Message
    )

    $Row['Status'] = $Status
    $Row['Message'] = $Message
    $Row['Updated'] = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
}

function Get-ExistingTargets {
    param([System.Data.DataTable]$Table)

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $Table.Rows) {
        if ($row['Target']) {
            [void]$set.Add([string]$row['Target'])
        }
    }
    return ,$set
}

function Add-Target {
    param(
        [System.Data.DataTable]$Table,
        [string]$Target
    )

    $cleanTarget = ($Target -as [string]).Trim()
    if ([string]::IsNullOrWhiteSpace($cleanTarget)) {
        return $false
    }

    if ($cleanTarget -match '[\s\\/]' ) {
        throw "Target '$cleanTarget' is not a valid IP address or hostname."
    }

    $existingTargets = Get-ExistingTargets -Table $Table
    if ($existingTargets.Contains($cleanTarget)) {
        return $false
    }

    $row = $Table.NewRow()
    $row['Target'] = $cleanTarget
    $row['Status'] = 'Pending'
    $row['Message'] = ''
    $row['Updated'] = ''
    [void]$Table.Rows.Add($row)
    return $true
}

function Add-TrustedHostsEntry {
    param([string]$TrustedHostsPattern)

    $cleanPattern = ($TrustedHostsPattern -as [string]).Trim()
    if ([string]::IsNullOrWhiteSpace($cleanPattern)) {
        throw 'TrustedHosts pattern cannot be empty.'
    }

    $trustedHostsPath = 'WSMan:\localhost\Client\TrustedHosts'
    $currentItem = Get-Item -Path $trustedHostsPath -ErrorAction Stop
    $currentValue = [string]$currentItem.Value

    if ($currentValue.Trim() -eq '*') {
        return "TrustedHosts is already set to '*'."
    }

    $entries = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($currentValue)) {
        foreach ($entry in ($currentValue -split ',')) {
            $trimmed = $entry.Trim()
            if (-not [string]::IsNullOrWhiteSpace($trimmed) -and -not $entries.Contains($trimmed)) {
                [void]$entries.Add($trimmed)
            }
        }
    }

    foreach ($entry in $entries) {
        if ($entry.Equals($cleanPattern, [StringComparison]::OrdinalIgnoreCase)) {
            return "TrustedHosts already includes '$cleanPattern'."
        }

        if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($entry)) {
            $wildcard = New-Object System.Management.Automation.WildcardPattern($entry, [System.Management.Automation.WildcardOptions]::IgnoreCase)
            if ($wildcard.IsMatch($cleanPattern)) {
                return "TrustedHosts entry '$entry' already covers '$cleanPattern'."
            }
        }
    }

    if (-not $entries.Contains($cleanPattern)) {
        [void]$entries.Add($cleanPattern)
        Set-Item -Path $trustedHostsPath -Value ($entries -join ',') -Force -ErrorAction Stop
        return "Added TrustedHosts entry '$cleanPattern'."
    }

    return "TrustedHosts already includes '$cleanPattern'."
}

function Test-TcpPort {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutMilliseconds = 1500
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return $false
        }

        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Test-TargetReachability {
    param([string]$ComputerName)

    $pingOk = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
    if ($pingOk) {
        return [pscustomobject]@{
            Success = $true
            Message = 'Reachable by ping.'
        }
    }

    $httpOk = Test-TcpPort -ComputerName $ComputerName -Port 5985
    $httpsOk = Test-TcpPort -ComputerName $ComputerName -Port 5986
    if ($httpOk -or $httpsOk) {
        return [pscustomobject]@{
            Success = $true
            Message = 'Reachable on a WinRM TCP port.'
        }
    }

    return [pscustomobject]@{
        Success = $false
        Message = 'Host did not respond to ping or WinRM ports 5985/5986.'
    }
}

function Test-WinRM {
    param([string]$ComputerName)

    try {
        Test-WSMan -ComputerName $ComputerName -ErrorAction Stop | Out-Null
        return [pscustomobject]@{
            Success = $true
            Message = 'WinRM is available.'
        }
    } catch {
        return [pscustomobject]@{
            Success = $false
            Message = "WinRM check failed: $($_.Exception.Message)"
        }
    }
}

function Start-RemoteRemediation {
    param(
        [string]$ComputerName,
        [string]$ScriptPath,
        [string]$LogPath,
        [ValidateSet('Install','ScanOnly','Skip')]
        [string]$WindowsUpdateMode,
        [ValidateSet('All','WindowsUpdate')]
        [string]$Section,
        [bool]$SkipWindowsUpdate
    )

    try {
        $trustedHostsMessage = Add-TrustedHostsEntry -TrustedHostsPattern $ComputerName
    } catch {
        return [pscustomobject]@{
            Status = 'Failed'
            Message = "TrustedHosts update failed for '$ComputerName': $($_.Exception.Message). Run this console as an elevated domain admin."
        }
    }

    $reachability = Test-TargetReachability -ComputerName $ComputerName
    if (-not $reachability.Success) {
        return [pscustomobject]@{
            Status = 'Failed'
            Message = "$trustedHostsMessage $($reachability.Message)"
        }
    }

    $winRM = Test-WinRM -ComputerName $ComputerName
    if (-not $winRM.Success) {
        return [pscustomobject]@{
            Status = 'Failed'
            Message = "$trustedHostsMessage $($winRM.Message)"
        }
    }

    $launchId = [guid]::NewGuid().ToString('N')

    $remoteBlock = {
        param(
            [string]$RemoteScriptPath,
            [string]$RemoteLogPath,
            [string]$RemoteWindowsUpdateMode,
            [string]$RemoteSection,
            [bool]$RemoteSkipWindowsUpdate,
            [string]$RemoteLaunchId,
            [string]$WorkDir,
            [string]$TaskName,
            [int]$WaitSeconds
        )

        $ErrorActionPreference = 'Stop'

        New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

        $launcherPath = Join-Path $WorkDir 'Launch-Remediation.ps1'
        $configPath = Join-Path $WorkDir 'Launch-Remediation.config.json'
        $statusPath = Join-Path $WorkDir 'Launch-Remediation.status.json'

        $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existingTask -and $existingTask.State -eq 'Running') {
            return [pscustomobject]@{
                Status = 'Failed'
                Message = "Remote task '$TaskName' is already running."
                LaunchId = $RemoteLaunchId
                Computer = $env:COMPUTERNAME
            }
        }

        Remove-Item -LiteralPath $statusPath -Force -ErrorAction SilentlyContinue

        $config = [ordered]@{
            LaunchId = $RemoteLaunchId
            ScriptPath = $RemoteScriptPath
            LogPath = $RemoteLogPath
            WindowsUpdateMode = $RemoteWindowsUpdateMode
            Section = $RemoteSection
            SkipWindowsUpdate = $RemoteSkipWindowsUpdate
            StatusPath = $statusPath
            TaskName = $TaskName
            CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
        $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8 -Force

        $launcher = @'
param([string]$ConfigPath)

$ErrorActionPreference = 'Stop'

function Write-LaunchStatus {
    param(
        [string]$State,
        [string]$Message,
        [int]$ExitCode = 0
    )

    $status = [ordered]@{
        LaunchId = $config.LaunchId
        Computer = $env:COMPUTERNAME
        State = $State
        Message = $Message
        ExitCode = $ExitCode
        Timestamp = (Get-Date).ToString('o')
    }
    $status | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $config.StatusPath -Encoding UTF8 -Force
}

try {
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json

    New-Item -ItemType Directory -Path $config.LogPath -Force | Out-Null
    $resolvedScriptPath = [string]$config.ScriptPath
    if (-not (Test-Path -LiteralPath $resolvedScriptPath -PathType Leaf)) {
        Write-LaunchStatus -State 'Failed' -Message "Script path not found or not readable from endpoint: $resolvedScriptPath" -ExitCode 2
        exit 2
    }

    Write-LaunchStatus -State 'Started' -Message "Remediation script started from $resolvedScriptPath."

    $parameters = @{
        LogPath = [string]$config.LogPath
        WindowsUpdateMode = [string]$config.WindowsUpdateMode
        Section = [string]$config.Section
    }
    if ([bool]$config.SkipWindowsUpdate) {
        $parameters['SkipWindowsUpdate'] = $true
    }

    & $resolvedScriptPath @parameters
    $exitCode = if ($global:LASTEXITCODE -is [int]) { $global:LASTEXITCODE } else { 0 }
    Write-LaunchStatus -State 'Completed' -Message "Remediation script completed with exit code $exitCode." -ExitCode $exitCode
    exit $exitCode
} catch {
    Write-LaunchStatus -State 'Failed' -Message $_.Exception.Message -ExitCode 1
    exit 1
}
'@
        Set-Content -LiteralPath $launcherPath -Value $launcher -Encoding UTF8 -Force

        $actionArguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -ConfigPath "{1}"' -f $launcherPath, $configPath
        $action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $actionArguments
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 6)

        Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskName $TaskName

        $deadline = (Get-Date).AddSeconds($WaitSeconds)
        do {
            Start-Sleep -Milliseconds 750
            if (Test-Path -LiteralPath $statusPath -PathType Leaf) {
                try {
                    $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
                    if ($status.State -eq 'Started' -or $status.State -eq 'Completed') {
                        return [pscustomobject]@{
                            Status = 'Started'
                            Message = [string]$status.Message
                            LaunchId = [string]$status.LaunchId
                            Computer = [string]$status.Computer
                        }
                    }
                    if ($status.State -eq 'Failed') {
                        return [pscustomobject]@{
                            Status = 'Failed'
                            Message = [string]$status.Message
                            LaunchId = [string]$status.LaunchId
                            Computer = [string]$status.Computer
                        }
                    }
                } catch {
                    # Keep polling if the status file is mid-write.
                }
            }
        } while ((Get-Date) -lt $deadline)

        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        return [pscustomobject]@{
            Status = 'Failed'
            Message = "Scheduled task was accepted, but no launch status was written within $WaitSeconds seconds. LastTaskResult: $($taskInfo.LastTaskResult)"
            LaunchId = $RemoteLaunchId
            Computer = $env:COMPUTERNAME
        }
    }

    try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $remoteBlock -ArgumentList @(
            $ScriptPath,
            $LogPath,
            $WindowsUpdateMode,
            $Section,
            $SkipWindowsUpdate,
            $launchId,
            $script:RemoteWorkDir,
            $script:RemoteTaskName,
            $script:LaunchWaitSeconds
        ) -ErrorAction Stop

        $firstResult = @($result)[0]
        return [pscustomobject]@{
            Status = [string]$firstResult.Status
            Message = "$trustedHostsMessage $([string]$firstResult.Message)"
        }
    } catch {
        return [pscustomobject]@{
            Status = 'Failed'
            Message = "$trustedHostsMessage Remote launch failed: $($_.Exception.Message)"
        }
    }
}

function Set-ControlsEnabled {
    param(
        [bool]$Enabled,
        [System.Windows.Forms.Control[]]$Controls
    )

    foreach ($control in $Controls) {
        $control.Enabled = $Enabled
    }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'MedPro Remote Remediation Console'
$form.Size = New-Object System.Drawing.Size(1020, 720)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(900, 620)

$font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.Font = $font

$mainPanel = New-Object System.Windows.Forms.TableLayoutPanel
$mainPanel.Dock = 'Fill'
$mainPanel.ColumnCount = 1
$mainPanel.RowCount = 5
$mainPanel.Padding = New-Object System.Windows.Forms.Padding(12)
[void]$mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 96)))
[void]$mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 52)))
[void]$mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 50)))
[void]$mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 132)))
$form.Controls.Add($mainPanel)

$scriptPanel = New-Object System.Windows.Forms.TableLayoutPanel
$scriptPanel.Dock = 'Fill'
$scriptPanel.ColumnCount = 4
$scriptPanel.RowCount = 2
[void]$scriptPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 112)))
[void]$scriptPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$scriptPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 112)))
[void]$scriptPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150)))
[void]$scriptPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 42)))
[void]$scriptPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 42)))
$mainPanel.Controls.Add($scriptPanel, 0, 0)

$scriptPathLabel = New-Object System.Windows.Forms.Label
$scriptPathLabel.Text = 'Script UNC'
$scriptPathLabel.TextAlign = 'MiddleLeft'
$scriptPathLabel.Dock = 'Fill'
$scriptPanel.Controls.Add($scriptPathLabel, 0, 0)

$scriptPathText = New-Object System.Windows.Forms.TextBox
$scriptPathText.Text = $script:DefaultRemediationScriptPath
$scriptPathText.Dock = 'Fill'
$scriptPathText.Anchor = 'Left,Right'
$scriptPanel.Controls.Add($scriptPathText, 1, 0)

$browseButton = New-Object System.Windows.Forms.Button
$browseButton.Text = 'Browse'
$browseButton.Dock = 'Fill'
$scriptPanel.Controls.Add($browseButton, 2, 0)

$validateButton = New-Object System.Windows.Forms.Button
$validateButton.Text = 'Validate Path'
$validateButton.Dock = 'Fill'
$scriptPanel.Controls.Add($validateButton, 3, 0)

$logPathLabel = New-Object System.Windows.Forms.Label
$logPathLabel.Text = 'Remote logs'
$logPathLabel.TextAlign = 'MiddleLeft'
$logPathLabel.Dock = 'Fill'
$scriptPanel.Controls.Add($logPathLabel, 0, 1)

$logPathText = New-Object System.Windows.Forms.TextBox
$logPathText.Text = $script:DefaultRemoteLogPath
$logPathText.Dock = 'Fill'
$scriptPanel.Controls.Add($logPathText, 1, 1)

$windowsUpdateCombo = New-Object System.Windows.Forms.ComboBox
$windowsUpdateCombo.DropDownStyle = 'DropDownList'
[void]$windowsUpdateCombo.Items.AddRange(@('Install','ScanOnly','Skip'))
$windowsUpdateCombo.SelectedItem = 'Install'
$windowsUpdateCombo.Dock = 'Fill'
$scriptPanel.Controls.Add($windowsUpdateCombo, 2, 1)

$sectionCombo = New-Object System.Windows.Forms.ComboBox
$sectionCombo.DropDownStyle = 'DropDownList'
[void]$sectionCombo.Items.AddRange(@('All','WindowsUpdate'))
$sectionCombo.SelectedItem = 'All'
$sectionCombo.Dock = 'Fill'
$scriptPanel.Controls.Add($sectionCombo, 3, 1)

$targetPanel = New-Object System.Windows.Forms.TableLayoutPanel
$targetPanel.Dock = 'Fill'
$targetPanel.ColumnCount = 5
$targetPanel.RowCount = 1
[void]$targetPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 112)))
[void]$targetPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$targetPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 112)))
[void]$targetPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 112)))
[void]$targetPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 112)))
$mainPanel.Controls.Add($targetPanel, 0, 1)

$targetLabel = New-Object System.Windows.Forms.Label
$targetLabel.Text = 'Target'
$targetLabel.TextAlign = 'MiddleLeft'
$targetLabel.Dock = 'Fill'
$targetPanel.Controls.Add($targetLabel, 0, 0)

$targetText = New-Object System.Windows.Forms.TextBox
$targetText.Dock = 'Fill'
$targetPanel.Controls.Add($targetText, 1, 0)

$addTargetButton = New-Object System.Windows.Forms.Button
$addTargetButton.Text = 'Add'
$addTargetButton.Dock = 'Fill'
$targetPanel.Controls.Add($addTargetButton, 2, 0)

$importCsvButton = New-Object System.Windows.Forms.Button
$importCsvButton.Text = 'Import CSV'
$importCsvButton.Dock = 'Fill'
$targetPanel.Controls.Add($importCsvButton, 3, 0)

$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text = 'Clear'
$clearButton.Dock = 'Fill'
$targetPanel.Controls.Add($clearButton, 4, 0)

$optionsPanel = New-Object System.Windows.Forms.TableLayoutPanel
$optionsPanel.Dock = 'Fill'
$optionsPanel.ColumnCount = 4
$optionsPanel.RowCount = 1
[void]$optionsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 180)))
[void]$optionsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$optionsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150)))
[void]$optionsPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150)))
$mainPanel.Controls.Add($optionsPanel, 0, 2)

$skipWindowsUpdateCheck = New-Object System.Windows.Forms.CheckBox
$skipWindowsUpdateCheck.Text = 'Skip Windows Update'
$skipWindowsUpdateCheck.Dock = 'Fill'
$optionsPanel.Controls.Add($skipWindowsUpdateCheck, 0, 0)

$noticeLabel = New-Object System.Windows.Forms.Label
$noticeLabel.Text = 'Use TrustedHosts first to prepare exact target entries, then Push to start an auditable SYSTEM scheduled task over WinRM.'
$noticeLabel.TextAlign = 'MiddleLeft'
$noticeLabel.Dock = 'Fill'
$optionsPanel.Controls.Add($noticeLabel, 1, 0)

$trustedHostsButton = New-Object System.Windows.Forms.Button
$trustedHostsButton.Text = 'TrustedHosts'
$trustedHostsButton.Dock = 'Fill'
$optionsPanel.Controls.Add($trustedHostsButton, 2, 0)

$pushButton = New-Object System.Windows.Forms.Button
$pushButton.Text = 'Push'
$pushButton.Dock = 'Fill'
$optionsPanel.Controls.Add($pushButton, 3, 0)

$targetsTable = New-DataTable

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.DataSource = $targetsTable
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $true
$grid.SelectionMode = 'FullRowSelect'
$grid.MultiSelect = $true
$grid.ReadOnly = $true
$grid.AutoSizeColumnsMode = 'Fill'
$grid.RowHeadersVisible = $false
$mainPanel.Controls.Add($grid, 0, 3)

$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Dock = 'Fill'
$logBox.Multiline = $true
$logBox.ReadOnly = $true
$logBox.ScrollBars = 'Vertical'
$mainPanel.Controls.Add($logBox, 0, 4)

$interactiveControls = @(
    $scriptPathText,
    $browseButton,
    $validateButton,
    $logPathText,
    $windowsUpdateCombo,
    $sectionCombo,
    $targetText,
    $addTargetButton,
    $importCsvButton,
    $clearButton,
    $skipWindowsUpdateCheck,
    $trustedHostsButton,
    $pushButton
)

$browseButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = 'PowerShell scripts (*.ps1)|*.ps1|All files (*.*)|*.*'
    $dialog.Title = 'Select remediation script from secured share'
    if ($dialog.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $scriptPathText.Text = $dialog.FileName
    }
})

$validateButton.Add_Click({
    try {
        if (Test-Path -LiteralPath $scriptPathText.Text -PathType Leaf) {
            Add-LogLine -LogBox $logBox -Message "Script path validated from admin workstation: $($scriptPathText.Text)"
            [System.Windows.Forms.MessageBox]::Show($form, 'Script path is reachable from this admin workstation.', 'Validation', 'OK', 'Information') | Out-Null
        } else {
            Add-LogLine -LogBox $logBox -Message "Script path validation failed: $($scriptPathText.Text)"
            [System.Windows.Forms.MessageBox]::Show($form, 'Script path was not found from this admin workstation.', 'Validation', 'OK', 'Warning') | Out-Null
        }
    } catch {
        Add-LogLine -LogBox $logBox -Message "Script path validation failed: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show($form, $_.Exception.Message, 'Validation failed', 'OK', 'Error') | Out-Null
    }
})

$addTargetButton.Add_Click({
    try {
        if (Add-Target -Table $targetsTable -Target $targetText.Text) {
            Add-LogLine -LogBox $logBox -Message "Added target $($targetText.Text.Trim())."
            $targetText.Clear()
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show($form, $_.Exception.Message, 'Invalid target', 'OK', 'Warning') | Out-Null
    }
})

$targetText.Add_KeyDown({
    param($sender, $eventArgs)

    if ($eventArgs.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $addTargetButton.PerformClick()
        $eventArgs.SuppressKeyPress = $true
    }
})

$importCsvButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
    $dialog.Title = 'Import targets CSV'
    if ($dialog.ShowDialog($form) -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    try {
        $rows = Import-Csv -LiteralPath $dialog.FileName
        if (-not $rows -or -not ($rows[0].PSObject.Properties.Name -contains 'Target')) {
            throw "CSV must include a 'Target' column."
        }

        $added = 0
        foreach ($csvRow in $rows) {
            if (Add-Target -Table $targetsTable -Target $csvRow.Target) {
                $added++
            }
        }
        Add-LogLine -LogBox $logBox -Message "Imported $added target(s) from $($dialog.FileName)."
    } catch {
        [System.Windows.Forms.MessageBox]::Show($form, $_.Exception.Message, 'Import failed', 'OK', 'Error') | Out-Null
    }
})

$clearButton.Add_Click({
    $targetsTable.Clear()
    Add-LogLine -LogBox $logBox -Message 'Cleared target list.'
})

$trustedHostsButton.Add_Click({
    if ($targetsTable.Rows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show($form, 'Add at least one destination IP or hostname before updating TrustedHosts.', 'No targets', 'OK', 'Warning') | Out-Null
        return
    }

    Set-ControlsEnabled -Enabled $false -Controls $interactiveControls
    try {
        Add-LogLine -LogBox $logBox -Message "Updating TrustedHosts for $($targetsTable.Rows.Count) target(s)."
        foreach ($row in @($targetsTable.Rows)) {
            $target = [string]$row['Target']
            Set-RowStatus -Row $row -Status 'TrustedHosts' -Message 'Updating local TrustedHosts.'
            $grid.Refresh()
            [System.Windows.Forms.Application]::DoEvents()

            try {
                $message = Add-TrustedHostsEntry -TrustedHostsPattern $target
                Set-RowStatus -Row $row -Status 'TrustedHosts' -Message $message
                Add-LogLine -LogBox $logBox -Message "$target [TrustedHosts]: $message"
            } catch {
                $message = "TrustedHosts update failed for '$target': $($_.Exception.Message). Run this console as an elevated domain admin."
                Set-RowStatus -Row $row -Status 'Failed' -Message $message
                Add-LogLine -LogBox $logBox -Message "$target [Failed]: $message"
            }

            $grid.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
        }
        Add-LogLine -LogBox $logBox -Message 'TrustedHosts update cycle finished.'
    } finally {
        Set-ControlsEnabled -Enabled $true -Controls $interactiveControls
    }
})

$pushButton.Add_Click({
    if ($targetsTable.Rows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show($form, 'Add at least one destination IP or hostname before pushing.', 'No targets', 'OK', 'Warning') | Out-Null
        return
    }

    $scriptPath = $scriptPathText.Text.Trim()
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        [System.Windows.Forms.MessageBox]::Show($form, 'The remediation script path was not found from this admin workstation.', 'Script not found', 'OK', 'Error') | Out-Null
        return
    }

    $logPath = $logPathText.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($logPath)) {
        [System.Windows.Forms.MessageBox]::Show($form, 'Remote log path cannot be empty.', 'Invalid log path', 'OK', 'Warning') | Out-Null
        return
    }

    Set-ControlsEnabled -Enabled $false -Controls $interactiveControls
    try {
        Add-LogLine -LogBox $logBox -Message "Starting remote push for $($targetsTable.Rows.Count) target(s)."
        foreach ($row in @($targetsTable.Rows)) {
            $target = [string]$row['Target']
            Set-RowStatus -Row $row -Status 'Connecting' -Message 'Checking reachability and WinRM.'
            $grid.Refresh()
            [System.Windows.Forms.Application]::DoEvents()

            Add-LogLine -LogBox $logBox -Message "Connecting to $target."
            $result = Start-RemoteRemediation -ComputerName $target `
                                             -ScriptPath $scriptPath `
                                             -LogPath $logPath `
                                             -WindowsUpdateMode ([string]$windowsUpdateCombo.SelectedItem) `
                                             -Section ([string]$sectionCombo.SelectedItem) `
                                             -SkipWindowsUpdate ([bool]$skipWindowsUpdateCheck.Checked)

            Set-RowStatus -Row $row -Status $result.Status -Message $result.Message
            Add-LogLine -LogBox $logBox -Message "$target [$($result.Status)]: $($result.Message)"
            $grid.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
        }
        Add-LogLine -LogBox $logBox -Message 'Remote push cycle finished.'
    } finally {
        Set-ControlsEnabled -Enabled $true -Controls $interactiveControls
    }
})

Add-LogLine -LogBox $logBox -Message 'Console ready. Update the Script UNC field to the secured weekly script path before pushing.'

[void][System.Windows.Forms.Application]::Run($form)
