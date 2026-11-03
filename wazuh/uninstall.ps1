# Destructive local agent removal. Never contacts the manager or reinstalls.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-RemovalAdministrator {
    if ($env:OS -ne 'Windows_NT') { throw 'Windows is required.' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run the removal command in PowerShell as Administrator.'
    }
}
function Get-AgentProducts {
    # Registry enumeration does not trigger Win32_Product's MSI repair behavior.
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32, [Microsoft.Win32.RegistryView]::Registry64)) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($null -eq $uninstall) { continue }
            try {
                foreach ($name in $uninstall.GetSubKeyNames()) {
                    if ($name -notmatch '\A\{[0-9a-fA-F-]{36}\}\z') { continue }
                    $entry = $uninstall.OpenSubKey($name)
                    try {
                        if ($entry.GetValue('DisplayName', '') -ne 'Wazuh Agent' -or $entry.GetValue('WindowsInstaller', 0) -ne 1) { continue }
                        [pscustomobject]@{Code=$name; Version=[string]$entry.GetValue('DisplayVersion', ''); Location=[string]$entry.GetValue('InstallLocation', '')}
                    } finally { $entry.Dispose() }
                }
            } finally { $uninstall.Dispose() }
        } finally { $base.Dispose() }
    }
}
function Get-AgentRemovalRoots {
    param($Products)
    $paths = @()
    foreach ($variable in @('ProgramFiles(x86)', 'ProgramW6432', 'ProgramFiles')) {
        $directory = [Environment]::GetEnvironmentVariable($variable)
        if (-not [string]::IsNullOrWhiteSpace($directory)) { $paths += Join-Path $directory 'ossec-agent' }
    }
    foreach ($product in $Products) {
        if (-not [string]::IsNullOrWhiteSpace($product.Location)) { $paths += $product.Location }
    }
    foreach ($registry in @('HKLM:\SOFTWARE\Wazuh, Inc.\Wazuh Agent', 'HKLM:\SOFTWARE\WOW6432Node\Wazuh, Inc.\Wazuh Agent')) {
        if (Test-Path -LiteralPath $registry) {
            $path = Get-ItemPropertyValue -LiteralPath $registry -Name WazuhInstallDir -ErrorAction SilentlyContinue
            if (-not [string]::IsNullOrWhiteSpace($path)) { $paths += $path }
        }
    }
    $paths | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd([IO.Path]::DirectorySeparatorChar) } | Select-Object -Unique
}
function Assert-AgentRemovalRoot {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or [IO.Path]::GetFileName($Path) -ine 'ossec-agent') {
        throw "Refusing unexpected agent directory '$Path'. Custom installations outside ossec-agent need manual removal."
    }
    $directory = [IO.DirectoryInfo]::new($Path)
    while ($null -ne $directory) {
        if (Test-Path -LiteralPath $directory.FullName) {
            $item = Get-Item -LiteralPath $directory.FullName -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Refusing a linked or non-directory agent path: '$($directory.FullName)'."
            }
        }
        $directory = $directory.Parent
    }
}
function Remove-AgentTree {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return }
    # Delete junctions/symlinks themselves; never recurse into their targets.
    if ($item.PSIsContainer) {
        if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            foreach ($child in Get-ChildItem -LiteralPath $Path -Force) { Remove-AgentTree $child.FullName }
        }
        [IO.Directory]::Delete($Path)
    } else {
        if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $item.Attributes = [IO.FileAttributes]::Normal }
        [IO.File]::Delete($Path)
    }
}
function Remove-AgentLinks {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($child in Get-ChildItem -LiteralPath $Path -Force) {
        if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Remove-AgentTree $child.FullName
        } elseif ($child.PSIsContainer) {
            Remove-AgentLinks $child.FullName
        }
    }
}
function Stop-AgentProcesses {
    param([string[]]$Roots)
    $service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        try {
            if ($service.Status -ne 'Stopped') {
                Stop-Service -Name WazuhSvc -ErrorAction Stop
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
            }
        } finally { $service.Dispose() }
    }
    foreach ($process in Get-CimInstance -ClassName Win32_Process) {
        if ([string]::IsNullOrWhiteSpace($process.ExecutablePath)) { continue }
        foreach ($root in $Roots) {
            if ($process.ExecutablePath.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
                break
            }
        }
    }
}
function Uninstall-AgentProduct {
    param([string]$Code)
    if ($Code -notmatch '\A\{[0-9a-fA-F-]{36}\}\z') { throw 'Invalid MSI product code.' }
    $work = Join-Path ([IO.Path]::GetTempPath()) ('wazuh-uninstall-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($work)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', [Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $work -AclObject $acl
    $log = Join-Path $work 'msi.log'
    $process = Start-Process -FilePath msiexec.exe -ArgumentList "/x $Code /qn /norestart /L*v `"$log`"" -Wait -PassThru
    try { $exitCode = $process.ExitCode } finally { $process.Dispose() }
    if ($null -eq $exitCode -or $exitCode -notin @(0,1605,1614,3010)) {
        throw "MSI removal failed (exit $exitCode). Cleanup stopped. Private diagnostic log: '$log'."
    }
    Remove-AgentTree $work
    return ($exitCode -eq 3010)
}
function Remove-AgentService {
    $service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
    if ($null -eq $service) { return $false }
    $service.Dispose()
    & sc.exe delete WazuhSvc | Out-Host
    if ($LASTEXITCODE -notin @(0,1060,1072)) { throw "Could not remove WazuhSvc (exit $LASTEXITCODE)." }
    return $true
}
function Remove-AgentRegistry {
    foreach ($path in @(
        'HKLM:\SOFTWARE\Wazuh, Inc.\Wazuh Agent',
        'HKLM:\SOFTWARE\WOW6432Node\Wazuh, Inc.\Wazuh Agent',
        'HKCU:\SOFTWARE\Wazuh, Inc.\Wazuh Agent',
        'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\wazuh-agent.exe'
    )) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    foreach ($path in @('HKLM:\SOFTWARE\Wazuh, Inc.', 'HKLM:\SOFTWARE\WOW6432Node\Wazuh, Inc.', 'HKCU:\SOFTWARE\Wazuh, Inc.')) {
        if (Test-Path -LiteralPath $path) {
            $key = Get-Item -LiteralPath $path
            try { $empty = $key.SubKeyCount -eq 0 -and $key.ValueCount -eq 0 } finally { $key.Dispose() }
            if ($empty) { Remove-Item -LiteralPath $path -Force }
        }
    }
}
function Invoke-AgentRemoval {
    Assert-RemovalAdministrator
    $products = @(Get-AgentProducts | Sort-Object Code -Unique)
    $roots = @(Get-AgentRemovalRoots $products)
    if (-not $roots.Count) { throw 'Could not determine the agent installation directories.' }
    foreach ($root in $roots) { Assert-AgentRemovalRoot $root }
    Write-Host 'This permanently removes the local Wazuh agent, its configuration, logs, enrollment keys, and saved backups. No backup is made.'
    Write-Host ('Agent directories: ' + ($roots -join ', '))
    foreach ($product in $products) { Write-Host "Installed MSI: Wazuh Agent $($product.Version) ($($product.Code))" }
    if ((Read-Host "Type REMOVE to delete this device's local Wazuh agent") -cne 'REMOVE') {
        Write-Host 'Cancelled. Nothing was removed.'
        return
    }
    Stop-AgentProcesses $roots
    # Native MSI cleanup must not get a chance to follow a junction into other data.
    foreach ($root in $roots) { Remove-AgentLinks $root }
    $reboot = $false
    foreach ($product in $products) { if (Uninstall-AgentProduct $product.Code) { $reboot = $true } }
    if (@(Get-AgentProducts).Count) { throw 'Windows Installer still lists Wazuh Agent. Cleanup stopped; reboot and retry.' }
    if (Remove-AgentService) { $reboot = $true }
    foreach ($root in $roots) { Assert-AgentRemovalRoot $root; Remove-AgentTree $root }
    Remove-AgentRegistry
    Write-Host 'Local Wazuh agent files and identity removed.'
    if ($reboot) { Write-Warning 'Reboot this device before reinstalling; Windows reported a pending restart or service deletion.' }
    Write-Host "Have the server owner remove this device's old manager registration before reusing its name. Then run the installation command from https://shivanshu.ca/wazuh/."
}
if ($MyInvocation.InvocationName -ne '.') { Invoke-AgentRemoval }
