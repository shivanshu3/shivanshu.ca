# One-time Windows agent installation. Passwords never enter process arguments.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$BaseUrl = 'https://shivanshu.ca/wazuh'

function Get-VerifiedDownload {
    param([string]$Url, [string]$Path)
    if ($Url -notmatch '\Ahttps://(?:shivanshu\.ca/wazuh/|packages\.wazuh\.com/4\.x/)') { throw 'Unexpected download origin.' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 300 -Uri $Url -OutFile $Path
}
function Assert-Hash {
    param([string]$Path, [string]$Expected, [string]$Algorithm)
    if ((Get-FileHash -LiteralPath $Path -Algorithm $Algorithm).Hash -ine $Expected) { throw "$Algorithm verification failed." }
}
function Assert-NoAgentIdentity {
    param([string[]]$Roots)
    foreach ($root in $Roots) {
        foreach ($name in @('client.keys', 'client.keys.save')) {
            $identity = Join-Path $root $name
            if ((Test-Path -LiteralPath $identity) -and (Get-Item -LiteralPath $identity).Length -gt 0) {
                throw "An enrollment identity exists at '$identity'. Enrollment was not attempted. Preserve that identity or explicitly move the old agent files aside before a fresh enrollment."
            }
        }
    }
}
function Wait-EnrollmentProcess {
    param($Process, [int]$TimeoutMilliseconds = 45000)
    try {
        # Windows PowerShell can otherwise return null ExitCode after Start-Process.
        # https://github.com/PowerShell/PowerShell/issues/5421
        $null = $Process.Handle
        if (-not $Process.WaitForExit($TimeoutMilliseconds)) {
            $Process.Kill()
            $Process.WaitForExit()
            throw 'Enrollment timed out. Preserve any client.keys file and inspect ossec.log before retrying.'
        }
        $Process.WaitForExit()
        $exitCode = $Process.ExitCode
        if ($null -eq $exitCode) {
            throw 'Could not read the enrollment exit code. Preserve client.keys and check ossec.log; enrollment may have succeeded.'
        }
        return $exitCode
    } finally { $Process.Dispose() }
}
function Assert-Certificate {
    param([string]$Path, [string]$Expected, [string]$Manager)
    $pem = [IO.File]::ReadAllText($Path)
    if ($pem -notmatch '\A\s*-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*\z') { throw 'Expected exactly one public certificate.' }
    $der = [Convert]::FromBase64String(($Matches[1] -replace '\s', ''))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($der))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    if ($actual -ine $Expected) { throw 'Enrollment certificate fingerprint mismatch.' }
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$der)
    try {
        $dnsName = $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
        if ($dnsName -ine $Manager -or $certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $certificate.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow.AddDays(1)) {
            throw 'Enrollment certificate hostname or validity check failed.'
        }
    } finally { $certificate.Dispose() }
}
function New-PrivateFileSecurity {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl.SetOwner($admins)
    foreach ($sid in @($admins, $system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
    }
    return $acl
}
function Write-EnrollmentPassword {
    param([string]$Path, [Security.SecureString]$Password)
    if (Test-Path -LiteralPath $Path) { throw 'An enrollment password file already exists; it was not overwritten.' }
    $acl = New-PrivateFileSecurity
    $stream = $null
    $pointer = [IntPtr]::Zero
    $plain = $null
    $created = $false
    $complete = $false
    try {
        # Set the non-inherited SYSTEM/Administrators DACL at file creation.
        if ($PSVersionTable.PSEdition -eq 'Desktop') {
            $stream = [IO.File]::Create($Path, 4096, [IO.FileOptions]::None, $acl)
        } else {
            $stream = [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($Path), [IO.FileMode]::CreateNew,
                [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $acl)
        }
        $created = $true
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        if ([string]::IsNullOrEmpty($plain) -or $plain.Length -gt 1024 -or $plain -match '[\r\n\x00]') { throw 'Invalid enrollment password.' }
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($plain + "`n")
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
        $complete = $true
    } finally {
        if ($stream) { $stream.Dispose() }
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        $plain = $null
        if ($created -and -not $complete) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue }
    }
}
function Set-AgentConfiguration {
    param([string]$Root, [string]$Manager, [string]$AgentName)
    $path = Join-Path $Root 'ossec.conf'
    $text = [IO.File]::ReadAllText($path) -replace '\A\s*<\?xml[^>]*\?>', ''
    $document = [Xml.XmlDocument]::new()
    $document.PreserveWhitespace = $true
    $document.LoadXml('<root>' + $text + '</root>')
    $clients = $document.SelectNodes('/root/ossec_config/client')
    if ($clients.Count -ne 1) { throw 'Unexpected official agent configuration.' }
    $client = $clients[0]
    foreach ($entry in @($client.SelectNodes('server|enrollment'))) { [void]$client.RemoveChild($entry) }
    $server = $document.CreateElement('server')
    foreach ($entry in @(@('address',$Manager), @('port','1514'), @('protocol','tcp'))) {
        $element = $document.CreateElement($entry[0]); $element.InnerText = $entry[1]; [void]$server.AppendChild($element)
    }
    [void]$client.AppendChild($server)
    $enrollment = $document.CreateElement('enrollment')
    $disabledEnrollment = $document.CreateElement('enabled'); $disabledEnrollment.InnerText = 'no'
    [void]$enrollment.AppendChild($disabledEnrollment); [void]$client.AppendChild($enrollment)
    foreach ($entry in @($document.SelectNodes('/root/ossec_config/active-response'))) { [void]$entry.ParentNode.RemoveChild($entry) }
    $response = $document.CreateElement('active-response'); $disabled = $document.CreateElement('disabled'); $disabled.InnerText = 'yes'
    [void]$response.AppendChild($disabled); [void]$document.SelectSingleNode('/root/ossec_config').AppendChild($response)
    [IO.File]::WriteAllText($path, $document.DocumentElement.InnerXml, [Text.UTF8Encoding]::new($false))
    $options = Join-Path $Root 'local_internal_options.conf'
    $lines = if (Test-Path -LiteralPath $options) { [IO.File]::ReadAllLines($options) } else { @() }
    $lines = @($lines | Where-Object { $_ -notmatch '^\s*(logcollector|wazuh_command|sca)\.remote_commands\s*=' })
    [IO.File]::WriteAllLines($options, $lines + @('logcollector.remote_commands=0','wazuh_command.remote_commands=0','sca.remote_commands=0'), [Text.UTF8Encoding]::new($false))
}
function Assert-AgentArchitecture {
    # A 32-bit PowerShell process exposes the host architecture through ARCHITEW6432.
    $architecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
    if ([string]::IsNullOrEmpty($architecture)) { $architecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE') }
    if ($architecture -inotIn @('AMD64', 'ARM64')) { throw 'This Windows helper requires an x86-64 or ARM64 CPU.' }
    if ($architecture -ieq 'ARM64') {
        # The pinned official Windows MSI is Intel/x86; use Windows' built-in emulation.
        Write-Host 'ARM64 detected: the official x86 agent will run through Windows emulation. Verify agent health and event collection on this device after installation.'
    }
}
function Invoke-AgentInstall {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) { throw 'A 64-bit Windows system is required.' }
    Assert-AgentArchitecture
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the installation command in PowerShell as Administrator.' }
    Remove-Item Env:WAZUH_REGISTRATION_PASSWORD -ErrorAction SilentlyContinue
    $roots = @((Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'), (Join-Path $env:ProgramFiles 'ossec-agent')) | Select-Object -Unique
    $work = Join-Path ([IO.Path]::GetTempPath()) ('wazuh-bootstrap-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($work)
    $authFile = $null; $authCreated = $false; $password = $null
    try {
        $manifest = Join-Path $work 'release.json'
        Get-VerifiedDownload "$BaseUrl/release.json" $manifest
        $release = [IO.File]::ReadAllText($manifest) | ConvertFrom-Json
        if ($release.schema -ne 1 -or $release.agent_version -notmatch '\A4\.\d+\.\d+\z' -or $release.manager -notmatch '\A[a-z0-9][a-z0-9.-]*[a-z0-9]\z' -or $release.certificate_sha256 -notmatch '\A[a-f0-9]{64}\z') { throw 'Invalid release metadata.' }
        $manager = [string]$release.manager
        $package = $release.packages.windows
        $packagePattern = '\Ahttps://packages\.wazuh\.com/4\.x/windows/wazuh-agent-' + [Regex]::Escape($release.agent_version) + '-\d+\.msi\z'
        if ($package.sha512 -notmatch '\A[a-f0-9]{128}\z' -or $package.url -notmatch $packagePattern) { throw 'Invalid package metadata.' }
        $ca = Join-Path $work 'certificate.pem'
        Get-VerifiedDownload "$BaseUrl/certificate.pem" $ca
        Assert-Certificate $ca $release.certificate_sha256 $manager
        foreach ($port in @(1514,1515)) {
            $tcp = [Net.Sockets.TcpClient]::new()
            try { $task = $tcp.ConnectAsync($manager, $port); if (-not $task.Wait(8000) -or -not $tcp.Connected) { throw "Cannot reach $manager on TCP $port." } } finally { $tcp.Dispose() }
        }
        Write-Host "Manager: $manager"
        Write-Host "Official agent version: $($release.agent_version)"
        $name = Read-Host "Agent name [$env:COMPUTERNAME]"
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $env:COMPUTERNAME }
        if ($name -notmatch '\A[a-zA-Z0-9_.-]{2,128}\z') { throw 'Invalid agent name.' }
        if ((Read-Host 'Install and enroll this device? [y/N]') -notmatch '\Ay(?:es)?\z') { throw 'Cancelled.' }
        $msi = Join-Path $work 'wazuh-agent.msi'
        Get-VerifiedDownload $package.url $msi
        Assert-Hash $msi $package.sha512 SHA512
        $signature = Get-AuthenticodeSignature -LiteralPath $msi
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -notin @('Wazuh','Wazuh, Inc.','Wazuh, Inc','Wazuh Inc.','Wazuh Inc')) {
            throw 'The official MSI signature or publisher could not be verified.'
        }
        $process = Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru
        if ($process.ExitCode -notin @(0,3010)) { throw "MSI installation failed (exit $($process.ExitCode))." }
        # MSI handles installation state and may restore a saved enrollment key.
        # Protect identities before changing service settings or enrolling again.
        Assert-NoAgentIdentity $roots
        $service = Get-Service -Name WazuhSvc -ErrorAction Stop
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name WazuhSvc -ErrorAction Stop
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
        }
        Set-Service -Name WazuhSvc -StartupType Manual
        $root = @($roots | Where-Object { Test-Path -LiteralPath (Join-Path $_ 'agent-auth.exe') }) | Select-Object -First 1
        if (-not $root) { throw 'Unexpected package layout: agent-auth.exe is missing.' }
        $identity = Join-Path $root 'client.keys'
        $savedCa = Join-Path $root 'enrollment-manager.pem'
        Copy-Item -LiteralPath $ca -Destination $savedCa
        Set-AgentConfiguration $root $manager $name
        $authFile = Join-Path $root 'authd.pass'
        $password = Read-Host 'Enrollment password (hidden)' -AsSecureString
        if (Test-Path -LiteralPath $authFile) { throw 'An enrollment password file already exists; it was not replaced.' }
        Write-EnrollmentPassword $authFile $password
        $authCreated = $true
        $password.Dispose(); $password = $null
        $process = Start-Process -FilePath (Join-Path $root 'agent-auth.exe') -ArgumentList "-m $manager -A $name -v `"$savedCa`"" -PassThru -NoNewWindow
        $exitCode = Wait-EnrollmentProcess $process
        if ($exitCode -ne 0) {
            throw "agent-auth failed (exit $exitCode). The agent remains stopped. See the Wazuh output above and '$root\ossec.log'."
        }
        if (-not (Test-Path -LiteralPath $identity) -or (Get-Item -LiteralPath $identity).Length -eq 0) {
            throw "agent-auth exited successfully but client.keys is missing or empty. The agent remains stopped; inspect '$root\ossec.log'."
        }
        Set-Acl -LiteralPath $identity -AclObject (New-PrivateFileSecurity)
        Remove-Item -LiteralPath $authFile -Force; $authCreated = $false
        Set-Service -Name WazuhSvc -StartupType Automatic
        Start-Service -Name WazuhSvc
        Write-Host "Agent installed and enrolled. Confirm $name is Active in the dashboard."
    } finally {
        if ($password) { $password.Dispose() }
        if ($authCreated -and $authFile) { Remove-Item -LiteralPath $authFile -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
if ($MyInvocation.InvocationName -ne '.') { Invoke-AgentInstall }
