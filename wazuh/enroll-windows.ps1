<#
.SYNOPSIS
Install a new Windows agent with the official Wazuh MSI and verified enrollment.
.DESCRIPTION
Use the administrator PowerShell command printed on production by:
  sudo python3 scripts/enrollment.py windows-command

The command downloads this public helper over HTTPS and checks its fingerprint.
This helper downloads the public CA, verifies its expected SHA-256 fingerprint,
downloads the pinned official MSI over HTTPS, and validates its Authenticode
signature. Only then does it ask for the enrollment password. No bundle is needed.
The CA is used only by Wazuh; it is not added to the Windows system trust store.

Uses the official WAZUH_MANAGER, WAZUH_REGISTRATION_SERVER, WAZUH_REGISTRATION_PORT,
WAZUH_REGISTRATION_CA, and WAZUH_AGENT_NAME MSI properties. The password is written
to the documented authd.pass file with SYSTEM/Administrators-only permissions,
never passed through command arguments, installer variables, or verbose logs.
The matching Wazuh agent is installed and started; verify its connected status in
the dashboard afterward. This helper refuses existing agents instead of changing
their configuration or keys; use the existing agent's config/upgrade procedure.

The public CA/helper can be hosted on GitHub Pages. Never publish passwords,
private keys, or old enrollment bundles. If a fingerprint check fails, publish
the exact generated public files and regenerate the command; do not skip checks.
URLs must be HTTPS and return directly without redirects. The computer hostname
becomes the agent name; an existing registration with that name must be removed
explicitly before intentionally enrolling a replacement.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9.-]+\.[a-z0-9-]+$')]
    [string]$Manager,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [uri]$CaUrl,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$CaSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run the generated command in administrator Windows PowerShell.'
}
if ($CaUrl.Scheme -ne 'https' -or $CaUrl.UserInfo -or $CaUrl.Query -or $CaUrl.Fragment -or $CaUrl.Port -ne 443) {
    throw 'Use a direct HTTPS CA URL without credentials, query, or fragment.'
}
if (Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue) {
    throw 'A Wazuh agent is already installed. Manage its existing configuration/upgrade separately.'
}
$agentDirectory = if (${env:ProgramFiles(x86)}) { "${env:ProgramFiles(x86)}\ossec-agent" } else { "$env:ProgramFiles\ossec-agent" }
if (Test-Path -LiteralPath $agentDirectory) {
    throw 'An existing ossec-agent directory was found. Review it before a fresh installation.'
}

function Set-PrivateAcl([string]$Path, [switch]$Directory) {
    if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Refusing an enrollment path that is a filesystem link.'
    }
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = if ($Directory) {
            New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        } else {
            New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
        }
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

$workingDirectory = Join-Path $env:ProgramData 'WazuhEnrollment'
New-Item -ItemType Directory -Path $workingDirectory -Force | Out-Null
Set-PrivateAcl $workingDirectory -Directory
$caPath = Join-Path $workingDirectory 'enrollment-ca.pem'
$msiPath = Join-Path $workingDirectory "wazuh-agent-$Version-1.msi"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$password = $null
$securePassword = $null
try {
    foreach ($path in @($caPath, $msiPath)) {
        if (Test-Path -LiteralPath $path) {
            if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Refusing a download target that is a filesystem link.'
            }
        }
    }
    Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -Uri $CaUrl -OutFile $caPath
    if ((Get-FileHash -LiteralPath $caPath -Algorithm SHA256).Hash -ne $CaSha256) {
        throw 'CA fingerprint mismatch; no enrollment password has been requested or sent.'
    }
    Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version-1.msi" -OutFile $msiPath
    $signature = Get-AuthenticodeSignature -LiteralPath $msiPath
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?i)\bWazuh\b') {
        throw 'The MSI must have a valid Wazuh Authenticode signature.'
    }
    $securePassword = Read-Host 'Wazuh enrollment password' -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($password -cnotmatch '^[A-Za-z0-9_-]{43}$') { throw 'Expected the generated enrollment password from production.' }

    # The official MSI writes the client settings; no custom XML rewriting.
    # Password-file authentication avoids putting the password into MSI logs.
    $arguments = @(
        '/i', "`"$msiPath`"", '/qn', '/norestart',
        "WAZUH_MANAGER=`"$Manager`"", "WAZUH_REGISTRATION_SERVER=`"$Manager`"",
        'WAZUH_REGISTRATION_PORT="1515"', "WAZUH_REGISTRATION_CA=`"$caPath`"",
        "WAZUH_AGENT_NAME=`"$env:COMPUTERNAME`""
    )
    $install = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
    if ($install.ExitCode -notin @(0, 3010)) { throw "MSI failed with exit code $($install.ExitCode)." }
    $passwordPath = Join-Path $agentDirectory 'authd.pass'
    if (-not (Test-Path -LiteralPath $passwordPath)) { New-Item -ItemType File -Path $passwordPath | Out-Null }
    Set-PrivateAcl $passwordPath
    [IO.File]::WriteAllText($passwordPath, $password + "`n", (New-Object Text.UTF8Encoding($false)))
    Start-Service -Name WazuhSvc
    Write-Host 'Wazuh agent installed and started with certificate verification. Confirm it connects in the dashboard.'
} finally {
    $password = $null
    if ($securePassword) { $securePassword.Dispose() }
    if (Test-Path -LiteralPath $msiPath) { Remove-Item -LiteralPath $msiPath }
}
