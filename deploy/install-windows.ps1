<#
  Installs s1wazuh as a Windows service. Run elevated, from the extracted release folder.
  The Wazuh agent on the same host then ships the NDJSON files (see README).
  Usage: .\deploy\install-windows.ps1 -BaseUrl https://TENANT.sentinelone.net -ApiToken (Read-Host -AsSecureString)
#>
param(
  [Parameter(Mandatory)] [string] $BaseUrl,
  [Parameter(Mandatory)] [securestring] $ApiToken,
  [string] $InstallDir = 'C:\Program Files\s1wazuh',
  [string] $OutputDir  = 'C:\Program Files (x86)\ossec-agent\sentinelone',
  [string] $StateDir   = 'C:\ProgramData\s1wazuh'
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $InstallDir, $OutputDir, $StateDir | Out-Null
Copy-Item "$PSScriptRoot\..\s1wazuh.exe", "$PSScriptRoot\..\appsettings.json" $InstallDir -Force

$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiToken))
if (Get-Service s1wazuh -ErrorAction SilentlyContinue) { Stop-Service s1wazuh; sc.exe delete s1wazuh | Out-Null; Start-Sleep 2 }
New-Service -Name s1wazuh -BinaryPathName "`"$InstallDir\s1wazuh.exe`"" -DisplayName 'SentinelOne to Wazuh collector' -StartupType Automatic | Out-Null

# Service-scoped environment (not visible to other users/processes): config + secret.
$env = @("SentinelOne__BaseUrl=$BaseUrl", "SentinelOne__ApiToken=$plain",
        "Output__Directory=$OutputDir", "State__Directory=$StateDir")
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\s1wazuh" -Name Environment -Type MultiString -Value $env
sc.exe failure s1wazuh reset= 86400 actions= restart/10000/restart/10000/restart/60000 | Out-Null
Start-Service s1wazuh
Get-Service s1wazuh
