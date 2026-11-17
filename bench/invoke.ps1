# Runs Update-EsxiCertificate.ps1 against the simulator, the way an administrator would:
# the script logs in by itself with -Credential. The simulator takes any credentials and
# has a self-signed certificate, so certificate validation is off for this session only.
param([string] $Tool, [string] $Server = 'vcsa01.example.com', [string] $ToolArgs = '')
Import-Module VMware.VimAutomation.Core -WarningAction SilentlyContinue
Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
$cred = New-Object System.Management.Automation.PSCredential('administrator@vsphere.local', (ConvertTo-SecureString 'bench-only' -AsPlainText -Force))
$global:LASTEXITCODE = 0
Invoke-Expression "& '$Tool' -Server $Server -Credential `$cred $ToolArgs"
Write-Host "exit=$LASTEXITCODE"
