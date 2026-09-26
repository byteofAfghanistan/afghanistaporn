[CmdletBinding()]
param([string]$HostsFile="$env:SystemRoot\System32\drivers\etc\hosts",[switch]$SkipDnsFlush,
  [ValidateRange(1,12)][int]$RetryCount=12,[ValidateRange(0,1000)][int]$RetryDelayMs=300)
$ErrorActionPreference='Stop'
try {
  . (Join-Path $PSScriptRoot 'Zula-HostsTools.ps1')
  Invoke-ZulaHosts -Action Restore -HostsFile $HostsFile -SkipDnsFlush:$SkipDnsFlush -RetryCount $RetryCount -RetryDelayMs $RetryDelayMs
  exit 0
} catch { Write-Host ('[hosts] HATA: '+$_.Exception.Message);exit 1 }
