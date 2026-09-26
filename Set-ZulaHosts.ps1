[CmdletBinding()]
param([string]$HostsFile="$env:SystemRoot\System32\drivers\etc\hosts",[switch]$SkipDnsFlush,
  [ValidateRange(1,12)][int]$RetryCount=12,[ValidateRange(0,1000)][int]$RetryDelayMs=300,[string]$ServerAddress='127.0.0.1')
$ErrorActionPreference='Stop'
try {
  . (Join-Path $PSScriptRoot 'Zula-HostsTools.ps1')
  Invoke-ZulaHosts -Action Set -HostsFile $HostsFile -SkipDnsFlush:$SkipDnsFlush -RetryCount $RetryCount -RetryDelayMs $RetryDelayMs -ServerAddress $ServerAddress
  exit 0
} catch { Write-Host ('[hosts] HATA: '+$_.Exception.Message);exit 1 }
