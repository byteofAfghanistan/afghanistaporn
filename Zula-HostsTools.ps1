                                                                           
function Read-ZulaHostLines([string]$Path,[int]$RetryCount=12,[int]$RetryDelayMs=300) {
  for ($attempt=0;$attempt -lt $RetryCount;$attempt++) {
    try { return ,([System.IO.File]::ReadAllLines($Path)) }
    catch { if ($attempt+1 -ge $RetryCount) { throw };Start-Sleep -Milliseconds $RetryDelayMs }
  }
}
function Invoke-ZulaHosts([ValidateSet('Set','Restore')][string]$Action,[string]$HostsFile,[switch]$SkipDnsFlush,
  [int]$RetryCount=12,[int]$RetryDelayMs=300,[string]$ServerAddress='127.0.0.1') {
  . (Join-Path $PSScriptRoot 'Zula-LaunchArguments.ps1')
  $ServerAddress=Resolve-ZulaServerAddress $ServerAddress
  $marker='# ZULA-MITM';$managed=[regex]::Escape($marker)+'\s*$'
  $domains=@('apitest.zulaoyun.com','scs.zulaoyun.com','api.zulaoyun.com','zulaoyun.com','www.zulaoyun.com')
  $existing=Read-ZulaHostLines -Path $HostsFile -RetryCount $RetryCount -RetryDelayMs $RetryDelayMs
  $kept=@($existing | Where-Object { $_ -notmatch $managed })
  if ($Action -eq 'Set') {
    foreach ($line in $kept) {
      $tokens=@(($line -split '#',2)[0].Trim() -split '\s+')
      if ($tokens.Count -lt 2) { continue }
      foreach ($domain in $tokens[1..($tokens.Count-1)]) {
        if ($domains -contains $domain -and $tokens[0] -ne $ServerAddress) {
          throw ('hosts dosyasinda yonetilmeyen cakisan kayit var: '+$domain+'. Mevcut satir degistirilmedi.')
        }
      }
    }
    $lines=@($kept)+@($domains | ForEach-Object { "$ServerAddress`t$_`t$marker" })
  } else { $lines=@($kept) }
  $file=Get-Item -LiteralPath $HostsFile -Force -ErrorAction Stop;$wasReadOnly=$file.IsReadOnly
  try {
    if ($wasReadOnly) { $file.IsReadOnly=$false }
    for ($attempt=0;$attempt -lt $RetryCount;$attempt++) {
      try { [System.IO.File]::WriteAllLines($HostsFile,[string[]]$lines,(New-Object System.Text.UTF8Encoding($false)));break }
      catch { if ($attempt+1 -ge $RetryCount) { throw };Start-Sleep -Milliseconds $RetryDelayMs }
    }
    $actual=Read-ZulaHostLines -Path $HostsFile -RetryCount $RetryCount -RetryDelayMs $RetryDelayMs
    if (-not [string]::Equals(($actual -join "`n"),($lines -join "`n"),[System.StringComparison]::Ordinal)) { throw 'hosts yazildi ancak icerik dogrulanamadi.' }
    if (-not $SkipDnsFlush) {
      & ipconfig.exe /flushdns | Out-Null
      if ($LASTEXITCODE -ne 0) { throw 'hosts yazildi ancak DNS onbellegi temizlenemedi.' }
    }
  } finally { if ($wasReadOnly) { (Get-Item -LiteralPath $HostsFile -Force).IsReadOnly=$true } }
  Write-Host $(if($Action -eq 'Set'){'[hosts] Bes yonlendirme dogrulandi: '+$ServerAddress}else{'[hosts] Yalniz ZULA-MITM yonlendirmeleri kaldirildi ve dogrulandi.'})
}
