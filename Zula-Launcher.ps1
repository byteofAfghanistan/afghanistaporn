[CmdletBinding()]
param([ValidateSet('Start','Stop','StopClient')][string]$Action='Start',
  [string]$Workspace=(Split-Path -Parent $PSScriptRoot),[ValidateRange(1,120)][int]$ReadyTimeoutSeconds=60,
  [string[]]$ClientArguments=@())
$ErrorActionPreference='Stop'
$launchReady=$false
try {
  $Workspace=(Resolve-Path -LiteralPath $Workspace).Path
  . (Join-Path $PSScriptRoot 'Zula-LaunchArguments.ps1')
  $ClientArguments=Resolve-ZulaClientArguments -Values $ClientArguments -Workspace $Workspace
  if ($Action -ne 'Start' -and $ClientArguments.Count -gt 0) { throw 'Durdurma komutu oyun secenegi kabul etmez.' }
  $serverAddress=$null
  if ($Action -eq 'Start') {
    $serverIndex=[Array]::IndexOf($ClientArguments,'--server')
    if ($serverIndex -lt 0) { throw 'Uzak istemci icin --server IPv4 gerekiyor.' }
    $serverAddress=$ClientArguments[$serverIndex+1]
  }
  $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '[*] Yonetici izni gerekiyor; dogrulanan secenekler korunarak devam ediliyor...'
    $code=Invoke-ZulaElevation -LauncherPath $PSCommandPath -Options @{Action=$Action;Workspace=$Workspace;ReadyTimeoutSeconds=$ReadyTimeoutSeconds;ClientArguments=$ClientArguments}
    exit $code
  }
  Set-Location -LiteralPath $Workspace
  . (Join-Path $PSScriptRoot 'Zula-ProcessTools.ps1')
  $gameExecutable=Get-ZulaGameExecutable -Workspace $Workspace
  if ($Action -in @('Stop','StopClient')) {
    Stop-ZulaOwnedProcesses -Workspace $Workspace -GameExecutable $gameExecutable -ClientOnly
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Restore-ZulaHosts.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Surecler kapatildi ancak hosts geri alinamadi.' }
    Write-Host '[tamam] Bu kurulumun istemcisi ve hosts yonlendirmesi kapatildi.'
    exit 0
  }
  $node=(Get-Command node.exe -ErrorAction Stop).Source
  $python=(Get-Command python.exe -ErrorAction Stop).Source
  if (-not (Test-Path -LiteralPath $gameExecutable -PathType Leaf)) { throw ('Oyun dosyasi yok: '+$gameExecutable) }
  $certificateFile=Join-Path $Workspace 'certs\server.crt'
  if (-not (Test-Path -LiteralPath $certificateFile -PathType Leaf)) { throw 'certs/server.crt bulunamadi.' }
                                                                          
                                                                            
  $artResult=& $python (Join-Path $PSScriptRoot 'install_source_art.py') --game-dir (Split-Path -Parent $gameExecutable)
  if ($LASTEXITCODE -ne 0) { throw 'Kaynak esya gorseli dogrulanamadi; oyun baslatilmadi.' }
  $null=$artResult | ConvertFrom-Json
                                                                           
                                                                              
  $textureResult=& $python (Join-Path $PSScriptRoot 'install_source_textures.py') --game-dir (Split-Path -Parent $gameExecutable)
  if ($LASTEXITCODE -ne 0) { throw 'Kaynak silah dokusu dogrulanamadi; oyun baslatilmadi.' }
  $null=$textureResult | ConvertFrom-Json
  Write-Host ('[*] Yalniz istemci: '+$serverAddress+' hazirligi bekleniyor...')
  & $node (Join-Path $PSScriptRoot 'check_remote_zula_ready.js') $serverAddress $certificateFile ([string]$ReadyTimeoutSeconds)
  if ($LASTEXITCODE -ne 0) { throw 'Uzak sunucu dogrulanamadi; oyun baslatilmadi ve hosts degistirilmedi.' }
  Stop-ZulaOwnedProcesses -Workspace $Workspace -GameExecutable $gameExecutable -ClientOnly
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Set-ZulaHosts.ps1') -ServerAddress $serverAddress
  if ($LASTEXITCODE -ne 0) { throw 'hosts yonlendirmesi dogrulanamadi; oyun baslatilmadi.' }
  $launchReady=$true
  Write-Host '[*] Uzak istemci baslatiliyor.'
  $clientExit=1
                                                                             
                                                                       
  Invoke-ZulaClientProcess -Executable $python -Arguments (@('-u',(Join-Path $PSScriptRoot 'frida_play_connect.py'))+$ClientArguments+@('--emulator')) -ExitCode ([ref]$clientExit)
  if ($clientExit -ne 0) { Write-Host ('[HATA] Oyun baslaticisi cikis kodu: '+$clientExit) }
  exit $clientExit
} catch {
  Write-Host ('[HATA] '+$_.Exception.Message)
  exit 1
}
