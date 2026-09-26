                                                                               
function Resolve-ZulaServerAddress([string]$Value) {
  if ($Value -cnotmatch '\A(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\z') { throw 'Sunucu adresi noktayla ayrilmis IPv4 olmali.' }
  $parts=@($Value.Split('.') | ForEach-Object { [int]$_ })
  if (@($parts | Where-Object { $_ -gt 255 }).Count -gt 0 -or $parts[0] -eq 0 -or $parts[0] -ge 224) { throw 'Gecerli bir IPv4 sunucu adresi gerekiyor.' }
  return $Value
}

function Resolve-ZulaClientArguments([string[]]$Values,[string]$Workspace) {
  $result=New-Object 'System.Collections.Generic.List[string]'
  $seen=@{}
  for ($index=0;$index -lt $Values.Count;$index++) {
    $name=$Values[$index]
    if ($name -cnotin @('--identity','--schema-output','--parse','--schema','--diagnostics','--server')) { throw ('Bilinmeyen baslatici secenegi: '+$name) }
    if ($seen.ContainsKey($name)) { throw ('Yinelenen baslatici secenegi: '+$name) }
    $seen[$name]=$true;$result.Add($name)
    if ($name -eq '--server') {
      $index++
      if ($index -ge $Values.Count) { throw ($name+' icin IPv4 adresi gerekiyor.') }
      $result.Add((Resolve-ZulaServerAddress $Values[$index]));continue
    }
    if ($name -in @('--identity','--schema-output')) {
      $index++
      if ($index -ge $Values.Count -or [string]::IsNullOrWhiteSpace($Values[$index]) -or $Values[$index].StartsWith('--')) { throw ($name+' icin dosya yolu gerekiyor.') }
      $value=$Values[$index]
      if ($value.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0 -or $value -match '[\r\n]') { throw 'Gecersiz dosya yolu.' }
      if (-not [System.IO.Path]::IsPathRooted($value)) { $value=Join-Path $Workspace $value }
      $value=[System.IO.Path]::GetFullPath($value)
      if ($name -eq '--identity') {
        if (-not (Test-Path -LiteralPath $value -PathType Leaf)) { throw ('Kimlik dosyasi yok: '+$value) }
        $file=Get-Item -LiteralPath $value
        if ($file.Length -gt 65536) { throw 'Kimlik dosyasi boyut sinirini asti.' }
        try { $identity=[System.IO.File]::ReadAllText($value) | ConvertFrom-Json } catch { throw 'Kimlik dosyasi gecerli JSON degil.' }
        if ($identity.Token -isnot [string] -or $identity.Token -cnotmatch '\A[\x21-\x7e]{32,128}\z') { throw 'Kimlik dosyasinda gecerli oyuncu bileti yok.' }
      }
      $result.Add($value)
    }
  }
  if ($seen.ContainsKey('--schema-output') -and -not $seen.ContainsKey('--schema')) { throw '--schema-output icin --schema gerekiyor.' }
  return ,$result.ToArray()
}

function New-ZulaElevationCommand([string]$LauncherPath,[hashtable]$Options,[string]$OutputFile) {
                                                                              
                                                                           
  $payload=@{script=$LauncherPath;options=$Options;output=$OutputFile} | ConvertTo-Json -Compress -Depth 5
  $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
  $command='$ErrorActionPreference="Stop"; $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("'+$encoded+'")) | ConvertFrom-Json; $o=@{}; $p.options.psobject.Properties | ForEach-Object { $o[$_.Name]=$_.Value }; & $p.script @o *>> $p.output; exit $LASTEXITCODE'
  return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
}

function Invoke-ZulaClientProcess([string]$Executable,[string[]]$Arguments,[ref]$ExitCode) {
                                                                           
                                                                        
  $previousPreference=$ErrorActionPreference
  $previousNativeExit=$global:LASTEXITCODE
  try {
    $ErrorActionPreference='Continue'
    $global:LASTEXITCODE=$null
    & $Executable @Arguments
    $ExitCode.Value=if($null -eq $global:LASTEXITCODE){1}else{$global:LASTEXITCODE}
  } finally { $ErrorActionPreference=$previousPreference;$global:LASTEXITCODE=$previousNativeExit }
}

function Invoke-ZulaElevation([string]$LauncherPath,[hashtable]$Options) {
  $logs=Join-Path $Options.Workspace 'logs'
  [System.IO.Directory]::CreateDirectory($logs) | Out-Null
  $output=Join-Path $logs ('launcher-'+[guid]::NewGuid().ToString('N')+'.log')
  [System.IO.File]::WriteAllText($output,'',[Text.Encoding]::Unicode)
  $encoded=New-ZulaElevationCommand -LauncherPath $LauncherPath -Options $Options -OutputFile $output
  $child=$null;$reader=$null
  try {
    $child=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -Verb RunAs -WindowStyle Hidden -PassThru
    $stream=[System.IO.File]::Open($output,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $reader=New-Object System.IO.StreamReader($stream,[Text.Encoding]::Unicode)
    do {
      [Console]::Write($reader.ReadToEnd())
      if ($child.HasExited) { break }
      Start-Sleep -Milliseconds 200
    } while ($true)
    $child.WaitForExit();[Console]::Write($reader.ReadToEnd())
    return $child.ExitCode
  } finally {
    if ($null -ne $reader) { $reader.Dispose() }
    if ($null -ne $child) { $child.Dispose() }
  }
}
