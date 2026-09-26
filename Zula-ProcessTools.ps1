                                                                            
if (-not ('ZulaLauncher.CommandLine' -as [type])) {
  Add-Type -TypeDefinition 'using System;
using System.Runtime.InteropServices;
namespace ZulaLauncher {
  public static class CommandLine {
    [DllImport("shell32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
    public static string[] Parse(string value) {
      if (String.IsNullOrWhiteSpace(value)) return new string[0];
      int count; IntPtr memory=CommandLineToArgvW(value, out count);
      if(memory==IntPtr.Zero) return new string[0];
      try { var args=new string[count]; for(int i=0;i<count;i++) args[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(memory,i*IntPtr.Size)); return args; }
      finally { LocalFree(memory); }
    }
  }
}'
}
function Get-ZulaGameExecutable([string]$Workspace) {
  if (-not [string]::IsNullOrWhiteSpace($env:ZULA_GAME_DIR)) {
    if (-not [System.IO.Path]::IsPathRooted($env:ZULA_GAME_DIR) -or $env:ZULA_GAME_DIR -match '[\r\n]') { throw 'Gecersiz oyun klasoru.' }
    return [System.IO.Path]::GetFullPath((Join-Path $env:ZULA_GAME_DIR 'zula.exe'))
  }
  $source=[System.IO.File]::ReadAllText((Join-Path $Workspace 'tools\frida_play_connect.py'))
  $match=[regex]::Match($source,'(?m)^GAME_DIR\s*=\s*r"([^"\r\n]+)"\s*$')
  if (-not $match.Success) { throw 'frida_play_connect.py GAME_DIR ayari okunamadi; genis surec temizligi yapilmadi.' }
  return [System.IO.Path]::GetFullPath((Join-Path $match.Groups[1].Value 'zula.exe'))
}
function Select-ZulaOwnedProcess([object[]]$Processes,[string]$Workspace,[string]$GameExecutable,[switch]$ClientOnly) {
  $root=[System.IO.Path]::GetFullPath($Workspace)
  $clientScript=Join-Path $root 'tools\frida_play_connect.py'
  foreach ($process in $Processes) {
    if ($process.Name -ieq 'zula.exe') {
      if ($process.ExecutablePath -and [string]::Equals($process.ExecutablePath,$GameExecutable,[System.StringComparison]::OrdinalIgnoreCase)) { $process }
      continue
    }
    if ($process.Name -notmatch '^python(?:\d+(?:\.\d+)*)?\.exe$') { continue }
    $argv=[ZulaLauncher.CommandLine]::Parse([string]$process.CommandLine)
    $scriptIndex=1
    if ($argv.Length -gt 1 -and $argv[1] -eq '-u') { $scriptIndex=2 }
    if ($argv.Length -le $scriptIndex -or $argv[$scriptIndex] -notmatch '^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+\\)') { continue }
    try { $script=[System.IO.Path]::GetFullPath($argv[$scriptIndex]) } catch { continue }
    if ($script -ieq $clientScript) { $process }
  }
}
function Stop-ZulaOwnedProcesses([string]$Workspace,[string]$GameExecutable,[switch]$ClientOnly) {
  $owned=@(Select-ZulaOwnedProcess -Processes @(Get-CimInstance Win32_Process) -Workspace $Workspace -GameExecutable $GameExecutable -ClientOnly:$ClientOnly)
  foreach ($process in ($owned | Sort-Object @{Expression={if($_.Name -ieq 'zula.exe'){0}else{1}}})) {
                                                                           
                                                                             
    $handle=$null
    try {
      $handle=[System.Diagnostics.Process]::GetProcessById([int]$process.ProcessId)
      $null=$handle.Handle
      $current=Get-CimInstance Win32_Process -Filter ("ProcessId = "+[int]$process.ProcessId) -ErrorAction SilentlyContinue
      if ($null -eq $current -or $current.CreationDate -ne $process.CreationDate) { continue }
      if (@(Select-ZulaOwnedProcess -Processes @($current) -Workspace $Workspace -GameExecutable $GameExecutable -ClientOnly:$ClientOnly).Count -eq 1 -and -not $handle.HasExited) {
        $handle.Kill();$handle.WaitForExit(2000) | Out-Null
        Write-Host ('[surec] Kapatildi: '+$current.Name+' PID '+$current.ProcessId)
      }
    } catch {
      if ($null -ne $handle -and -not $handle.HasExited) { throw }
    } finally { if ($null -ne $handle) { $handle.Dispose() } }
  }
}
