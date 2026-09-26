                                                                          
                                                                               
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'Zula-Launcher.ps1') -Action Start -Workspace (Split-Path -Parent $PSScriptRoot) -ClientArguments @($args)
exit $LASTEXITCODE
