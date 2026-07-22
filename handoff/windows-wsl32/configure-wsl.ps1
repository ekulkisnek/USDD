$ErrorActionPreference = "Stop"

$configPath = Join-Path $env:USERPROFILE ".wslconfig"
if (Test-Path $configPath) {
    Write-Error "Refusing to overwrite existing $configPath. Merge .wslconfig.example manually."
}

$source = Join-Path $PSScriptRoot ".wslconfig.example"
Copy-Item -LiteralPath $source -Destination $configPath
Write-Host "Installed $configPath"
Write-Host "Run 'wsl --shutdown', then restart Ubuntu."
