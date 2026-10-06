# Build IronVeil Keygen on Windows (PowerShell 5.1 or 7).
# Runs the checks first, then writes the executables and SHA256SUMS.txt to dist\.
#   powershell -ExecutionPolicy Bypass -File .\build.ps1
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$Version = if ($env:VERSION) { $env:VERSION } else { '1.0.0' }
$env:CGO_ENABLED = '0'

function Invoke-Checked([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$exe $($arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

$unformatted = & gofmt -l .
if ($unformatted) { throw "gofmt needed on: $unformatted" }
Invoke-Checked go @('vet', './...')
Invoke-Checked go @('test', '-count=1', './...')

New-Item -ItemType Directory -Force -Path dist | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue dist\IronVeil-Keygen-*.exe, dist\SHA256SUMS.txt

$env:GOOS = 'windows'
foreach ($arch in 'amd64', 'arm64') {
    $env:GOARCH = $arch
    Invoke-Checked go @('build', '-trimpath', '-buildvcs=false',
        '-ldflags', "-s -w -H windowsgui -X main.version=$Version",
        '-o', "dist\IronVeil-Keygen-$Version-windows-$arch.exe", './cmd/ironveil-keygen')
}
Remove-Item Env:GOOS, Env:GOARCH

$lines = Get-ChildItem dist\IronVeil-Keygen-*.exe | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLower(), $_.Name
}
[IO.File]::WriteAllLines((Join-Path $PSScriptRoot 'dist\SHA256SUMS.txt'), $lines)
$lines
