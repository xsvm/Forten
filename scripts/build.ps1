param([switch]$InstallCore)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repo
try {
    go build -trimpath -o dist/forten.exe .
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed.' }

    dotnet publish desktop/Forten.Desktop.csproj -c Release -o dist
    if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed.' }

    if ($InstallCore) {
        & (Join-Path $PSScriptRoot 'install-core.ps1')
    }
}
finally {
    Pop-Location
}
