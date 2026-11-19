$ErrorActionPreference = 'Stop'

$version = 'v1.19.33'
$sha256 = '6ab2180875f9f6fff8b19386d760daec257f66b45f72b3afc650634272fa837a'
$asset = "mihomo-windows-amd64-$version.zip"
$source = "https://github.com/MetaCubeX/mihomo/releases/download/$version/$asset"
$dist = Join-Path (Split-Path -Parent $PSScriptRoot) 'dist'
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("forten-core-" + [guid]::NewGuid().ToString('N'))
$archive = Join-Path $temp $asset
New-Item -Type Directory -Path $temp | Out-Null
try {
    curl.exe --fail --location --silent --show-error --retry 2 --max-time 180 $source -o $archive
    if ($LASTEXITCODE -ne 0) { throw 'Download from the official Mihomo release failed.' }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $sha256) {
        throw 'Mihomo archive checksum did not match the pinned release.'
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $temp
    $cores = @(Get-ChildItem -LiteralPath $temp -Filter 'mihomo*.exe' -File)
    if ($cores.Count -ne 1) { throw 'Unexpected Mihomo release archive contents.' }
    New-Item -Type Directory -Path $dist -Force | Out-Null
    Copy-Item -LiteralPath $cores[0].FullName -Destination (Join-Path $dist 'mihomo.exe') -Force
}
finally {
    $resolvedTemp = (Resolve-Path -LiteralPath $temp).Path
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ($resolvedTemp.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}
