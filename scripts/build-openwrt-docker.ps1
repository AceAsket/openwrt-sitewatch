param(
    [ValidateSet("all", "arm64", "armv7", "armv6", "amd64", "386", "mips", "mipsle")]
    [string]$Arch = "all"
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$targets = @(
    @{ Name = "arm64"; GoArch = "arm64"; GoArm = ""; GoMips = "" },
    @{ Name = "armv7"; GoArch = "arm"; GoArm = "7"; GoMips = "" },
    @{ Name = "armv6"; GoArch = "arm"; GoArm = "6"; GoMips = "" },
    @{ Name = "amd64"; GoArch = "amd64"; GoArm = ""; GoMips = "" },
    @{ Name = "386"; GoArch = "386"; GoArm = ""; GoMips = "" },
    @{ Name = "mips"; GoArch = "mips"; GoArm = ""; GoMips = "softfloat" },
    @{ Name = "mipsle"; GoArch = "mipsle"; GoArm = ""; GoMips = "softfloat" }
)

if ($Arch -ne "all") {
    $targets = $targets | Where-Object { $_.Name -eq $Arch }
}

$buildLines = @(
    "/usr/local/go/bin/go test ./...",
    "mkdir -p dist",
    "rm -f dist/sitewatch-linux-* dist/SHA256SUMS"
)

foreach ($target in $targets) {
    $envParts = @("GOOS=linux", "GOARCH=$($target.GoArch)")
    if ($target.GoArm) {
        $envParts += "GOARM=$($target.GoArm)"
    }
    if ($target.GoMips) {
        $envParts += "GOMIPS=$($target.GoMips)"
    }

    $out = "dist/sitewatch-linux-$($target.Name)"
    $buildLines += "$($envParts -join ' ') /usr/local/go/bin/go build -trimpath -ldflags '-s -w' -o $out ./cmd/sitewatch"
    $buildLines += "sha256sum $out >> dist/SHA256SUMS"
}

$buildScript = $buildLines -join " && "

docker run --rm `
    -v "${repo}:/src" `
    -w /src `
    -e CGO_ENABLED=0 `
    golang:1.22-alpine `
    sh -lc $buildScript

if ($LASTEXITCODE -ne 0) {
    throw "Docker build failed with exit code $LASTEXITCODE"
}

Write-Host "Built SiteWatch OpenWrt binaries:"
Get-ChildItem -Path (Join-Path $repo "dist") -Filter "sitewatch-linux-*" | Select-Object -ExpandProperty Name
