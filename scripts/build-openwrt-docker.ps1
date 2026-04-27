param(
    [ValidateSet("arm64")]
    [string]$Arch = "arm64"
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$out = "dist/sitewatch-linux-$Arch"

docker run --rm `
    -v "${repo}:/src" `
    -w /src `
    -e CGO_ENABLED=0 `
    golang:1.22-alpine `
    sh -lc "/usr/local/go/bin/go test ./... && mkdir -p dist && GOOS=linux GOARCH=$Arch /usr/local/go/bin/go build -trimpath -ldflags '-s -w' -o $out ./cmd/sitewatch && sha256sum $out > $out.sha256"

if ($LASTEXITCODE -ne 0) {
    throw "Docker build failed with exit code $LASTEXITCODE"
}

Write-Host "Built $out"
