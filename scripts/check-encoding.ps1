param(
    [string[]]$Paths = @(
        "files/www/cgi-bin/sitewatch",
        "files/usr/bin/sitewatch-collect",
        "files/usr/bin/sitewatch-check-url",
        "files/usr/bin/sitewatch-detector",
        "README.md"
    )
)

$ErrorActionPreference = "Stop"
$bad = $false
$mojibakePattern = "(?:[РСВ][\u00A0-\u00BF\u0401-\u040F\u0452-\u045F\u2010-\u2122])|(?:в[\u0402-\u040F\u0452-\u045F\u2010-\u2122])|�"

foreach ($path in $Paths) {
    if (-not (Test-Path -LiteralPath $path)) {
        continue
    }

    $bytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $path))
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-Error "UTF-8 BOM found: $path"
        $bad = $true
    }

    if ($path -like "*/cgi-bin/sitewatch" -or $path -like "*\cgi-bin\sitewatch") {
        $shebang = ($bytes[0..8] | ForEach-Object { $_.ToString("X2") }) -join " "
        if ($shebang -ne "23 21 2F 62 69 6E 2F 61 73") {
            Write-Error "CGI shebang is not the first bytes in ${path}: $shebang"
            $bad = $true
        }
    }

    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $matches = [regex]::Matches($text, $mojibakePattern)
    if ($matches.Count -gt 0) {
        Write-Error "Possible mojibake found in $path"
        $bad = $true
    }
}

if ($bad) {
    exit 1
}

Write-Host "Encoding check passed"
