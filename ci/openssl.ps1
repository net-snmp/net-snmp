# Set TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Fetch OpenSSL hashes JSON
$url = "https://slproweb.com/download/win32_openssl_hashes.json"
Write-Host "Fetching OpenSSL installer info from $url"
$data = Invoke-RestMethod -Uri $url

# Filter files for 64-bit non-light EXE installer
$files = $data.files.PSObject.Properties | ForEach-Object { $_.Value }
$filtered = $files | Where-Object {
    $_.bits -eq 64 -and
    $_.arch -eq 'INTEL' -and
    $_.installer -eq 'exe' -and
    -not $_.light
}

# Sort by basever and subver descending to get the latest
$latest = $filtered | Sort-Object { [version]$_.basever }, { $_.subver } -Descending | Select-Object -First 1

if ($null -eq $latest) {
    Write-Error "Failed to find a matching OpenSSL installer."
    exit 1
}

Write-Host "Latest OpenSSL Installer found: $($latest.url)"
Write-Host "Downloading OpenSSL installer..."
Invoke-WebRequest -Uri $latest.url -OutFile "openssl.exe"
