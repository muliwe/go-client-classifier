# Integration test script for Windows (PowerShell)
# Usage: .\integration_test.ps1 [base_url]

param(
    [string]$BaseUrl = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Integration Tests ===" -ForegroundColor Cyan
Write-Host "Base URL: $BaseUrl" -ForegroundColor Gray
Write-Host ""

$passed = 0
$failed = 0

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [string]$ExpectedStatus,
        [string]$ExpectedContent
    )
    
    Write-Host -NoNewline "Testing $Name... "
    
    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop
        $statusCode = $response.StatusCode
        $body = $response.Content
        
        if ($statusCode -ne $ExpectedStatus) {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "  Expected status: $ExpectedStatus, got: $statusCode" -ForegroundColor Yellow
            return $false
        }
        
        if ($ExpectedContent -and ($body -notlike "*$ExpectedContent*")) {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "  Expected content to contain: $ExpectedContent" -ForegroundColor Yellow
            Write-Host "  Got: $body" -ForegroundColor Yellow
            return $false
        }
        
        Write-Host "PASSED" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "  Error: $_" -ForegroundColor Yellow
        return $false
    }
}

function Test-CurlEndpoint {
    param(
        [string]$Name,
        [string]$Url,
        [string]$ExpectedContent
    )
    
    Write-Host -NoNewline "Testing $Name (curl)... "
    
    try {
        $curlOutput = curl.exe -s -w "`n%{http_code}" $Url 2>$null
        $lines = $curlOutput -split "`n"
        $statusCode = $lines[-1]
        $body = ($lines[0..($lines.Length - 2)]) -join "`n"
        
        if ($statusCode -ne "200") {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "  Expected status: 200, got: $statusCode" -ForegroundColor Yellow
            return $false
        }
        
        if ($ExpectedContent -and ($body -notlike "*$ExpectedContent*")) {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Host "  Expected content to contain: $ExpectedContent" -ForegroundColor Yellow
            Write-Host "  Got: $body" -ForegroundColor Yellow
            return $false
        }
        
        Write-Host "PASSED" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host "  Error: $_" -ForegroundColor Yellow
        return $false
    }
}

# Test 1: Health endpoint
if (Test-Endpoint -Name "Health endpoint (GET /health)" -Url "$BaseUrl/health" -ExpectedStatus 200 -ExpectedContent '"status":"ok"') {
    $passed++
} else {
    $failed++
}

# Test 2: Classify endpoint (root)
if (Test-Endpoint -Name "Classify endpoint (GET /)" -Url "$BaseUrl/" -ExpectedStatus 200 -ExpectedContent '"classification"') {
    $passed++
} else {
    $failed++
}

# Test 3: Debug endpoint
if (Test-Endpoint -Name "Debug endpoint (GET /debug)" -Url "$BaseUrl/debug" -ExpectedStatus 200 -ExpectedContent '"fingerprint"') {
    $passed++
} else {
    $failed++
}

# Test 4: Classification using real curl (should detect as bot)
if (Test-CurlEndpoint -Name "Curl detection (should be bot)" -Url "$BaseUrl/" -ExpectedContent '"classification":"bot"') {
    $passed++
} else {
    $failed++
}

# Test 5: Health via curl
if (Test-CurlEndpoint -Name "Health via curl" -Url "$BaseUrl/health" -ExpectedContent '"status":"ok"') {
    $passed++
} else {
    $failed++
}

# Summary
Write-Host ""
Write-Host "=== Results ===" -ForegroundColor Cyan
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Gray" })

if ($failed -gt 0) {
    exit 1
}
exit 0
