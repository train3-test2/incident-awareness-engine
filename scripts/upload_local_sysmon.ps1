[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SysmonJsonlPath,
    [string]$EnvironmentFile = ".env.localstack"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $EnvironmentFile -PathType Leaf)) {
    throw "LocalStack environment file was not found: $EnvironmentFile"
}

$settings = @{}
Get-Content -LiteralPath $EnvironmentFile | ForEach-Object {
    if ($_ -match '^\s*([^#\s][^=]*)=(.*)$') {
        $settings[$matches[1].Trim()] = $matches[2].Trim()
    }
}

$source = (Resolve-Path -LiteralPath $SysmonJsonlPath).Path
$bucket = $settings.LOCAL_FIRST_CYCLE_BUCKET
$port = $settings.LOCALSTACK_PORT
if ([string]::IsNullOrWhiteSpace($bucket) -or [string]::IsNullOrWhiteSpace($port)) {
    throw "LOCAL_FIRST_CYCLE_BUCKET and LOCALSTACK_PORT must be set in $EnvironmentFile"
}

$ingestId = "ING-$([guid]::NewGuid().ToString())"
$key = "incoming/first-cycle/sysmon/$ingestId/sysmon.jsonl"
$endpoint = "http://127.0.0.1:$port"

$previousAccessKey = $env:AWS_ACCESS_KEY_ID
$previousSecretKey = $env:AWS_SECRET_ACCESS_KEY
$previousRegion = $env:AWS_DEFAULT_REGION
$env:AWS_ACCESS_KEY_ID = "test"
$env:AWS_SECRET_ACCESS_KEY = "test"
$env:AWS_DEFAULT_REGION = $settings.LOCAL_AWS_REGION

try {
    aws --endpoint-url $endpoint s3 cp $source "s3://$bucket/$key"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to upload local First Cycle input (aws exit code $LASTEXITCODE)"
    }

    aws --endpoint-url $endpoint s3api head-object --bucket $bucket --key $key | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to verify uploaded local First Cycle input (aws exit code $LASTEXITCODE)"
    }
} finally {
    $env:AWS_ACCESS_KEY_ID = $previousAccessKey
    $env:AWS_SECRET_ACCESS_KEY = $previousSecretKey
    $env:AWS_DEFAULT_REGION = $previousRegion
}

Write-Output "Uploaded local First Cycle input: s3://$bucket/$key"
