<#
.SYNOPSIS
Move endpoints from one Nebula console to another and monitor job status.

.DESCRIPTION
- Creates migration jobs using command.engine.changeaccounttoken.
- Polls each job until it reaches a terminal state.
- Writes a JSON report with created jobs and final states.

.RUN
pwsh ./move-neb-to-neb-with-status.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Import-DotEnv {
    param(
        [string]$Path = ".env"
    )

    if (-not (Test-Path -Path $Path)) {
        return
    }

    Get-Content -Path $Path | ForEach-Object {
        $line = $_.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { return }
        if ($line.StartsWith("#")) { return }
        if (-not $line.Contains("=")) { return }

        $parts = $line.Split("=", 2)
        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        if ([string]::IsNullOrWhiteSpace($key)) { return }

        # Remove wrapping quotes if present.
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }

        [System.Environment]::SetEnvironmentVariable($key, $value)
    }
}

function Get-EnvOrDefault {
    param(
        [string]$Name,
        [string]$DefaultValue = ""
    )

    $val = [System.Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($val)) {
        return $DefaultValue
    }
    return $val
}

Import-DotEnv -Path ".env"

###############################################################
# CONFIGURATION
###############################################################

# SOURCE console credentials (origin)
$OriginClientID = Get-EnvOrDefault -Name "SOURCE_CLIENT_ID" -DefaultValue ""
$OriginClientSecret = Get-EnvOrDefault -Name "SOURCE_CLIENT_SECRET" -DefaultValue ""
$OriginAccountID = Get-EnvOrDefault -Name "SOURCE_ACCOUNT_ID" -DefaultValue ""

# Destination account token (NOT destination account ID)
$DestinationAccountToken = Get-EnvOrDefault -Name "DESTINATION_ACCOUNT_TOKEN" -DefaultValue ""

# Machine IDs to migrate (fill with values from your inventory script)
$machine_ids = @(
    # "0014f412-9310-4f06-a0a6-35e0ddc46865"
)

# Optional: comma-separated machine IDs from .env (MIGRATION_MACHINE_IDS=id1,id2)
$machineIdsFromEnv = Get-EnvOrDefault -Name "MIGRATION_MACHINE_IDS" -DefaultValue ""
if (-not [string]::IsNullOrWhiteSpace($machineIdsFromEnv)) {
    $machine_ids = $machineIdsFromEnv.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
}

# API settings
$ApiBaseUrl = Get-EnvOrDefault -Name "SOURCE_API_BASE_URL" -DefaultValue "https://api.malwarebytes.com"
$TokenUrl = Get-EnvOrDefault -Name "SOURCE_TOKEN_URL" -DefaultValue "https://api.malwarebytes.com/oauth2/token"
$JobsPath = Get-EnvOrDefault -Name "TARGET_MOVE_ENDPOINT_PATH" -DefaultValue "/nebula/v1/jobs"
$Scope = Get-EnvOrDefault -Name "SOURCE_SCOPE" -DefaultValue "read write execute"

# Monitoring settings
$PollIntervalSeconds = [int](Get-EnvOrDefault -Name "POLL_INTERVAL_SECONDS" -DefaultValue "5")
$MaxPollAttempts = [int](Get-EnvOrDefault -Name "MAX_POLL_ATTEMPTS" -DefaultValue "60")
$ReportFile = Get-EnvOrDefault -Name "MIGRATION_REPORT_FILE" -DefaultValue "./migration-report.json"

###############################################################
# FUNCTIONS
###############################################################

function Get-Token {
    param (
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$TokenEndpoint,
        [string]$TokenScope
    )

    $basicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${ClientId}:${ClientSecret}"))
    $headers = @{
        "Content-Type" = "application/x-www-form-urlencoded"
        "Authorization" = "Basic $basicAuth"
    }

    $body = @{
        "grant_type" = "client_credentials"
        "scope" = $TokenScope
    }

    $response = Invoke-RestMethod -Method Post -Uri $TokenEndpoint -Headers $headers -Body $body
    if (-not $response.access_token) {
        throw "Token response did not include access_token"
    }
    return $response.access_token
}

function New-MigrationJob {
    param (
        [string]$AccessToken,
        [string]$BaseUrl,
        [string]$Path,
        [string]$AccountId,
        [string]$MachineId,
        [string]$AccountToken
    )

    $uri = "{0}{1}" -f $BaseUrl.TrimEnd('/'), $Path
    $headers = @{
        "Content-Type" = "application/json"
        "Accept" = "application/json"
        "Authorization" = "Bearer $AccessToken"
        "accountid" = $AccountId
    }

    $body = @{
        "command" = "command.engine.changeaccounttoken"
        "machine_ids" = @($MachineId)
        "data" = @{
            "account_token" = $AccountToken
        }
    } | ConvertTo-Json -Depth 6

    return Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body
}

function Get-JobStatus {
    param (
        [string]$AccessToken,
        [string]$BaseUrl,
        [string]$AccountId,
        [string]$JobId
    )

    $uri = "{0}/nebula/v1/jobs/{1}" -f $BaseUrl.TrimEnd('/'), $JobId
    $headers = @{
        "Accept" = "application/json"
        "Authorization" = "Bearer $AccessToken"
        "accountid" = $AccountId
    }

    return Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
}

function Wait-JobTerminalState {
    param (
        [string]$AccessToken,
        [string]$BaseUrl,
        [string]$AccountId,
        [string]$JobId,
        [int]$IntervalSeconds,
        [int]$MaxAttempts
    )

    $terminal = @("COMPLETED", "FAILED", "CANCELLED", "EXPIRED")

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        $job = Get-JobStatus -AccessToken $AccessToken -BaseUrl $BaseUrl -AccountId $AccountId -JobId $JobId
        $state = "$($job.state)"
        Write-Host "Job $JobId | attempt $i/$MaxAttempts | state=$state"

        if ($terminal -contains $state.ToUpperInvariant()) {
            return $job
        }

        Start-Sleep -Seconds $IntervalSeconds
    }

    return Get-JobStatus -AccessToken $AccessToken -BaseUrl $BaseUrl -AccountId $AccountId -JobId $JobId
}

###############################################################
# EXECUTION
###############################################################

if ([string]::IsNullOrWhiteSpace($OriginClientID) -or
    [string]::IsNullOrWhiteSpace($OriginClientSecret) -or
    [string]::IsNullOrWhiteSpace($OriginAccountID) -or
    [string]::IsNullOrWhiteSpace($DestinationAccountToken)) {
    throw "Missing required config values. Fill Origin credentials, OriginAccountID, and DestinationAccountToken."
}

if (-not $machine_ids -or $machine_ids.Count -eq 0) {
    throw "No machine_ids provided. Fill `$machine_ids with at least one machine ID."
}

$originToken = Get-Token -ClientId $OriginClientID -ClientSecret $OriginClientSecret -TokenEndpoint $TokenUrl -TokenScope $Scope

$report = [ordered]@{
    started_at = (Get-Date).ToString("o")
    api_base_url = $ApiBaseUrl
    jobs_path = $JobsPath
    total_requested = $machine_ids.Count
    items = @()
}

foreach ($mid in $machine_ids) {
    try {
        Write-Host "Creating migration job for machine_id=$mid"
        $create = New-MigrationJob -AccessToken $originToken -BaseUrl $ApiBaseUrl -Path $JobsPath -AccountId $OriginAccountID -MachineId $mid -AccountToken $DestinationAccountToken

        $jobId = $null
        if ($create.jobs -and $create.jobs.Count -gt 0) {
            $jobId = $create.jobs[0].job_id
        }

        if ([string]::IsNullOrWhiteSpace($jobId)) {
            throw "Job created without job_id for machine_id=$mid"
        }

        $final = Wait-JobTerminalState -AccessToken $originToken -BaseUrl $ApiBaseUrl -AccountId $OriginAccountID -JobId $jobId -IntervalSeconds $PollIntervalSeconds -MaxAttempts $MaxPollAttempts

        $report.items += [ordered]@{
            machine_id = $mid
            job_id = $jobId
            state = $final.state
            issued_at = $final.issued_at
            updated_at = $final.updated_at
            command = $final.command
            data = $final.data
            raw = $final
        }
    }
    catch {
        $report.items += [ordered]@{
            machine_id = $mid
            error = "$_"
        }
        Write-Error "Failed machine_id=$mid :: $_"
    }
}

$report.finished_at = (Get-Date).ToString("o")
$report.total_jobs = ($report.items | Where-Object { $_.job_id }).Count
$report.total_errors = ($report.items | Where-Object { $_.error }).Count
$report.total_completed = ($report.items | Where-Object { $_.state -eq "COMPLETED" }).Count
$report.total_failed = ($report.items | Where-Object { $_.state -eq "FAILED" }).Count

$report | ConvertTo-Json -Depth 10 | Set-Content -Path $ReportFile -Encoding UTF8
Write-Host "Report saved to $ReportFile"
Write-Host "Completed=$($report.total_completed) Failed=$($report.total_failed) Errors=$($report.total_errors)"
