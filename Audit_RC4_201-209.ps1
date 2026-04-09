#Requires -Modules ActiveDirectory

<#
  Parallel DC System Log scan for Event IDs 201..209
  - PS 7+: ForEach-Object -Parallel with ThrottleLimit
  - PS 5.1: Throttled Start-Job fallback
  - Exports: detailed events + per-DC totals + per-DC per-ID counts + errors
#>

# ----------------------------
# Config
# ----------------------------
$EventIds   = 201..209
$LogName    = 'System'

# Optional time window (edit or comment out StartTime to scan all time - not recommended)
$StartTime  = (Get-Date).AddDays(-7)
# $EndTime  = Get-Date   # optionally constrain upper bound if you want

$Throttle   = 10   # adjust to your environment (e.g. 4-15)
$OutDir     = 'C:\Temp'

# Output files (timestamped)
$ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
$DetailCsv  = Join-Path $OutDir "DC_${LogName}_Events_201-209_Detail_$ts.csv"
$DcTotalCsv = Join-Path $OutDir "DC_${LogName}_Events_201-209_Summary_ByDC_$ts.csv"
$DcIdCsv    = Join-Path $OutDir "DC_${LogName}_Events_201-209_Summary_ByDC_ById_$ts.csv"
$ErrCsv     = Join-Path $OutDir "DC_${LogName}_Events_201-209_Errors_$ts.csv"

# Ensure output dir exists
if (-not (Test-Path $OutDir)) { New-Item -Path $OutDir -ItemType Directory -Force | Out-Null }

# ----------------------------
# Enumerate DCs
# ----------------------------
$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
if (-not $DCs -or $DCs.Count -eq 0) { throw "No Domain Controllers found." }

Write-Host "Found $($DCs.Count) DCs. Scanning System log for Event IDs 201..209 in parallel (Throttle=$Throttle)..." -ForegroundColor Cyan

# ----------------------------
# Query function (runs per DC)
# ----------------------------
$QueryOneDc = {
    param(
        [string]$DC,
        [string]$LogName,
        [int[]] $EventIds,
        [datetime]$StartTime
        # ,[datetime]$EndTime
    )

    try {
        $fh = @{
            LogName = $LogName
            Id      = $EventIds
        }
        if ($StartTime) { $fh['StartTime'] = $StartTime }
        # if ($EndTime)  { $fh['EndTime']   = $EndTime }

        Get-WinEvent -ComputerName $DC -FilterHashtable $fh -ErrorAction Stop |
            Select-Object @{
                Name       = 'DomainController'
                Expression = { $DC }
            }, TimeCreated, Id, LevelDisplayName, ProviderName, Message
    }
    catch {
        # Emit a structured error record so it can be exported
        [PSCustomObject]@{
            DomainController = $DC
            TimeCreated      = $null
            Id               = $null
            LevelDisplayName = 'ERROR'
            ProviderName     = 'Get-WinEvent'
            Message          = $_.Exception.Message
        }
    }
}

# ----------------------------
# Run in parallel (PS7) or fallback (PS5.1)
# ----------------------------
$Results = @()

if ($PSVersionTable.PSVersion.Major -ge 7) {
    $Results = $DCs | ForEach-Object -Parallel {
        param($LogName, $EventIds, $StartTime)

        # Use the embedded scriptblock logic directly (PS7-safe)
        try {
            $fh = @{ LogName = $LogName; Id = $EventIds }
            if ($StartTime) { $fh['StartTime'] = $StartTime }

            Get-WinEvent -ComputerName $_ -FilterHashtable $fh -ErrorAction Stop |
                Select-Object @{Name='DomainController';Expression={$_=$using:_; $using:_}}, TimeCreated, Id, LevelDisplayName, ProviderName, Message
        }
        catch {
            [PSCustomObject]@{
                DomainController = $_
                TimeCreated      = $null
                Id               = $null
                LevelDisplayName = 'ERROR'
                ProviderName     = 'Get-WinEvent'
                Message          = $_.Exception.Message
            }
        }
    } -ThrottleLimit $Throttle -ArgumentList $LogName, $EventIds, $StartTime
}
else {
    # PS 5.1 fallback: throttled background jobs
    $jobs = @()

    foreach ($dc in $DCs) {
        while ( ($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $Throttle ) {
            Start-Sleep -Seconds 1
        }

        $jobs += Start-Job -Name $dc -ScriptBlock $QueryOneDc -ArgumentList $dc, $LogName, $EventIds, $StartTime
    }

    $Results = $jobs | Receive-Job -Wait -AutoRemoveJob
}

# ----------------------------
# Separate details vs errors
# ----------------------------
$Errors  = $Results | Where-Object { $_.LevelDisplayName -eq 'ERROR' -or -not $_.TimeCreated }
$Details = $Results | Where-Object { $_.TimeCreated -ne $null }

# ----------------------------
# Build summaries
# ----------------------------

# Per-DC totals
$SummaryByDC = $Details |
    Group-Object DomainController |
    Select-Object @{Name='DomainController';Expression={$_.Name}},
                  @{Name='EventCount';Expression={$_.Count}} |
    Sort-Object EventCount -Descending

# Per-DC per-EventID counts
$SummaryByDCById = $Details |
    Group-Object DomainController, Id |
    ForEach-Object {
        $parts = $_.Name -split ',\s*'
        [PSCustomObject]@{
            DomainController = $parts[0]
            EventId          = [int]$parts[1]
            Count            = $_.Count
        }
    } |
    Sort-Object DomainController, EventId

# ----------------------------
# Export CSVs
# ----------------------------
$Details | Sort-Object DomainController, TimeCreated | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $DetailCsv
$SummaryByDC | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $DcTotalCsv
$SummaryByDCById | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $DcIdCsv
$Errors | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $ErrCsv

# ----------------------------
# Console output
# ----------------------------
Write-Host "`nExported:" -ForegroundColor Green
Write-Host "  Detail  : $DetailCsv"
Write-Host "  By DC   : $DcTotalCsv"
Write-Host "  By DC/ID: $DcIdCsv"
Write-Host "  Errors  : $ErrCsv"

Write-Host "`nPer-DC totals (top 20):" -ForegroundColor Cyan
$SummaryByDC | Select-Object -First 20 | Format-Table -AutoSize

if ($Errors.Count -gt 0) {
    Write-Host "`nDC query errors ($($Errors.Count)) — see $ErrCsv" -ForegroundColor Yellow
}