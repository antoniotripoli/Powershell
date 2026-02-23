param(
    [int]$DaysBack = 7,
    [int]$Throttle = 16,
    [string]$OutputCsv = ".\NTLMv1_4624_Findings.csv",
    [switch]$IncludeAnonymous,
    [string[]]$DomainControllers
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-EventDataValue {
    param([xml]$Xml, [string]$Name)
    $n = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($null -eq $n) { return $null }
    $n.'#text'
}

# Discover DCs if not provided
if (-not $DomainControllers -or $DomainControllers.Count -eq 0) {
    $DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
}

# FilterXml requires UTC SystemTime
$startUtc = (Get-Date).AddDays(-[math]::Abs($DaysBack)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

# Build the Select clause:
#   4624 AND time>=start AND AuthPkg=NTLM AND LmPackageName=NTLM V1
# Optionally exclude ANONYMOUS LOGON (TargetUserSid = S-1-5-7)
$anonClause = ""
if (-not $IncludeAnonymous) {
    $anonClause = "and *[EventData[Data[@Name='TargetUserSid']!='S-1-5-7']]"
}

$filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624) and TimeCreated[@SystemTime >= '$startUtc']]]
      and *[EventData[Data[@Name='AuthenticationPackageName']='NTLM']]
      and *[EventData[Data[@Name='LmPackageName']='NTLM V1']]
      $anonClause
    </Select>
  </Query>
</QueryList>
"@

$scriptBlock = {
    param($dc, $xmlQuery)

    function Get-EventDataValue {
        param([xml]$Xml, [string]$Name)
        $n = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if ($null -eq $n) { return $null }
        $n.'#text'
    }

    try {
        $out = New-Object System.Collections.Generic.List[object]
        $events = Get-WinEvent -ComputerName $dc -FilterXml $xmlQuery -ErrorAction Stop

        foreach ($ev in $events) {
            $x = [xml]$ev.ToXml()

            $out.Add([pscustomobject]@{
                TimeCreated      = $ev.TimeCreated
                DomainController = $dc
                TargetUser       = Get-EventDataValue $x 'TargetUserName'
                TargetDomain     = Get-EventDataValue $x 'TargetDomainName'
                TargetUserSid    = Get-EventDataValue $x 'TargetUserSid'
                LogonType        = Get-EventDataValue $x 'LogonType'
                Workstation      = Get-EventDataValue $x 'WorkstationName'
                IpAddress        = Get-EventDataValue $x 'IpAddress'
                LogonProcess     = Get-EventDataValue $x 'LogonProcessName'
                AuthPackage      = Get-EventDataValue $x 'AuthenticationPackageName'
                LmPackageName    = Get-EventDataValue $x 'LmPackageName'      # NTLM V1
                KeyLength        = Get-EventDataValue $x 'KeyLength'
                ProcessName      = Get-EventDataValue $x 'ProcessName'
                EventRecordId    = $ev.RecordId
            })
        }

        $out
    }
    catch {
        Write-Warning "[$dc] FAILED: $($_.Exception.Message)"
    }
}

# Runspace pool parallelism (PS 5.1 compatible)
$pool = [RunspaceFactory]::CreateRunspacePool(1, $Throttle)
$pool.Open()

$jobs = @()
foreach ($dc in $DomainControllers) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript($scriptBlock).AddArgument($dc).AddArgument($filterXml)
    $handle = $ps.BeginInvoke()
    $jobs += [pscustomobject]@{ DC = $dc; PS = $ps; Handle = $handle }
}

$results = New-Object System.Collections.Generic.List[object]
foreach ($j in $jobs) {
    try {
        $r = $j.PS.EndInvoke($j.Handle)
        if ($r) { $results.AddRange($r) }
    } finally {
        $j.PS.Dispose()
    }
}

$pool.Close()
$pool.Dispose()

if ($results.Count -gt 0) {
    $results | Sort-Object TimeCreated |
        Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "FAIL: Found $($results.Count) NTLMv1 logons (4624 LmPackageName=NTLM V1). CSV: $OutputCsv" -ForegroundColor Red
} else {
    Write-Host "PASS: No NTLMv1 logons found (4624 LmPackageName=NTLM V1) in last $DaysBack day(s)." -ForegroundColor Green
}
