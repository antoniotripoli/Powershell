#Requires -Modules ActiveDirectory
param(
    [int]$HoursBack = 6,
    [int]$Throttle  = 12,
    [string]$OutputCsv = ".\Kerberos_FieldOnly_RC4_CurrentDomain.csv"
)

Import-Module ActiveDirectory
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# RC4 etypes: 0x17=23, 0x18=24
$Rc4Ints   = @(23,24)
$StartTime = (Get-Date).AddHours(-[math]::Abs($HoursBack))

# ----------------------------
# Current domain ONLY DCs
# ----------------------------
$curDomain = Get-ADDomain -Current LoggedOnUser
$DomainControllers = Get-ADDomainController -Filter * -Server $curDomain.DNSRoot |
    Select-Object -ExpandProperty HostName |
    Sort-Object -Unique

Write-Host ("Scanning CURRENT DOMAIN [{0}] | DCs: {1} | StartTime: {2}" -f $curDomain.DNSRoot, $DomainControllers.Count, $StartTime) -ForegroundColor Cyan

# ----------------------------
# Helpers (unchanged)
# ----------------------------
function Convert-HexOrInt {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $v = $s.Trim()
    if ($v -match '^0x[0-9A-Fa-f]+$') { return [Convert]::ToInt32($v,16) }
    if ($v -match '^\d+$') { return [int]$v }
    return $null
}

function Get-SectionBlock {
    param([string]$Message, [string]$SectionTitle)
    if ([string]::IsNullOrWhiteSpace($Message) -or [string]::IsNullOrWhiteSpace($SectionTitle)) { return $null }
    $t = [regex]::Escape($SectionTitle)
    $pattern = "(?ms)${t}:\s*(.+?)(?:(?:\r?\n){2,}^\w.+?Information:|$)"
    $m = [regex]::Match($Message, $pattern)
    if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null }
}

function Get-FieldValue {
    param([string]$Block, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Block) -or [string]::IsNullOrWhiteSpace($Label)) { return $null }
    $l = [regex]::Escape($Label)
    $m = [regex]::Match($Block, "(?m)^\s*${l}\s*:\s*(.+?)\s*$")
    if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null }
}

function Get-AdvertisedEtypesFromNetworkBlock {
    param([string]$NetworkBlock)
    if ([string]::IsNullOrWhiteSpace($NetworkBlock)) { return $null }
    $lines = $NetworkBlock -split "`r?`n"
    $start = $false
    $list  = New-Object System.Collections.Generic.List[string]
    foreach ($ln in $lines) {
        if ($ln -match 'Adverti[sz]ed Etypes\s*:') { $start = $true; continue }
        if ($start) {
            if ($ln -match '^\s*$') { break }
            $list.Add($ln.Trim()) | Out-Null
        }
    }
    if ($list.Count -gt 0) { ($list -join '; ') } else { $null }
}

function Build-EventDataHashtable {
    param([xml]$Xml)
    $h = @{}
    $nodes = $Xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")
    foreach ($n in $nodes) {
        $a = $n.Attributes['Name']
        if (-not $a) { continue }
        $k = $a.Value
        if ([string]::IsNullOrWhiteSpace($k)) { continue }
        $h[$k.Trim()] = $n.InnerText
    }
    return $h
}

# ----------------------------
# Worker (per DC)  (unchanged)
# ----------------------------
$scriptBlock = {
    param($dc, $startTime, $rc4Ints)

    function Convert-HexOrInt { param([string]$s)
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        $v = $s.Trim()
        if ($v -match '^0x[0-9A-Fa-f]+$') { return [Convert]::ToInt32($v,16) }
        if ($v -match '^\d+$') { return [int]$v }
        return $null
    }
    function Get-SectionBlock { param([string]$Message,[string]$SectionTitle)
        if ([string]::IsNullOrWhiteSpace($Message) -or [string]::IsNullOrWhiteSpace($SectionTitle)) { return $null }
        $t = [regex]::Escape($SectionTitle)
        $pattern = "(?ms)${t}:\s*(.+?)(?:(?:\r?\n){2,}^\w.+?Information:|$)"
        $m = [regex]::Match($Message, $pattern)
        if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null }
    }
    function Get-FieldValue { param([string]$Block,[string]$Label)
        if ([string]::IsNullOrWhiteSpace($Block) -or [string]::IsNullOrWhiteSpace($Label)) { return $null }
        $l=[regex]::Escape($Label)
        $m=[regex]::Match($Block,"(?m)^\s*${l}\s*:\s*(.+?)\s*$")
        if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null }
    }
    function Get-AdvertisedEtypesFromNetworkBlock { param([string]$NetworkBlock)
        if ([string]::IsNullOrWhiteSpace($NetworkBlock)) { return $null }
        $lines=$NetworkBlock -split "`r?`n"; $start=$false
        $list=New-Object System.Collections.Generic.List[string]
        foreach($ln in $lines){
            if($ln -match 'Adverti[sz]ed Etypes\s*:'){ $start=$true; continue }
            if($start){
                if($ln -match '^\s*$'){ break }
                $list.Add($ln.Trim()) | Out-Null
            }
        }
        if($list.Count -gt 0){ $list -join '; ' } else { $null }
    }
    function Build-EventDataHashtable { param([xml]$Xml)
        $h=@{}
        $nodes=$Xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")
        foreach($n in $nodes){
            $a=$n.Attributes['Name']; if(-not $a){ continue }
            $k=$a.Value; if([string]::IsNullOrWhiteSpace($k)){ continue }
            $h[$k.Trim()]=$n.InnerText
        }
        return $h
    }

    $rows = New-Object System.Collections.Generic.List[object]

    $events = Get-WinEvent -ComputerName $dc -FilterHashtable @{
        LogName   = 'Security'
        Id        = @(4768,4769)
        StartTime = $startTime
    } -ErrorAction SilentlyContinue

    foreach ($evt in @($events)) {
        $msg = $evt.Message
        $xml = $null
        try { $xml = [xml]$evt.ToXml() } catch { $xml = $null }

        $data = @{}
        if ($xml) { $data = Build-EventDataHashtable $xml }

        $ticketEncRaw  = $data['TicketEncryptionType']
        $sessionEncRaw = $data['SessionEncryptionType']
        if (-not $sessionEncRaw) { $sessionEncRaw = $data['SessionKeyEncryptionType'] }

        $preAuthEncRaw = $data['PreAuthEncryptionType']
        $preAuthType   = $data['PreAuthType']

        $addBlock = Get-SectionBlock -Message $msg -SectionTitle 'Additional Information'

        if (-not $ticketEncRaw)  { $ticketEncRaw  = Get-FieldValue -Block $addBlock -Label 'Ticket Encryption Type' }
        if (-not $sessionEncRaw) { $sessionEncRaw = Get-FieldValue -Block $addBlock -Label 'Session Encryption Type' }

        if (-not $preAuthEncRaw) {
            $preAuthEncRaw = Get-FieldValue -Block $addBlock -Label 'Pre-Authentication EncryptionType'
            if (-not $preAuthEncRaw) { $preAuthEncRaw = Get-FieldValue -Block $addBlock -Label 'Pre-Authentication Encryption Type' }
        }
        if (-not $preAuthType) {
            $preAuthType = Get-FieldValue -Block $addBlock -Label 'Pre-Authentication Type'
        }

        $ti = Convert-HexOrInt $ticketEncRaw
        $si = Convert-HexOrInt $sessionEncRaw
        $pi = Convert-HexOrInt $preAuthEncRaw

        $isRc4Ticket  = ($ti -ne $null -and ($rc4Ints -contains $ti))
        $isRc4Session = ($si -ne $null -and ($rc4Ints -contains $si))
        $isRc4PreAuth = ($pi -ne $null -and ($rc4Ints -contains $pi))

        if (-not ($isRc4Ticket -or $isRc4Session -or $isRc4PreAuth)) { continue }

        $rc4Source =
            if ($isRc4Ticket -and $isRc4Session -and $isRc4PreAuth) { 'Ticket+Session+PreAuth' }
            elseif ($isRc4Ticket -and $isRc4Session) { 'Ticket+Session' }
            elseif ($isRc4Ticket -and $isRc4PreAuth) { 'Ticket+PreAuth' }
            elseif ($isRc4Session -and $isRc4PreAuth) { 'Session+PreAuth' }
            elseif ($isRc4Ticket)  { 'Ticket' }
            elseif ($isRc4Session) { 'Session' }
            elseif ($isRc4PreAuth) { 'PreAuth' }
            else { 'Unknown' }

        $acctBlock = Get-SectionBlock -Message $msg -SectionTitle 'Account Information'
        $svcBlock  = Get-SectionBlock -Message $msg -SectionTitle 'Service Information'
        $dcBlock   = Get-SectionBlock -Message $msg -SectionTitle 'Domain Controller Information'
        $netBlock  = Get-SectionBlock -Message $msg -SectionTitle 'Network Information'

        $accountName   = $data['TargetUserName'];  if (-not $accountName)   { $accountName   = Get-FieldValue $acctBlock 'Account Name' }
        $accountDomain = $data['TargetDomainName'];if (-not $accountDomain) { $accountDomain = Get-FieldValue $acctBlock 'Supplied Realm Name' }

        $serviceName = $data['ServiceName']; if (-not $serviceName) { $serviceName = Get-FieldValue $svcBlock 'Service Name' }

        $accEncTypes = $data['AccountSupportedEncryptionTypes']; if (-not $accEncTypes) { $accEncTypes = Get-FieldValue $acctBlock 'MSDS-SupportedEncryptionTypes' }
        $accKeys     = $data['AccountAvailableKeys'];            if (-not $accKeys)     { $accKeys     = Get-FieldValue $acctBlock 'Available Keys' }

        $svcEncTypes = $data['ServiceSupportedEncryptionTypes']; if (-not $svcEncTypes) { $svcEncTypes = Get-FieldValue $svcBlock 'MSDS-SupportedEncryptionTypes' }
        $svcKeys     = $data['ServiceAvailableKeys'];            if (-not $svcKeys)     { $svcKeys     = Get-FieldValue $svcBlock 'Available Keys' }

        $dcEncTypes  = $data['DCSupportedEncryptionTypes'];      if (-not $dcEncTypes)  { $dcEncTypes  = Get-FieldValue $dcBlock 'MSDS-SupportedEncryptionTypes' }
        $dcKeys      = $data['DCAvailableKeys'];                 if (-not $dcKeys)      { $dcKeys      = Get-FieldValue $dcBlock 'Available Keys' }

        $clientAddr = $data['IpAddress']; if (-not $clientAddr) { $clientAddr = Get-FieldValue $netBlock 'Client Address' }
        $advEtypes  = $data['ClientAdvertizedEncryptionTypes']
        if (-not $advEtypes) { $advEtypes = Get-AdvertisedEtypesFromNetworkBlock $netBlock }

        $rows.Add([pscustomobject]@{
            DomainController = $dc
            TimeCreated      = $evt.TimeCreated
            EventID          = $evt.Id
            AccountName      = $accountName
            AccountDomain    = $accountDomain
            'Account MSDS-SupportedEncryptionTypes' = $accEncTypes
            'Account Available Keys'               = $accKeys
            ServiceName      = $serviceName
            'Service MSDS-SupportedEncryptionTypes' = $svcEncTypes
            'Service Available Keys'               = $svcKeys
            'DC MSDS-SupportedEncryptionTypes'      = $dcEncTypes
            'DC Available Keys'                     = $dcKeys
            ClientAddress    = $clientAddr
            AdvertizedEtypes = $advEtypes
            TicketEncryptionType            = $ticketEncRaw
            SessionEncryptionType           = $sessionEncRaw
            PreAuthenticationType           = $preAuthType
            PreAuthenticationEncryptionType = $preAuthEncRaw
            RC4Source        = $rc4Source
        }) | Out-Null
    }

    $rows
}

# ----------------------------
# Parallel runspace pool (improved collection + streaming output)
# ----------------------------
# Make output paths robust even if relative + file doesn't exist yet
$OutputCsvFull = if ([IO.Path]::IsPathRooted($OutputCsv)) { $OutputCsv } else { Join-Path (Get-Location).Path $OutputCsv }
$ErrorLog = $OutputCsvFull + ".errors.txt"

# Ensure output folder exists
$outDir = Split-Path -Path $OutputCsvFull -Parent
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

# If an old CSV exists, keep it as backup (optional but useful)
if (Test-Path $OutputCsvFull) {
    $bak = $OutputCsvFull + "." + (Get-Date -Format "yyyyMMdd_HHmmss") + ".bak"
    Copy-Item -LiteralPath $OutputCsvFull -Destination $bak -Force
    Remove-Item -LiteralPath $OutputCsvFull -Force
}

$pool = [RunspaceFactory]::CreateRunspacePool(1, $Throttle)
$pool.Open()

$jobs = @()
foreach ($dc in $DomainControllers) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript($scriptBlock).AddArgument($dc).AddArgument($StartTime).AddArgument($Rc4Ints)
    $handle = $ps.BeginInvoke()
    $jobs += [pscustomobject]@{ DC=$dc; PS=$ps; Handle=$handle }
}

$headerWritten = $false
$completed = 0
$totalRows = 0
$rc4Counts = @{}   # RC4Source -> count

# Process in completion order (so we don't block on a slow first DC)
$pending = New-Object System.Collections.Generic.List[object]
$pending.AddRange($jobs)

while ($pending.Count -gt 0) {

    # Grab all completed jobs this loop
    $doneNow = @($pending | Where-Object { $_.Handle.IsCompleted })

    if ($doneNow.Count -eq 0) {
        Start-Sleep -Milliseconds 250
        continue
    }

    foreach ($j in $doneNow) {
        try {
            $r = $j.PS.EndInvoke($j.Handle)

            if ($r) {
                $chunk = @($r) | Sort-Object TimeCreated

                if (-not $headerWritten) {
                    $chunk | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputCsvFull
                    $headerWritten = $true
                } else {
                    $chunk | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputCsvFull -Append
                }

                $totalRows += $chunk.Count

                # Update RC4Source counters without storing everything
                foreach ($g in ($chunk | Group-Object RC4Source)) {
                    if (-not $rc4Counts.ContainsKey($g.Name)) { $rc4Counts[$g.Name] = 0 }
                    $rc4Counts[$g.Name] += $g.Count
                }
            }
        }
        catch {
            ("{0}`t{1}`t{2}" -f (Get-Date), $j.DC, $_.Exception.Message) |
                Out-File -FilePath $ErrorLog -Append -Encoding UTF8
        }
        finally {
            $j.PS.Dispose()
            [void]$pending.Remove($j)
            $completed++

            if (($completed % 20) -eq 0) {
                Write-Host ("Progress: {0}/{1} DCs completed | Rows so far: {2} | CSV: {3}" -f $completed, $jobs.Count, $totalRows, $OutputCsvFull) -ForegroundColor Yellow
            }
        }
    }
}

$pool.Close()
$pool.Dispose()

Write-Host ("DONE. Rows: {0}  CSV: {1}" -f $totalRows, $OutputCsvFull) -ForegroundColor Green

if ($rc4Counts.Count -gt 0) {
    $summary = ($rc4Counts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
    Write-Host ("RC4 by source: {0}" -f $summary) -ForegroundColor Cyan
} else {
    Write-Host "RC4 by source: (no rows)" -ForegroundColor Cyan
}

if (Test-Path $ErrorLog) {
    Write-Host ("Some DCs had errors. See: {0}" -f $ErrorLog) -ForegroundColor DarkYellow
}