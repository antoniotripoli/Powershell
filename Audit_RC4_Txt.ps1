
#Requires -Modules ActiveDirectory

<#
  Parallel Hybrid Optimized RC4 Kerberos Report (Event IDs 4768, 4769)
  - Fast path: Get-WinEvent -LogName Security -FilterXPath -> RC4 in Ticket/Session (4768/4769)
  - Supplement: 4768-only scan, cheaply match "Pre-Authentication EncryptionType = 0x17/0x18 | 23/24" in message
  - Parses XML EventData first; falls back to Message for fields not in EventData
  - Captures PreAuthEncType & PreAuthType; sets RC4Source = Ticket | Session | PreAuth | combinations
  - Adds Network Information: ClientAddress, ClientPort, AdvertizedEtypes
  - Parallelized per-DC with throttle; PS 5.x compatible
#>

# ----------------------------
# Config
# ----------------------------
$Rc4IntCodes = @(23, 24)              # RC4-HMAC (0x17=23), RC4-HMAC-EXP (0x18=24)
$Rc4Hex      = @('0x17','0x18')       # Sometimes recorded as hex strings
$EventIDs    = @(4768, 4769)          # TGT request, Service ticket
$StartTime   = (Get-Date).AddDays(-7)
$OutCsv      = Join-Path (Get-Location) 'RC4_Events_Detailed.csv'
$Throttle    = 4                      # adjust for your environment

Write-Host "Scanning DCs in parallel for Kerberos RC4 since $StartTime ..." -ForegroundColor Cyan

# ----------------------------
# Build FilterXPath (time-bound + RC4 in ticket/session)
# ----------------------------
$startIso = $StartTime.ToUniversalTime().ToString('o')
$FilterXPath = @"
*[System[
    (EventID=4768 or EventID=4769)
    and TimeCreated[@SystemTime >= '$startIso']
]]
and
*[EventData[
    (
      (Data[@Name='TicketEncryptionType']='0x17') or (Data[@Name='TicketEncryptionType']='0x18')
      or (Data[@Name='SessionEncryptionType']='0x17') or (Data[@Name='SessionEncryptionType']='0x18')
      or (Data[@Name='TicketEncryptionType']='23') or (Data[@Name='TicketEncryptionType']='24')
      or (Data[@Name='SessionEncryptionType']='23') or (Data[@Name='SessionEncryptionType']='24')
    )
]]
"@

# ----------------------------
# Collect DCs
# ----------------------------
try {
    $DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
} catch {
    Write-Error "Failed to enumerate domain controllers: $($_.Exception.Message)"
    return
}

# ----------------------------
# Job ScriptBlock
# ----------------------------
$jobScript = {
    param($DC, $FilterXPath, $EventIDs, $StartTime, $Rc4IntCodes, $Rc4Hex)

    # ------------- Helpers (PS5 safe) -------------
    function Parse-HexOrInt {
        param([string]$raw)
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $val = $raw.Trim()
        if ($val -match '^0x[0-9A-Fa-f]+$') { return [Convert]::ToInt32($val, 16) }
        elseif ($val -match '^\d+$')        { return [int]$val }
        else                                { return $null }
    }
    function Get-EventDataValue {
        param([xml]$xml, [string]$name)
        if (-not $xml -or [string]::IsNullOrEmpty($name)) { return $null }
        $node = $xml.SelectSingleNode("//Event/EventData/Data[@Name='$name']")
        if ($node -and $node.InnerText) { return $node.InnerText.Trim() } else { return $null }
    }
    function Get-SectionBlock {
        param([string]$Message, [string]$SectionTitle)
        if ([string]::IsNullOrEmpty($Message) -or [string]::IsNullOrEmpty($SectionTitle)) { return $null }
        $escapedTitle = [regex]::Escape($SectionTitle)
        $pattern = "(?ms)$($escapedTitle):\s*(.+?)(?:(?:\r?\n){2,}|^\w.+?Information:)"
        $m = [regex]::Match($Message, $pattern)
        if ($m.Success) { return $m.Groups[1].Value.Trim() } else { return $null }
    }
    function Get-FieldValue {
        param([string]$Block, [string]$FieldLabel)
        if ([string]::IsNullOrWhiteSpace($Block)) { return $null }
        $escapedLabel = [regex]::Escape($FieldLabel)
        $pattern = "(?m)^\s*$escapedLabel\s*:\s*(.+?)\s*$"
        $m = [regex]::Match($Block, $pattern)
        if ($m.Success) { return $m.Groups[1].Value.Trim() } else { return $null }
    }
    # Network: collect Advertized Etypes lines from the "Network Information" block
    function Get-AdvertisedEtypesText {
        param([string]$NetworkBlock)
        if ([string]::IsNullOrWhiteSpace($NetworkBlock)) { return $null }
        $lines = $NetworkBlock -split "`r?`n"
        $start = $false
        $list = @()
        foreach ($line in $lines) {
            if ($line -match 'Adverti[sz]ed Etypes\s*:') { $start = $true; continue }
            if ($start) {
                if ($line -match '^\s*$') { break }
                $list += $line.Trim()
            }
        }
        if ($list.Count -gt 0) { return ($list -join '; ') } else { return $null }
    }

    # Cheap test for 4768 Pre-Auth RC4 directly in message text
    function Test-PreAuthRc4FromMessage {
        param([string]$msg)
        if ([string]::IsNullOrWhiteSpace($msg)) { return $false }
        # Accept hex (0x17/0x18) or decimal (23/24)
        return ($msg -match 'Pre-Authentication\s+EncryptionType\s*:\s*(0x17|0x18|23|24)')
    }
    function Extract-PreAuthFromMessage {
        param([string]$msg)
        $add = Get-SectionBlock -Message $msg -SectionTitle 'Additional Information'
        if (-not $add) { return @{ PreAuthEnc=$null; PreAuthType=$null } }
        $enc  = Get-FieldValue -Block $add -FieldLabel 'Pre-Authentication EncryptionType'
        $typ  = Get-FieldValue -Block $add -FieldLabel 'Pre-Authentication Type'
        return @{ PreAuthEnc=$enc; PreAuthType=$typ }
    }

    # ------------- Collect events (fast path) -------------
    $eventsFast = $null
    try {
        $eventsFast = Get-WinEvent -ComputerName $DC -LogName 'Security' -FilterXPath $FilterXPath -ErrorAction Stop
    } catch {
        # Ignore; fallback below for Ticket/Session RC4
        $eventsFast = @()
    }

    # Fallback for Ticket/Session RC4 when XPath not available on a DC
    $eventsBasic = @()
    if (-not $eventsFast -or $eventsFast.Count -eq 0) {
        try {
            $eventsBasic = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                LogName   = 'Security'
                Id        = $EventIDs
                StartTime = $StartTime
            } -ErrorAction Stop
        } catch {
            Write-Warning "Failed to read events from $($DC): $($_.Exception.Message)"
            return
        }
    }

    # Supplemental pass: 4768 ONLY, to catch Pre-Auth RC4
    $events4768PreAuth = @()
    try {
        $ev4768 = Get-WinEvent -ComputerName $DC -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4768
            StartTime = $StartTime
        } -ErrorAction Stop

        foreach ($e in $ev4768) {
            if (Test-PreAuthRc4FromMessage -msg $e.Message) { $events4768PreAuth += $e }
        }
    } catch {
        # If this fails on a DC, we still have fast/fallback results
    }

    # Merge lists (avoid duplicates by RecordId)
    $all = @{}
    foreach ($e in ($eventsFast + $eventsBasic + $events4768PreAuth)) {
        if (-not $all.ContainsKey($e.RecordId)) { $all[$e.RecordId] = $e }
    }
    $events = $all.Values

    # ------------- Build rows -------------
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $msg = $evt.Message

        # Ticket/Session
        $TicketEncRaw  = Get-EventDataValue $xml 'TicketEncryptionType'
        $SessionEncRaw = Get-EventDataValue $xml 'SessionEncryptionType'
        if (-not $TicketEncRaw -or -not $SessionEncRaw) {
            $addBlock = Get-SectionBlock -Message $msg -SectionTitle 'Additional Information'
            if (-not $TicketEncRaw)  { $TicketEncRaw  = Get-FieldValue -Block $addBlock -FieldLabel 'Ticket Encryption Type' }
            if (-not $SessionEncRaw) { $SessionEncRaw = Get-FieldValue -Block $addBlock -FieldLabel 'Session Encryption Type' }
        }

        # Pre-Authentication (4768 only)
        $PreAuthEncRaw = Get-EventDataValue $xml 'PreAuthenticationEncryptionType'
        $PreAuthType   = Get-EventDataValue $xml 'PreAuthenticationType'
        if (-not $PreAuthEncRaw -or -not $PreAuthType) {
            $pa = Extract-PreAuthFromMessage -msg $msg
            if (-not $PreAuthEncRaw) { $PreAuthEncRaw = $pa.PreAuthEnc }
            if (-not $PreAuthType)   { $PreAuthType   = $pa.PreAuthType }
        }

        # ---------------------------- Network Information ----------------------------
        # Prefer EventData names commonly present in 4768/4769; fall back to message block.
        $ClientAddress = $null
        $ClientPort    = $null

        # Try common EventData names first
        $ClientAddress = Get-EventDataValue $xml 'ClientAddress'
        if (-not $ClientAddress) { $ClientAddress = Get-EventDataValue $xml 'IpAddress' }
        $ClientPort    = Get-EventDataValue $xml 'ClientPort'
        if (-not $ClientPort)    { $ClientPort    = Get-EventDataValue $xml 'IpPort' }

        # Fallback to message "Network Information" block
        $netBlock = Get-SectionBlock -Message $msg -SectionTitle 'Network Information'
        if (-not $ClientAddress) { $ClientAddress = Get-FieldValue -Block $netBlock -FieldLabel 'Client Address' }
        if (-not $ClientPort)    { $ClientPort    = Get-FieldValue -Block $netBlock -FieldLabel 'Client Port' }
        $AdvertizedEtypes = Get-AdvertisedEtypesText -NetworkBlock $netBlock
        if ([string]::IsNullOrWhiteSpace($ClientAddress)) { $ClientAddress = 'N/A' }
        if ([string]::IsNullOrWhiteSpace($ClientPort))    { $ClientPort    = 'N/A' }
        if ([string]::IsNullOrWhiteSpace($AdvertizedEtypes)) { $AdvertizedEtypes = $null }

        # ---------------------------- RC4 detection ----------------------------
        $isRc4Ticket  = $false
        $isRc4Session = $false
        $isRc4PreAuth = $false

        $ti = Parse-HexOrInt $TicketEncRaw
        $si = Parse-HexOrInt $SessionEncRaw
        $pi = Parse-HexOrInt $PreAuthEncRaw

        if ($ti -ne $null -and ($Rc4IntCodes -contains $ti)) { $isRc4Ticket  = $true }
        if ($si -ne $null -and ($Rc4IntCodes -contains $si)) { $isRc4Session = $true }
        if ($pi -ne $null -and ($Rc4IntCodes -contains $pi)) { $isRc4PreAuth = $true }

        # If coming from fallback set (4768/4769) and none are RC4, skip
        if (-not ($isRc4Ticket -or $isRc4Session -or $isRc4PreAuth)) { continue }

        # ---------------------------- Account ----------------------------
        $AccountName   = Get-EventDataValue $xml 'TargetUserName'
        if (-not $AccountName) {
            $acctBlock = Get-SectionBlock -Message $msg -SectionTitle 'Account Information'
            $AccountName = Get-FieldValue -Block $acctBlock -FieldLabel 'Account Name'
            if (-not $AccountName) { $AccountName = Get-FieldValue -Block $acctBlock -FieldLabel 'Target Account Name' }
        }
        $AccountDomain = Get-EventDataValue $xml 'TargetDomainName'
        if (-not $AccountDomain) {
            $acctBlock = if ($acctBlock) { $acctBlock } else { Get-SectionBlock -Message $msg -SectionTitle 'Account Information' }
            $AccountDomain = Get-FieldValue -Block $acctBlock -FieldLabel 'Account Domain'
        }
        if (-not $acctBlock) { $acctBlock = Get-SectionBlock -Message $msg -SectionTitle 'Account Information' }
        $AcctSupported = Get-FieldValue -Block $acctBlock -FieldLabel 'MSDS-SupportedEncryptionTypes'
        $AcctAvailKeys = Get-FieldValue -Block $acctBlock -FieldLabel 'Available Keys'
        if ([string]::IsNullOrEmpty($AcctSupported)) { $AcctSupported = 'N/A' }
        if ([string]::IsNullOrEmpty($AcctAvailKeys)) { $AcctAvailKeys = 'N/A' }

        # ---------------------------- Service ----------------------------
        $ServiceName = Get-EventDataValue $xml 'ServiceName'
        if (-not $ServiceName) {
            $svcBlock = Get-SectionBlock -Message $msg -SectionTitle 'Service Information'
            $ServiceName = Get-FieldValue -Block $svcBlock -FieldLabel 'Service Name'
        }
        $ServiceID = Get-EventDataValue $xml 'ServiceSid'
        if (-not $ServiceID) {
            $svcBlock = if ($svcBlock) { $svcBlock } else { Get-SectionBlock -Message $msg -SectionTitle 'Service Information' }
            $ServiceID = Get-FieldValue -Block $svcBlock -FieldLabel 'Service ID'
        }
        if (-not $svcBlock) { $svcBlock = Get-SectionBlock -Message $msg -SectionTitle 'Service Information' }
        $SvcSupported = Get-FieldValue -Block $svcBlock -FieldLabel 'MSDS-SupportedEncryptionTypes'
        $SvcAvailKeys = Get-FieldValue -Block $svcBlock -FieldLabel 'Available Keys'
        if ([string]::IsNullOrEmpty($SvcSupported)) { $SvcSupported = 'N/A' }
        if ([string]::IsNullOrEmpty($SvcAvailKeys)) { $SvcAvailKeys = 'N/A' }

        # ---------------------------- DC ----------------------------
        $dcBlock    = Get-SectionBlock -Message $msg -SectionTitle 'Domain Controller Information'
        $DcSupported= Get-FieldValue -Block $dcBlock -FieldLabel 'MSDS-SupportedEncryptionTypes'
        $DcAvailKeys= Get-FieldValue -Block $dcBlock -FieldLabel 'Available Keys'
        if ([string]::IsNullOrEmpty($DcSupported)) { $DcSupported = 'N/A' }
        if ([string]::IsNullOrEmpty($DcAvailKeys)) { $DcAvailKeys = 'N/A' }

        # ---------------------------- Additional ----------------------------
        $TicketOptions = Get-EventDataValue $xml 'TicketOptions'
        if (-not $TicketOptions) {
            $addBlock = if ($addBlock) { $addBlock } else { Get-SectionBlock -Message $msg -SectionTitle 'Additional Information' }
            $TicketOptions = Get-FieldValue -Block $addBlock -FieldLabel 'Ticket Options'
        }
        $FailureCode = Get-EventDataValue $xml 'FailureCode'
        if (-not $FailureCode) {
            $addBlock = if ($addBlock) { $addBlock } else { Get-SectionBlock -Message $msg -SectionTitle 'Additional Information' }
            $FailureCode = Get-FieldValue -Block $addBlock -FieldLabel 'Failure Code'
        }
        $Transited = Get-EventDataValue $xml 'TransitedServices'
        if (-not $Transited) {
            $addBlock = if ($addBlock) { $addBlock } else { Get-SectionBlock -Message $msg -SectionTitle 'Additional Information' }
            $Transited = Get-FieldValue -Block $addBlock -FieldLabel 'Transited Services'
        }
        if ([string]::IsNullOrEmpty($Transited)) { $Transited = '-' }

        # ---------------------------- RC4 Source label ----------------------------
        $RC4Source = 'None'
        if ($isRc4Ticket -and $isRc4Session -and $isRc4PreAuth) { $RC4Source = 'Ticket+Session+PreAuth' }
        elseif ($isRc4Ticket -and $isRc4Session) { $RC4Source = 'Ticket+Session' }
        elseif ($isRc4Ticket -and $isRc4PreAuth) { $RC4Source = 'Ticket+PreAuth' }
        elseif ($isRc4Session -and $isRc4PreAuth) { $RC4Source = 'Session+PreAuth' }
        elseif ($isRc4Ticket) { $RC4Source = 'Ticket' }
        elseif ($isRc4Session) { $RC4Source = 'Session' }
        elseif ($isRc4PreAuth) { $RC4Source = 'PreAuth' }

        # ---------------------------- Row ----------------------------
        $rows.Add([pscustomobject]@{
            DomainController = $DC
            TimeCreated      = $evt.TimeCreated
            EventID          = $evt.Id

            AccountName      = $AccountName
            AccountDomain    = $AccountDomain
            AccountEncTypes  = $AcctSupported
            AccountKeys      = $AcctAvailKeys

            ServiceName      = $ServiceName
            ServiceID        = $ServiceID
            ServiceEncTypes  = $SvcSupported
            ServiceKeys      = $SvcAvailKeys

            DCEncTypes       = $DcSupported
            DCKeys           = $DcAvailKeys

            TicketOptions    = $TicketOptions
            TicketEncType    = $TicketEncRaw
            SessionEncType   = $SessionEncRaw
            PreAuthEncType   = $PreAuthEncRaw
            PreAuthType      = $PreAuthType
            FailureCode      = $FailureCode
            TransitedServices= $Transited

            # Network
            ClientAddress    = $ClientAddress
            ClientPort       = $ClientPort
            AdvertizedEtypes = $AdvertizedEtypes

            RC4Source        = $RC4Source
        })
    }

    # Emit rows from job
    $rows
}

# ----------------------------
# Run jobs with throttle
# ----------------------------
$jobs = @()
$AllResults = @()

foreach ($dc in $DCs) {
    while ($jobs.Count -ge $Throttle) {
        $finished = Wait-Job -Job $jobs -Any -Timeout 10
        if ($finished) {
            foreach ($fj in @($finished)) {
                $res = Receive-Job -Job $fj -ErrorAction SilentlyContinue
                if ($res) { $AllResults += $res }
                $jobs = $jobs | Where-Object { $_.Id -ne $fj.Id }
                Remove-Job -Job $fj -Force
            }
        }
    }
    $jobs += Start-Job -ScriptBlock $jobScript -ArgumentList $dc, $FilterXPath, $EventIDs, $StartTime, $Rc4IntCodes, $Rc4Hex
}

if ($jobs.Count -gt 0) {
    Wait-Job -Job $jobs | Out-Null
    foreach ($j in $jobs) {
        $res = Receive-Job -Job $j -ErrorAction SilentlyContinue
        if ($res) { $AllResults += $res }
        Remove-Job -Job $j -Force
    }
}

# ----------------------------
# Output (explicit column order; drop PS* job props)
# ----------------------------
$columns = @(
 'DomainController','TimeCreated','EventID',
 'AccountName','AccountDomain','AccountEncTypes','AccountKeys',
 'ServiceName','ServiceID','ServiceEncTypes','ServiceKeys',
 'DCEncTypes','DCKeys',
 'TicketOptions','TicketEncType','SessionEncType','PreAuthEncType','PreAuthType',
 'FailureCode','TransitedServices',
 'ClientAddress','ClientPort','AdvertizedEtypes',
 'RC4Source'
)

if ($AllResults.Count -gt 0) {
    $AllResults | Sort-Object TimeCreated |
        Select-Object $columns |
        Format-Table -AutoSize

    $AllResults | Sort-Object TimeCreated |
        Select-Object $columns |
        Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

    Write-Host "`nReport written to: $OutCsv" -ForegroundColor Green
    Write-Host "Total RC4-related events (Ticket/Session/PreAuth): $($AllResults.Count)" -ForegroundColor Yellow
} else {
       Write-Host "`nNo RC4 in ticket, session, or pre-auth detected in the selected window." -ForegroundColor Gray
}