#Requires -Modules ActiveDirectory
 
<#
  Parallel Hybrid Optimized RC4 Kerberos Report (Event IDs 4768, 4769) + Client Key Enrichment
  - Keeps your server-side filtering + fallback strategy
  - Adds: ClientHost (reverse-DNS), Account/ClientComputer encryption masks from AD
  - Optional: If DSInternals is present, also lists actual Kerberos keys (AES/RC4) via Get-ADReplAccount
  - PS 5.x compatible
#>
 
# ----------------------------
# Config
# ----------------------------
$Rc4IntCodes = @(23, 24)              # RC4-HMAC (0x17=23), RC4-HMAC-EXP (0x18=24)
$EventIDs    = @(4768, 4769)          # TGT request, Service ticket
$StartTime   = (Get-Date).AddDays(-7)
$OutCsv      = Join-Path (Get-Location) 'RC4_Events_Detailed.csv'
$Throttle    = 4                      # adjust for your environment
 
# Enrichment toggles
$ResolveClientHostnames    = $true    # reverse-DNS ClientAddress -> ClientHost
$EnrichAccountFromAD       = $true    # msDS-SupportedEncryptionTypes for event AccountName
$EnrichClientComputerFromAD= $true    # msDS-SupportedEncryptionTypes for ClientHost (if resolvable)
$UseDSInternalsIfAvailable = $true    # only if module/cmdlet is available
 
Write-Host "Scanning DCs in parallel for Kerberos RC4 since $StartTime ..." -ForegroundColor Cyan
 
# ----------------------------
# Helpers (shared)
# ----------------------------
function Convert-EncMaskToList {
    param([Nullable[int]]$mask)
    if ($mask -eq $null) { return @() }
    # Bits from msDS-SupportedEncryptionTypes
    # 0x01: DES-CBC-CRC, 0x02: DES-CBC-MD5, 0x04: RC4-HMAC, 0x08: AES128, 0x10: AES256, 0x20: FAST, 0x40: CompoundId, 0x80: Claims
    $map = [ordered]@{
        0x10 = 'AES256'
        0x08 = 'AES128'
        0x04 = 'RC4'
        0x02 = 'DES-MD5'
        0x01 = 'DES-CRC'
        0x20 = 'FAST'
        0x40 = 'CompoundIdentity'
        0x80 = 'Claims'
    }
    $list = @()
    foreach ($k in $map.Keys) {
        if (($mask -band $k) -ne 0) { $list += $map[$k] }
    }
    return $list
}
function Get-EncTypeName {
    param([Nullable[int]]$i)
    if ($i -eq $null) { return $null }
    switch ($i) {
        0x11 { 'AES128' }
        0x12 { 'AES256' }
        0x17 { 'RC4-HMAC' }
        0x18 { 'RC4-EXP' }
        0x01 { 'DES-CBC-CRC' }
        0x03 { 'DES-CBC-MD5' }
        default { ('0x{0:X}' -f $i) }
    }
}
function Parse-HexOrInt {
    param([string]$raw)
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $val = $raw.Trim()
    if ($val -match '^0x[0-9A-Fa-f]+$') { return [Convert]::ToInt32($val, 16) }
    elseif ($val -match '^\d+$')        { return [int]$val }
    else                                { return $null }
}
function Safe-SelectSingleNode {
    param([xml]$xml, [string]$xpath)
    try { return $xml.SelectSingleNode($xpath) } catch { return $null }
}
function Get-EventDataValue {
    param([xml]$xml, [string]$name)
    if (-not $xml -or [string]::IsNullOrEmpty($name)) { return $null }
    $node = Safe-SelectSingleNode $xml "//Event/EventData/Data[@Name='$name']"
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
function Test-PreAuthRc4FromMessage {
    param([string]$msg)
    if ([string]::IsNullOrWhiteSpace($msg)) { return $false }
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
# Job ScriptBlock (per-DC collection; unchanged logic + minor refactors)
# ----------------------------
$jobScript = {
    param($DC, $FilterXPath, $EventIDs, $StartTime, $Rc4IntCodes)
 
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
        try {
            $node = $xml.SelectSingleNode("//Event/EventData/Data[@Name='$name']")
            if ($node -and $node.InnerText) { return $node.InnerText.Trim() } else { return $null }
        } catch { return $null }
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
    function Test-PreAuthRc4FromMessage { param([string]$msg)
        if ([string]::IsNullOrWhiteSpace($msg)) { return $false }
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
 
    # Collect events (fast path)
    $eventsFast = @()
    try {
        $eventsFast = Get-WinEvent -ComputerName $DC -LogName 'Security' -FilterXPath $FilterXPath -ErrorAction Stop
    } catch { $eventsFast = @() }
 
    # Fallback broad read if needed
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
 
    # Supplemental pass: 4768 ONLY for Pre-Auth RC4
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
    } catch {}
 
    # Merge, dedupe within this DC by RecordId
    $all = @{}
    foreach ($e in ($eventsFast + $eventsBasic + $events4768PreAuth)) {
        if (-not $all.ContainsKey($e.RecordId)) { $all[$e.RecordId] = $e }
    }
    $events = $all.Values
 
    # Build rows
    $rows = New-Object System.Collections.Generic.List[object]
 
    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $msg = $evt.Message
 
        # Ticket/Session enc types
        $TicketEncRaw  = Get-EventDataValue $xml 'TicketEncryptionType'
        $SessionEncRaw = Get-EventDataValue $xml 'SessionEncryptionType'
        if (-not $TicketEncRaw -or -not $SessionEncRaw) {
            $addBlock = Get-SectionBlock -Message $msg -SectionTitle 'Additional Information'
            if (-not $TicketEncRaw)  { $TicketEncRaw  = Get-FieldValue -Block $addBlock -FieldLabel 'Ticket Encryption Type' }
            if (-not $SessionEncRaw) { $SessionEncRaw = Get-FieldValue -Block $addBlock -FieldLabel 'Session Encryption Type' }
        }
 
        # Pre-Auth (4768 only)
        $PreAuthEncRaw = Get-EventDataValue $xml 'PreAuthenticationEncryptionType'
        $PreAuthType   = Get-EventDataValue $xml 'PreAuthenticationType'
        if (-not $PreAuthEncRaw -or -not $PreAuthType) {
            $pa = Extract-PreAuthFromMessage -msg $msg
            if (-not $PreAuthEncRaw) { $PreAuthEncRaw = $pa.PreAuthEnc }
            if (-not $PreAuthType)   { $PreAuthType   = $pa.PreAuthType }
        }
 
        # Network block
        $ClientAddress = $null; $ClientPort = $null
        $ClientAddress = Get-EventDataValue $xml 'ClientAddress'
        if (-not $ClientAddress) { $ClientAddress = Get-EventDataValue $xml 'IpAddress' }
        $ClientPort    = Get-EventDataValue $xml 'ClientPort'
        if (-not $ClientPort)    { $ClientPort    = Get-EventDataValue $xml 'IpPort' }
 
        $netBlock = Get-SectionBlock -Message $msg -SectionTitle 'Network Information'
        if (-not $ClientAddress) { $ClientAddress = Get-FieldValue -Block $netBlock -FieldLabel 'Client Address' }
        if (-not $ClientPort)    { $ClientPort    = Get-FieldValue -Block $netBlock -FieldLabel 'Client Port' }
        $AdvertizedEtypes = Get-AdvertisedEtypesText -NetworkBlock $netBlock
        if ([string]::IsNullOrWhiteSpace($ClientAddress)) { $ClientAddress = 'N/A' }
        if ([string]::IsNullOrWhiteSpace($ClientPort))    { $ClientPort    = 'N/A' }
        if ([string]::IsNullOrWhiteSpace($AdvertizedEtypes)) { $AdvertizedEtypes = $null }
 
        # RC4 detection
        $isRc4Ticket  = $false; $isRc4Session = $false; $isRc4PreAuth = $false
        $ti = Parse-HexOrInt $TicketEncRaw
        $si = Parse-HexOrInt $SessionEncRaw
        $pi = Parse-HexOrInt $PreAuthEncRaw
        if ($ti -ne $null -and ($Rc4IntCodes -contains $ti)) { $isRc4Ticket  = $true }
        if ($si -ne $null -and ($Rc4IntCodes -contains $si)) { $isRc4Session = $true }
        if ($pi -ne $null -and ($Rc4IntCodes -contains $pi)) { $isRc4PreAuth = $true }
        if (-not ($isRc4Ticket -or $isRc4Session -or $isRc4PreAuth)) { continue }
 
        # Account info
        $AccountName   = Get-EventDataValue $xml 'TargetUserName'
        $AccountDomain = Get-EventDataValue $xml 'TargetDomainName'
        if (-not $AccountName -or -not $AccountDomain) {
            $acctBlock = Get-SectionBlock -Message $msg -SectionTitle 'Account Information'
            if (-not $AccountName)   { $AccountName   = Get-FieldValue -Block $acctBlock -FieldLabel 'Account Name' }
            if (-not $AccountDomain) { $AccountDomain = Get-FieldValue -Block $acctBlock -FieldLabel 'Account Domain' }
        }
 
        # Service info
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
 
        # Additional info
        $addBlock = Get-SectionBlock -Message $msg -SectionTitle 'Additional Information'
        $TicketOptions = Get-EventDataValue $xml 'TicketOptions'
        if (-not $TicketOptions) { $TicketOptions = Get-FieldValue -Block $addBlock -FieldLabel 'Ticket Options' }
        $FailureCode = Get-EventDataValue $xml 'FailureCode'
        if (-not $FailureCode) { $FailureCode = Get-FieldValue -Block $addBlock -FieldLabel 'Failure Code' }
        $Transited = Get-EventDataValue $xml 'TransitedServices'
        if (-not $Transited) { $Transited = Get-FieldValue -Block $addBlock -FieldLabel 'Transited Services' }
        if ([string]::IsNullOrEmpty($Transited)) { $Transited = '-' }
 
        # RC4 Source label
        $RC4Source = 'None'
        if     ($isRc4Ticket -and $isRc4Session -and $isRc4PreAuth) { $RC4Source = 'Ticket+Session+PreAuth' }
        elseif ($isRc4Ticket -and $isRc4Session) { $RC4Source = 'Ticket+Session' }
        elseif ($isRc4Ticket -and $isRc4PreAuth) { $RC4Source = 'Ticket+PreAuth' }
        elseif ($isRc4Session -and $isRc4PreAuth){ $RC4Source = 'Session+PreAuth' }
        elseif ($isRc4Ticket)  { $RC4Source = 'Ticket' }
        elseif ($isRc4Session) { $RC4Source = 'Session' }
        elseif ($isRc4PreAuth) { $RC4Source = 'PreAuth' }
 
        # Emit minimal row; enrichment done after merge to avoid repeated AD queries across DCs
        [pscustomobject]@{
            DomainController = $DC
            TimeCreated      = $evt.TimeCreated
            EventID          = $evt.Id
 
            AccountName      = $AccountName
            AccountDomain    = $AccountDomain
 
            ServiceName      = $ServiceName
            ServiceID        = $ServiceID
 
            TicketOptions    = $TicketOptions
            TicketEncType    = $TicketEncRaw
            SessionEncType   = $SessionEncRaw
            PreAuthEncType   = $PreAuthEncRaw
            PreAuthType      = $PreAuthType
            FailureCode      = $FailureCode
            TransitedServices= $Transited
 
            ClientAddress    = $ClientAddress
            ClientPort       = $ClientPort
            AdvertizedEtypes = $AdvertizedEtypes
 
            RC4Source        = $RC4Source
        }
    }
 
    # Return rows from job
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
    $jobs += Start-Job -ScriptBlock $jobScript -ArgumentList $dc, $FilterXPath, $EventIDs, $StartTime, $Rc4IntCodes
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
# Enrichment Phase (centralized, deduped)
# ----------------------------
if ($AllResults.Count -gt 0) {
 
    # 1) Resolve ClientAddress -> ClientHost (optional)
    $clientHostCache = @{}
    if ($ResolveClientHostnames) {
        foreach ($ip in ($AllResults.ClientAddress | Where-Object { $_ -and $_ -ne 'N/A' } | Select-Object -Unique)) {
            $name = $null
            try {
                # Handle IPv6 mapped IPv4 (::ffff:)
                $ipClean = ($ip -replace '^\:\:ffff\:', '')
                $name = [System.Net.Dns]::GetHostEntry($ipClean).HostName
            } catch { $name = $null }
            $clientHostCache[$ip] = $name
        }
    }
 
    # 2) Decide DC for AD queries (prefer PDC)
    $lookupDC = (Get-ADDomain).PDCEmulator
 
    # 3) Account & ClientComputer encryption lookups (cached)
    $acctCache = @{}
    $compCache = @{}
 
    function Get-EncSummaryFromAD {
        param([string]$samOrUpnOrComp, [bool]$isComputer)
        if (-not $samOrUpnOrComp) { return @{ Mask=$null; List=@(); HasAES=$null } }
 
        $props = 'Name','SamAccountName','UserPrincipalName','msDS-SupportedEncryptionTypes','pwdLastSet'
        try {
            if ($isComputer) {
                $obj = Get-ADComputer -Identity $samOrUpnOrComp -Server $lookupDC -Properties $props -ErrorAction Stop
            } else {
                $obj = Get-ADUser -Identity $samOrUpnOrComp -Server $lookupDC -Properties $props -ErrorAction Stop
            }
        } catch {
            # Try search by sam-like name if Identity lookup fails
            try {
                if ($isComputer) {
                    $obj = Get-ADComputer -LDAPFilter "(sAMAccountName=$samOrUpnOrComp)" -Server $lookupDC -Properties $props | Select-Object -First 1
                } else {
                    $obj = Get-ADUser -LDAPFilter "(|(userPrincipalName=$samOrUpnOrComp)(sAMAccountName=$samOrUpnOrComp))" -Server $lookupDC -Properties $props | Select-Object -First 1
                }
            } catch { $obj = $null }
        }
        if (-not $obj) { return @{ Mask=$null; List=@(); HasAES=$null } }
 
        $mask = $null
        if ($obj.'msDS-SupportedEncryptionTypes' -ne $null -and $obj.'msDS-SupportedEncryptionTypes' -ne '') {
            try { $mask = [int]$obj.'msDS-SupportedEncryptionTypes' } catch { $mask = $null }
        }
        $lst = Convert-EncMaskToList -mask $mask
        $hasAES = ($lst -contains 'AES128' -or $lst -contains 'AES256')
 
        return @{ Mask=$mask; List=$lst; HasAES=$hasAES }
    }
 
    $hasDSInternals = $false
    if ($UseDSInternalsIfAvailable) {
        $hasDSInternals = [bool](Get-Command Get-ADReplAccount -ErrorAction SilentlyContinue)
    }
 
    function Get-KeySummaryFromDSInternals {
        param([string]$identity, [bool]$isComputer)
        if (-not $hasDSInternals -or -not $identity) { return $null }
        try {
            if ($isComputer) {
                $adObj = Get-ADComputer -Identity $identity -Server $lookupDC -Properties SamAccountName
            } else {
                $adObj = Get-ADUser -Identity $identity -Server $lookupDC -Properties SamAccountName
            }
            if (-not $adObj) { return $null }
            $rep = $adObj | Get-ADReplAccount -Domain (Get-ADDomain).DNSRoot -Server $lookupDC
            if (-not $rep) { return $null }
 
            # Inspect KerberosNew first, then Kerberos
            $keys = @()
            if ($rep.KerberosNew -and $rep.KerberosNew.Credentials) {
                foreach ($c in $rep.KerberosNew.Credentials) {
                    if ($c.Type) { $keys += $c.Type.ToString() }
                }
            } elseif ($rep.Kerberos -and $rep.Kerberos.Credentials) {
                foreach ($c in $rep.Kerberos.Credentials) {
                    if ($c.Type) { $keys += $c.Type.ToString() }
                }
            }
            if ($keys.Count -eq 0) { return $null }
            # Normalize to AES256,AES128,RC4,DES
            $norm = @()
            if ($keys -match 'AES256') { $norm += 'AES256' }
            if ($keys -match 'AES128') { $norm += 'AES128' }
            if ($keys -match 'RC4')    { $norm += 'RC4' }
            if ($keys -match 'DES')    { $norm += 'DES' }
            return ($norm | Select-Object -Unique) -join ','
        } catch { return $null }
    }
 
    # Build enrichment caches
    foreach ($row in ($AllResults | Select-Object AccountName,AccountDomain -Unique)) {
        $acct = $row.AccountName
        if (-not $acct) { continue }
        if (-not $acctCache.ContainsKey($acct)) {
            $isComputer = $acct.EndsWith('$')
            $sum = if ($EnrichAccountFromAD) { Get-EncSummaryFromAD -samOrUpnOrComp $acct -isComputer:$isComputer } else { @{ Mask=$null; List=@(); HasAES=$null } }
            $keySum = if ($UseDSInternalsIfAvailable) { Get-KeySummaryFromDSInternals -identity $acct -isComputer:$isComputer } else { $null }
            $acctCache[$acct] = @{
                Mask = $sum.Mask
                List = $sum.List
                HasAES = $sum.HasAES
                KeySummary = $keySum
            }
        }
    }
 
    if ($EnrichClientComputerFromAD -and $ResolveClientHostnames) {
        foreach ($ip in ($clientHostCache.Keys | Where-Object { $_ })) {
            $host = $clientHostCache[$ip]
            if (-not $host) { continue }
            $sam = ($host.Split('.')[0] + '$')
            if (-not $compCache.ContainsKey($host)) {
                $sum = Get-EncSummaryFromAD -samOrUpnOrComp $sam -isComputer:$true
                $keySum = if ($UseDSInternalsIfAvailable) { Get-KeySummaryFromDSInternals -identity $sam -isComputer:$true } else { $null }
                $compCache[$host] = @{
                    Mask = $sum.Mask
                    List = $sum.List
                    HasAES = $sum.HasAES
                    KeySummary = $keySum
                }
            }
        }
    }
 
    # 4) Attach enrichment to each row
    $enriched = foreach ($r in $AllResults) {
        $clientHost = $null
        if ($ResolveClientHostnames -and $r.ClientAddress -and $clientHostCache.ContainsKey($r.ClientAddress)) {
            $clientHost = $clientHostCache[$r.ClientAddress]
        }
 
        $acctInfo = $null
        if ($r.AccountName -and $acctCache.ContainsKey($r.AccountName)) { $acctInfo = $acctCache[$r.AccountName] }
 
        $compInfo = $null
        if ($clientHost -and $compCache.ContainsKey($clientHost)) { $compInfo = $compCache[$clientHost] }
 
        # Friendly names for enc fields
        $TicketEncName  = Get-EncTypeName (Parse-HexOrInt $r.TicketEncType)
        $SessionEncName = Get-EncTypeName (Parse-HexOrInt $r.SessionEncType)
        $PreAuthEncName = Get-EncTypeName (Parse-HexOrInt $r.PreAuthEncType)
 
        [pscustomobject]@{
            DomainController = $r.DomainController
            TimeCreated      = $r.TimeCreated
            EventID          = $r.EventID
 
            AccountName      = $r.AccountName
            AccountDomain    = $r.AccountDomain
            AccountEncMask   = $acctInfo.Mask
            AccountEncList   = if ($acctInfo.List) { ($acctInfo.List -join ',') } else { $null }
            AccountHasAES    = $acctInfo.HasAES
            AccountKeySummary= $acctInfo.KeySummary
 
            ServiceName      = $r.ServiceName
            ServiceID        = $r.ServiceID
 
            TicketOptions    = $r.TicketOptions
            TicketEncType    = $r.TicketEncType
            TicketEncName    = $TicketEncName
            SessionEncType   = $r.SessionEncType
            SessionEncName   = $SessionEncName
            PreAuthEncType   = $r.PreAuthEncType
            PreAuthEncName   = $PreAuthEncName
            PreAuthType      = $r.PreAuthType
            FailureCode      = $r.FailureCode
            TransitedServices= $r.TransitedServices
 
            ClientAddress    = $r.ClientAddress
            ClientPort       = $r.ClientPort
            ClientHost       = $clientHost
            AdvertizedEtypes = $r.AdvertizedEtypes
 
            ClientComputerEncMask    = $compInfo.Mask
            ClientComputerEncList    = if ($compInfo.List) { ($compInfo.List -join ',') } else { $null }
            ClientComputerHasAES     = $compInfo.HasAES
            ClientComputerKeySummary = $compInfo.KeySummary
 
            RC4Source        = $r.RC4Source
        }
    }
 
    # ----------------------------
    # Output
    # ----------------------------
    $columns = @(
     'DomainController','TimeCreated','EventID',
     'AccountName','AccountDomain','AccountEncMask','AccountEncList','AccountHasAES','AccountKeySummary',
     'ServiceName','ServiceID',
     'TicketOptions','TicketEncType','TicketEncName','SessionEncType','SessionEncName','PreAuthEncType','PreAuthEncName','PreAuthType',
     'FailureCode','TransitedServices',
     'ClientAddress','ClientPort','ClientHost','AdvertizedEtypes',
     'ClientComputerEncMask','ClientComputerEncList','ClientComputerHasAES','ClientComputerKeySummary',
     'RC4Source'
    )
 
    $enriched | Sort-Object TimeCreated |
        Select-Object $columns |
        Format-Table -AutoSize
 
    $enriched | Sort-Object TimeCreated |
        Select-Object $columns |
        Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
 
    Write-Host "`nReport written to: $OutCsv" -ForegroundColor Green
    Write-Host "Total RC4-related events (Ticket/Session/PreAuth): $($enriched.Count)" -ForegroundColor Yellow
}
else {
    Write-Host "`nNo RC4 in ticket, session, or pre-auth detected in the selected window." -ForegroundColor Gray
}