
param(
    [int]$DaysBack = 7,
    [string[]]$EventDCs,
    [int]$Throttle = 4,
    [string]$OutputDir = (Get-Location).Path,
    [switch]$IncludeSummaries,
    [string]$DirectoryDC,
    [switch]$DeepKeys,
    [string]$KeyDC
)

$ErrorActionPreference = 'Stop'

function New-Path { param([string]$Path) if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null } (Resolve-Path -LiteralPath $Path).Path }

$OutDir = New-Path -Path $OutputDir
$StartTime = (Get-Date).AddDays(-[System.Math]::Abs($DaysBack))
$Rc4Ints = @(23,24)

function Convert-HexOrInt { param([string]$s) if ([System.String]::IsNullOrWhiteSpace($s)) { return $null } $v = $s.Trim(); if ($v -match '^0x[0-9A-Fa-f]+$') { return [System.Convert]::ToInt32($v, 16) } elseif ($v -match '^\d+$') { return [int]$v } else { return $null } }
function Get-Section { param([string]$Message,[string]$Title) if ([System.String]::IsNullOrWhiteSpace($Message)) { return $null } $t = [regex]::Escape($Title); $m = [regex]::Match($Message,"(?ms)$($t):\s*(.+?)(?:(?:\r?\n){2,}|^\w.+?Information:)"); if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null } }
function Get-Field { param([string]$Block,[string]$Label) if ([System.String]::IsNullOrWhiteSpace($Block)) { return $null } $l = [regex]::Escape($Label); $m = [regex]::Match($Block,"(?m)^\s*$($l)\s*:\s*(.+?)\s*$"); if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null } }
function Get-AdvertisedEtypes { param([string]$NetBlock) if ([System.String]::IsNullOrWhiteSpace($NetBlock)) { return $null } $lines = $NetBlock -split "`r?`n"; $start = $false; $list = @(); foreach ($ln in $lines) { if ($ln -match 'Adverti[sz]ed Etypes\s*:') { $start = $true; continue } if ($start) { if ($ln -match '^\s*$') { break } $list += $ln.Trim() } } if ($list.Count -gt 0) { $list -join '; ' } else { $null } }
function Test-PreAuthRc4InMessage { param([string]$msg) if ([System.String]::IsNullOrWhiteSpace($msg)) { return $false } return ($msg -match 'Pre-Authentication\s+EncryptionType\s*:\s*(0x17|0x18|23|24)') }

Write-Host ("RC4 events scan. Window: {0} → {1}" -f $StartTime,(Get-Date)) -ForegroundColor Cyan

try {
    if (-not $EventDCs) { $EventDCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName }
} catch { Write-Error "Failed to enumerate domain controllers: $($_.Exception.Message)"; return }

$jobs = @()
$AllEventRows = New-Object System.Collections.Generic.List[object]

$jobScript = {
    param($DC,$StartTime,$Rc4Ints)

    function Convert-HexOrInt { param([string]$s) if ([System.String]::IsNullOrWhiteSpace($s)) { return $null } $v = $s.Trim(); if ($v -match '^0x[0-9A-Fa-f]+$') { return [System.Convert]::ToInt32($v,16) } elseif ($v -match '^\d+$') { return [int]$v } else { return $null } }
    function Get-Section { param([string]$Message,[string]$Title) if ([System.String]::IsNullOrWhiteSpace($Message)) { return $null } $t = [regex]::Escape($Title); $m = [regex]::Match($Message,"(?ms)$($t):\s*(.+?)(?:(?:\r?\n){2,}|^\w.+?Information:)"); if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null } }
    function Get-Field { param([string]$Block,[string]$Label) if ([System.String]::IsNullOrWhiteSpace($Block)) { return $null } $l = [regex]::Escape($Label); $m = [regex]::Match($Block,"(?m)^\s*$($l)\s*:\s*(.+?)\s*$"); if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null } }
    function Get-AdvertisedEtypes { param([string]$NetBlock) if ([System.String]::IsNullOrWhiteSpace($NetBlock)) { return $null } $lines = $NetBlock -split "`r?`n"; $start = $false; $list = @(); foreach ($ln in $lines) { if ($ln -match 'Adverti[sz]ed Etypes\s*:') { $start = $true; continue } if ($start) { if ($ln -match '^\s*$') { break } $list += $ln.Trim() } } if ($list.Count -gt 0) { $list -join '; ' } else { $null } }
    function Test-PreAuthRc4InMessage { param([string]$msg) if ([System.String]::IsNullOrWhiteSpace($msg)) { return $false } return ($msg -match 'Pre-Authentication\s+EncryptionType\s*:\s*(0x17|0x18|23|24)') }

    $rows = New-Object System.Collections.Generic.List[object]
    $ids = @(4768,4769)

    try {
        $events = Get-WinEvent -ComputerName $DC -FilterHashtable @{ LogName='Security'; Id=$ids; StartTime=$StartTime } -ErrorAction Stop
    } catch {
        Write-Warning ("Get-WinEvent failed on {0}: {1}" -f $DC, $_.Exception.Message)
        return
    }

    foreach ($evt in $events) {
        $xml = $null; try { $xml = [xml]$evt.ToXml() } catch { $xml = $null }
        $msg = $evt.Message

        $TicketEncRaw = $null; $SessionEncRaw = $null; $PreAuthEncRaw = $null; $PreAuthType = $null
        if ($xml) {
            $n = $xml.SelectSingleNode("//Event/EventData/Data[@Name='TicketEncryptionType']");            if ($n) { $TicketEncRaw  = $n.InnerText.Trim() }
            $n = $xml.SelectSingleNode("//Event/EventData/Data[@Name='SessionEncryptionType']");           if ($n) { $SessionEncRaw = $n.InnerText.Trim() }
            $n = $xml.SelectSingleNode("//Event/EventData/Data[@Name='PreAuthenticationEncryptionType']"); if ($n) { $PreAuthEncRaw = $n.InnerText.Trim() }
            $n = $xml.SelectSingleNode("//Event/EventData/Data[@Name='PreAuthenticationType']");           if ($n) { $PreAuthType   = $n.InnerText.Trim() }
        }
        if (-not $TicketEncRaw -or -not $SessionEncRaw -or -not $PreAuthEncRaw -or -not $PreAuthType) {
            $add = Get-Section -Message $msg -Title 'Additional Information'
            if (-not $TicketEncRaw)  { $TicketEncRaw  = Get-Field -Block $add -Label 'Ticket Encryption Type' }
            if (-not $SessionEncRaw) { $SessionEncRaw = Get-Field -Block $add -Label 'Session Encryption Type' }
            if (-not $PreAuthEncRaw) { $PreAuthEncRaw = Get-Field -Block $add -Label 'Pre-Authentication EncryptionType' }
            if (-not $PreAuthType)   { $PreAuthType   = Get-Field -Block $add -Label 'Pre-Authentication Type' }
        }

        $ti = Convert-HexOrInt $TicketEncRaw
        $si = Convert-HexOrInt $SessionEncRaw
        $pi = Convert-HexOrInt $PreAuthEncRaw

        $isRc4Ticket  = ($ti -ne $null -and $Rc4Ints -contains $ti)
        $isRc4Session = ($si -ne $null -and $Rc4Ints -contains $si)
        $isRc4PreAuth = ($pi -ne $null -and $Rc4Ints -contains $pi)
        if (-not ($isRc4Ticket -or $isRc4Session -or $isRc4PreAuth)) {
            if ($evt.Id -eq 4768 -and (Test-PreAuthRc4InMessage -msg $msg)) { $isRc4PreAuth = $true }
        }
        if (-not ($isRc4Ticket -or $isRc4Session -or $isRc4PreAuth)) { continue }

        $AccountName = $null; $AccountDomain = $null; $UserID = $null; $AccountEncTypes = $null; $AccountKeys = $null
        $ServiceName = $null; $ServiceEncTypes = $null; $ServiceKeys = $null
        $DCEncTypes = $null; $DCKeys = $null
        $TicketOptions = $null; $FailureCode = $null; $TransitedServices = $null

        if ($xml) {
            $n = $xml.SelectSingleNode("//Event/EventData/Data[@Name='TargetUserName']");    if ($n) { $AccountName   = $n.InnerText.Trim() }
            $n = $xml.SelectSingleNode("//Event/EventData/Data[@Name='TargetDomainName']");  if ($n) { $AccountDomain = $n.InnerText.Trim() }
            $n = $xml.SelectSingleNode("//Event/EventData/Data[@Name='ServiceName']");       if ($n) { $ServiceName   = $n.InnerText.Trim() }
        }

        $acctBlock = Get-Section -Message $msg -Title 'Account Information'
        if (-not $AccountName)   { $AccountName   = Get-Field -Block $acctBlock -Label 'Account Name' }
        if (-not $AccountName)   { $AccountName   = Get-Field -Block $acctBlock -Label 'Target Account Name' }
        if (-not $AccountDomain) {
            $AccountDomain = Get-Field -Block $acctBlock -Label 'Account Domain'
            if (-not $AccountDomain) { $AccountDomain = Get-Field -Block $acctBlock -Label 'Supplied Realm Name' }
        }
        if (-not $UserID)            { $UserID           = Get-Field -Block $acctBlock -Label 'User ID' }
        if (-not $AccountEncTypes)   { $AccountEncTypes  = Get-Field -Block $acctBlock -Label 'MSDS-SupportedEncryptionTypes' }
        if (-not $AccountKeys)       { $AccountKeys      = Get-Field -Block $acctBlock -Label 'Available Keys' }

        $svcBlock = Get-Section -Message $msg -Title 'Service Information'
        if (-not $ServiceName)      { $ServiceName      = Get-Field -Block $svcBlock -Label 'Service Name' }
        if (-not $ServiceEncTypes)  { $ServiceEncTypes  = Get-Field -Block $svcBlock -Label 'MSDS-SupportedEncryptionTypes' }
        if (-not $ServiceKeys)      { $ServiceKeys      = Get-Field -Block $svcBlock -Label 'Available Keys' }

        $dcBlock = Get-Section -Message $msg -Title 'Domain Controller Information'
        if (-not $DCEncTypes)  { $DCEncTypes  = Get-Field -Block $dcBlock -Label 'MSDS-SupportedEncryptionTypes' }
        if (-not $DCKeys)      { $DCKeys      = Get-Field -Block $dcBlock -Label 'Available Keys' }

        $addBlock = Get-Section -Message $msg -Title 'Additional Information'
        if (-not $TicketOptions)     { $TicketOptions     = Get-Field -Block $addBlock -Label 'Ticket Options' }
        if (-not $FailureCode)       { $FailureCode       = Get-Field -Block $addBlock -Label 'Failure Code' }
        if (-not $TransitedServices) { $TransitedServices = Get-Field -Block $addBlock -Label 'Transited Services' }

        $netBlock = Get-Section -Message $msg -Title 'Network Information'
        $ClientAddress = Get-Field -Block $netBlock -Label 'Client Address'
        $ClientPort    = Get-Field -Block $netBlock -Label 'Client Port'
        if ([System.String]::IsNullOrWhiteSpace($ClientAddress)) { $ClientAddress = 'N/A' }
        if ([System.String]::IsNullOrWhiteSpace($ClientPort))    { $ClientPort    = 'N/A' }
        $AdvertizedEtypes = Get-AdvertisedEtypes -NetBlock $netBlock

        $RC4Source = if ($isRc4Ticket -and $isRc4Session -and $isRc4PreAuth) { 'Ticket+Session+PreAuth' }
            elseif ($isRc4Ticket -and $isRc4Session) { 'Ticket+Session' }
            elseif ($isRc4Ticket -and $isRc4PreAuth) { 'Ticket+PreAuth' }
            elseif ($isRc4Session -and $isRc4PreAuth) { 'Session+PreAuth' }
            elseif ($isRc4Ticket) { 'Ticket' }
            elseif ($isRc4Session) { 'Session' }
            elseif ($isRc4PreAuth) { 'PreAuth' } else { 'None' }

        $rows.Add([pscustomobject]@{
            DomainController = $DC
            TimeCreated      = $evt.TimeCreated
            EventID          = $evt.Id

            AccountName      = $AccountName
            AccountDomain    = $AccountDomain
            UserID           = $UserID
            AccountEncTypes  = $AccountEncTypes
            AccountKeys      = $AccountKeys

            ServiceName      = $ServiceName
            ServiceEncTypes  = $ServiceEncTypes
            ServiceKeys      = $ServiceKeys

            DCEncTypes       = $DCEncTypes
            DCKeys           = $DCKeys

            TicketOptions    = $TicketOptions
            TicketEncType    = $TicketEncRaw
            SessionEncType   = $SessionEncRaw
            PreAuthEncType   = $PreAuthEncRaw
            PreAuthType      = $PreAuthType
            FailureCode      = $FailureCode
            TransitedServices= $TransitedServices

            ClientAddress    = $ClientAddress
            ClientPort       = $ClientPort
            AdvertizedEtypes = $AdvertizedEtypes

            RC4Source        = $RC4Source
        })
    }
    $rows
}

foreach ($dc in $EventDCs) {
    while ($jobs.Count -ge $Throttle) {
        $done = Wait-Job -Job $jobs -Any -Timeout 10
        if ($done) {
            foreach ($j in @($done)) {
                $r = Receive-Job -Job $j -ErrorAction SilentlyContinue
                if ($r) { $AllEventRows.AddRange($r) }
                $jobs = $jobs | Where-Object { $_.Id -ne $j.Id }
                Remove-Job -Job $j -Force
            }
        }
    }
    $jobs += Start-Job -ScriptBlock $jobScript -ArgumentList $dc,$StartTime,$Rc4Ints
}
if ($jobs.Count -gt 0) {
    Wait-Job -Job $jobs | Out-Null
    foreach ($j in $jobs) {
        $r = Receive-Job -Job $j -ErrorAction SilentlyContinue
        if ($r) { $AllEventRows.AddRange($r) }
        Remove-Job -Job $j -Force
    }
}

$eventsCsv = Join-Path $OutDir 'RC4_Events_Detailed.csv'
$AllEventRows | Sort-Object TimeCreated | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $eventsCsv

$rc4PreAuth = ($AllEventRows | Where-Object { $_.RC4Source -match 'PreAuth' }).Count
$rc4Ticket  = ($AllEventRows | Where-Object { $_.RC4Source -match 'Ticket' }).Count
$rc4Session = ($AllEventRows | Where-Object { $_.RC4Source -match 'Session' }).Count

Write-Host ""
Write-Host "==== RC4 Events Summary ====" -ForegroundColor Green
Write-Host ("Event evidence (rows): {0}" -f $AllEventRows.Count)
Write-Host ("RC4 in PreAuth: {0}  | Ticket: {1}  | Session: {2}" -f $rc4PreAuth,$rc4Ticket,$rc4Session)
Write-Host ("Events CSV: {0}" -f (Resolve-Path $eventsCsv).Path)

if (-not $IncludeSummaries) { return }

function Get-DirUserBatch {
    param([string]$server)
    $props = @('msDS-SupportedEncryptionTypes','servicePrincipalName','Enabled','PasswordNeverExpires','LastLogonDate','AdminCount','UserAccountControl')
    if ([string]::IsNullOrWhiteSpace($server)) {
        Get-ADUser -LDAPFilter '(objectClass=user)' -Properties $props |
            Select-Object SamAccountName,DistinguishedName,Enabled,PasswordNeverExpires,LastLogonDate,AdminCount,
                @{n='SPNCount';e={($_.servicePrincipalName|Measure-Object).Count}},
                @{n='HasSPN';e={($_.servicePrincipalName -ne $null)}},
                @{n='SuppEnc';e={$_.{'msDS-SupportedEncryptionTypes'}}}
    } else {
        Get-ADUser -LDAPFilter '(objectClass=user)' -Server $server -Properties $props |
            Select-Object SamAccountName,DistinguishedName,Enabled,PasswordNeverExpires,LastLogonDate,AdminCount,
                @{n='SPNCount';e={($_.servicePrincipalName|Measure-Object).Count}},
                @{n='HasSPN';e={($_.servicePrincipalName -ne $null)}},
                @{n='SuppEnc';e={$_.{'msDS-SupportedEncryptionTypes'}}}
    }
}
function Get-DirCompBatch {
    param([string]$server)
    $props = @('msDS-SupportedEncryptionTypes','servicePrincipalName','Enabled','LastLogonDate','OperatingSystem','KerberosEncryptionType')
    if ([string]::IsNullOrWhiteSpace($server)) {
        Get-ADComputer -LDAPFilter '(objectClass=computer)' -Properties $props |
            Select-Object SamAccountName,DistinguishedName,Enabled,LastLogonDate,OperatingSystem,
                @{n='SPNCount';e={($_.servicePrincipalName|Measure-Object).Count}},
                @{n='HasSPN';e={($_.servicePrincipalName -ne $null)}},
                @{n='SuppEnc';e={$_.{'msDS-SupportedEncryptionTypes'}}},
                @{n='KerbTypes';e={$_.KerberosEncryptionType}}
    } else {
        Get-ADComputer -LDAPFilter '(objectClass=computer)' -Server $server -Properties $props |
            Select-Object SamAccountName,DistinguishedName,Enabled,LastLogonDate,OperatingSystem,
                @{n='SPNCount';e={($_.servicePrincipalName|Measure-Object).Count}},
                @{n='HasSPN';e={($_.servicePrincipalName -ne $null)}},
                @{n='SuppEnc';e={$_.{'msDS-SupportedEncryptionTypes'}}},
                @{n='KerbTypes';e={$_.KerberosEncryptionType}}
    }
}
function Decode-EncFlags {
    param([Nullable[int]]$v,[string[]]$kerbTypes)
    $o = [ordered]@{AllowsDES=$false;AllowsRC4=$false;AllowsAES128=$false;AllowsAES256=$false;Source='Attr'}
    if ($v -ne $null) {
        if ($v -band 0x01) { $o.AllowsDES=$true }
        if ($v -band 0x04) { $o.AllowsRC4=$true }
        if ($v -band 0x08) { $o.AllowsAES128=$true }
        if ($v -band 0x10) { $o.AllowsAES256=$true }
        return [pscustomobject]$o
    }
    if ($kerbTypes) {
        $o.Source='KerbTypes'
        if ($kerbTypes -contains 'DES')   { $o.AllowsDES=$true }
        if ($kerbTypes -contains 'RC4')   { $o.AllowsRC4=$true }
        if ($kerbTypes -contains 'AES128'){ $o.AllowsAES128=$true }
        if ($kerbTypes -contains 'AES256'){ $o.AllowsAES256=$true }
        return [pscustomobject]$o
    }
    $o.Source='Unknown'
    return [pscustomobject]$o
}

$users = Get-DirUserBatch -server $DirectoryDC
$comps = Get-DirCompBatch -server $DirectoryDC

$dirRows = New-Object System.Collections.Generic.List[object]
foreach ($u in $users) {
    $d = Decode-EncFlags -v $u.SuppEnc
    $dirRows.Add([pscustomobject]@{
        ObjectClass='User'
        SamAccountName=$u.SamAccountName
        DistinguishedName=$u.DistinguishedName
        Enabled=$u.Enabled
        PasswordNeverExpires=$u.PasswordNeverExpires
        LastLogonDate=$u.LastLogonDate
        AdminCount=$u.AdminCount
        HasSPN=$u.HasSPN
        SPNCount=$u.SPNCount
        SuppEncRaw=$u.SuppEnc
        AllowsDES=$d.AllowsDES
        AllowsRC4=$d.AllowsRC4
        AllowsAES128=$d.AllowsAES128
        AllowsAES256=$d.AllowsAES256
        AllowSource=$d.Source
    })
}
foreach ($c in $comps) {
    $d = Decode-EncFlags -v $c.SuppEnc -kerbTypes $c.KerbTypes
    $dirRows.Add([pscustomobject]@{
        ObjectClass='Computer'
        SamAccountName=$c.SamAccountName
        DistinguishedName=$c.DistinguishedName
        Enabled=$c.Enabled
        PasswordNeverExpires=$false
        LastLogonDate=$c.LastLogonDate
        AdminCount=$false
        HasSPN=$c.HasSPN
        SPNCount=$c.SPNCount
        SuppEncRaw=$c.SuppEnc
        AllowsDES=$d.AllowsDES
        AllowsRC4=$d.AllowsRC4
        AllowsAES128=$d.AllowsAES128
        AllowsAES256=$d.AllowsAES256
        OperatingSystem=$c.OperatingSystem
        AllowSource=$d.Source
    })
}

$eventsByAcct = $AllEventRows | Group-Object AccountName
$acctRows = New-Object System.Collections.Generic.List[object]
$dirIdx = @{}
foreach ($r in $dirRows) { $dirIdx[$r.SamAccountName.ToUpper()] = $r }

foreach ($g in $eventsByAcct) {
    $acct = $dirIdx[$g.Name.ToUpper()]
    if (-not $acct) { continue }
    $last = ($g.Group | Sort-Object TimeCreated | Select-Object -Last 1)
    $first= ($g.Group | Sort-Object TimeCreated | Select-Object -First 1)
    $acctRows.Add([pscustomobject]@{
        SamAccountName=$g.Name
        ObjectClass=$acct.ObjectClass
        Enabled=$acct.Enabled
        HasSPN=$acct.HasSPN
        SPNCount=$acct.SPNCount
        SuppEncRaw=$acct.SuppEncRaw
        AllowsDES=$acct.AllowsDES
        AllowsRC4=$acct.AllowsRC4
        AllowsAES128=$acct.AllowsAES128
        AllowsAES256=$acct.AllowsAES256
        FirstSeenRC4=$first.TimeCreated
        LastSeenRC4=$last.TimeCreated
        LastRC4Source=$last.RC4Source
        LastRC4DC=$last.DomainController
        LastRC4Client=$last.ClientAddress
        AllowSource=$acct.AllowSource
    })
}

$noEventButAllow = $dirRows | Where-Object { ($_.AllowsRC4 -or $_.AllowsDES) -and ($acctRows.SamAccountName -notcontains $_.SamAccountName) }
foreach ($r in $noEventButAllow) {
    $acctRows.Add([pscustomobject]@{
        SamAccountName=$r.SamAccountName
        ObjectClass=$r.ObjectClass
        Enabled=$r.Enabled
        HasSPN=$r.HasSPN
        SPNCount=$r.SPNCount
        SuppEncRaw=$r.SuppEncRaw
        AllowsDES=$r.AllowsDES
        AllowsRC4=$r.AllowsRC4
        AllowsAES128=$r.AllowsAES128
        AllowsAES256=$r.AllowsAES256
        FirstSeenRC4=$null
        LastSeenRC4=$null
        LastRC4Source=$null
        LastRC4DC=$null
        LastRC4Client=$null
        AllowSource=$r.AllowSource
    })
}

$acctCsv    = Join-Path $OutDir 'RC4_Accounts_Summary.csv'
$svcCsv     = Join-Path $OutDir 'RC4_ServiceAccounts_ToFix.csv'
$clientsCsv = Join-Path $OutDir 'RC4_ClientIPs_Advertising_RC4.csv'
$krbCsv     = Join-Path $OutDir 'RC4_Krbtgt_Status.csv'

$acctRows | Sort-Object ObjectClass,SamAccountName | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $acctCsv

($acctRows | Where-Object {
    ($_.HasSPN -and ($_.ObjectClass -in @('User','Computer'))) -and
    ( ($_.AllowsRC4 -or $_.AllowsDES) -or ($_.LastRC4Source -ne $null) )
}) | Sort-Object ObjectClass,SamAccountName | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $svcCsv

$clientRC4 = @()
if ($AllEventRows.Count -gt 0) {
    $clientRC4 = $AllEventRows | Where-Object { $_.AdvertizedEtypes -match 'rc4' } |
        Group-Object ClientAddress | ForEach-Object {
            [pscustomobject]@{
                ClientAddress = $_.Name
                Count = $_.Count
                SampleAccounts = ($_.Group | Select-Object -First 5 -ExpandProperty AccountName | Sort-Object -Unique) -join '; '
            }
        }
}
if ($clientRC4 -and $clientRC4.Count -gt 0) {
    $clientRC4 | Sort-Object -Property Count -Descending | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $clientsCsv
}

$krb = Get-ADUser -LDAPFilter '(samAccountName=krbtgt)' -Server ($DirectoryDC) -Properties msDS-SupportedEncryptionTypes,lastlogondate |
    Select-Object SamAccountName,DistinguishedName,LastLogonDate,@{n='SuppEncRaw';e={$_.{'msDS-SupportedEncryptionTypes'}}}
$krb | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $krbCsv

Write-Host ""
Write-Host "==== Summaries written (by request) ====" -ForegroundColor Green
Write-Host ("Accounts CSV: {0}" -f (Resolve-Path $acctCsv).Path)
Write-Host ("Service accounts to fix CSV: {0}" -f (Resolve-Path $svcCsv).Path)

if (Test-Path $clientsCsv) {
    Write-Host ("Clients advertising RC4 CSV: {0}" -f (Resolve-Path $clientsCsv).Path)
} else {
    Write-Host "Clients advertising RC4 CSV: None"
}

Write-Host ("krbtgt status CSV: {0}" -f (Resolve-Path $krbCsv).Path)
