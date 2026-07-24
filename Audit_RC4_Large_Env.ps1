#Requires -Modules ActiveDirectory
param(
    [int]$HoursBack = 6,
    [int]$Throttle = 12,
    [string]$OutputCsv = ".\Kerberos_FieldOnly_RC4_CurrentDomain.csv"
)

Import-Module ActiveDirectory -ErrorAction Stop
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Rc4Ints = @(23,24)
$StartTime = (Get-Date).AddHours(-[math]::Abs($HoursBack))

$curDomain = Get-ADDomain -Current LoggedOnUser -ErrorAction Stop
$lookupServer = $curDomain.PDCEmulator

$DomainControllers = @(
    Get-ADDomainController -Filter * -Server $lookupServer -ErrorAction Stop |
    Select-Object -ExpandProperty HostName |
    Sort-Object -Unique
)

if (@($DomainControllers).Count -eq 0) {
    throw "No domain controllers found for domain $($curDomain.DNSRoot)."
}

Write-Host ("Scanning CURRENT DOMAIN [{0}] | DCs: {1} | StartTime: {2}" -f $curDomain.DNSRoot, @($DomainControllers).Count, $StartTime) -ForegroundColor Cyan

$scriptBlock = {
    param(
        [string]$dc,
        [datetime]$startTime,
        [int[]]$rc4Ints
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function Convert-HexOrInt {
        param([string]$s)
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        $v = $s.Trim()
        if ($v -match '^0x[0-9A-Fa-f]+$') { return [Convert]::ToInt32($v, 16) }
        if ($v -match '^\d+$') { return [int]$v }
        return $null
    }

    function Get-SectionBlock {
        param(
            [string]$Message,
            [string]$SectionTitle
        )
        if ([string]::IsNullOrWhiteSpace($Message) -or [string]::IsNullOrWhiteSpace($SectionTitle)) { return $null }

        $escapedTitle = [regex]::Escape($SectionTitle)
        $pattern = "(?ms)^\s*$escapedTitle\s*:\s*(.*?)(?=^\s*\S.*Information\s*:|\z)"
        $m = [regex]::Match($Message, $pattern)
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
        return $null
    }

    function Get-FieldValue {
        param(
            [string]$Block,
            [string]$Label
        )
        if ([string]::IsNullOrWhiteSpace($Block) -or [string]::IsNullOrWhiteSpace($Label)) { return $null }

        $escapedLabel = [regex]::Escape($Label)
        $m = [regex]::Match($Block, "(?m)^\s*$escapedLabel\s*:\s*(.+?)\s*$")
        if ($m.Success) { return $m.Groups[1].Value.Trim() }
        return $null
    }

    function Get-AdvertisedEtypesFromNetworkBlock {
        param([string]$NetworkBlock)
        if ([string]::IsNullOrWhiteSpace($NetworkBlock)) { return $null }

        $lines = $NetworkBlock -split "`r?`n"
        $started = $false
        $list = New-Object 'System.Collections.Generic.List[string]'

        foreach ($ln in $lines) {
            if ($ln -match 'Adverti[sz]ed Etypes\s*:') {
                $started = $true
                continue
            }
            if ($started) {
                if ($ln -match '^\s*$') { break }
                $null = $list.Add($ln.Trim())
            }
        }

        if ($list.Count -gt 0) { return ($list -join '; ') }
        return $null
    }

    function Build-EventDataHashtable {
        param([xml]$Xml)

        $h = @{}
        $nodes = $Xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")

        foreach ($n in $nodes) {
            $attr = $n.Attributes['Name']
            if ($null -eq $attr) { continue }

            $key = $attr.Value
            if ([string]::IsNullOrWhiteSpace($key)) { continue }

            $h[$key.Trim()] = $n.InnerText
        }

        return $h
    }

    $rows = New-Object 'System.Collections.Generic.List[object]'

    $events = @(
        Get-WinEvent -ComputerName $dc -FilterHashtable @{
            LogName = 'Security'
            Id = @(4768,4769)
            StartTime = $startTime
        } -ErrorAction SilentlyContinue
    )

    foreach ($evt in $events) {
        $msg = $evt.Message
        $xml = $null

        try {
            $xml = [xml]$evt.ToXml()
        }
        catch {
            $xml = $null
        }

        $data = @{}
        if ($null -ne $xml) {
            $data = Build-EventDataHashtable -Xml $xml
        }

        $ticketEncRaw = $data['TicketEncryptionType']
        $sessionEncRaw = $data['SessionEncryptionType']
        if (-not $sessionEncRaw) { $sessionEncRaw = $data['SessionKeyEncryptionType'] }

        $preAuthEncRaw = $data['PreAuthEncryptionType']
        $preAuthType = $data['PreAuthType']

        $addBlock = Get-SectionBlock -Message $msg -SectionTitle 'Additional Information'

        if (-not $ticketEncRaw) {
            $ticketEncRaw = Get-FieldValue -Block $addBlock -Label 'Ticket Encryption Type'
        }
        if (-not $sessionEncRaw) {
            $sessionEncRaw = Get-FieldValue -Block $addBlock -Label 'Session Encryption Type'
        }
        if (-not $preAuthEncRaw) {
            $preAuthEncRaw = Get-FieldValue -Block $addBlock -Label 'Pre-Authentication EncryptionType'
            if (-not $preAuthEncRaw) {
                $preAuthEncRaw = Get-FieldValue -Block $addBlock -Label 'Pre-Authentication Encryption Type'
            }
        }
        if (-not $preAuthType) {
            $preAuthType = Get-FieldValue -Block $addBlock -Label 'Pre-Authentication Type'
        }

        $ti = Convert-HexOrInt -s $ticketEncRaw
        $si = Convert-HexOrInt -s $sessionEncRaw
        $pi = Convert-HexOrInt -s $preAuthEncRaw

        $isRc4Ticket = ($null -ne $ti -and ($rc4Ints -contains $ti))
        $isRc4Session = ($null -ne $si -and ($rc4Ints -contains $si))
        $isRc4PreAuth = ($null -ne $pi -and ($rc4Ints -contains $pi))

        if (-not ($isRc4Ticket -or $isRc4Session -or $isRc4PreAuth)) { continue }

        if ($isRc4Ticket -and $isRc4Session -and $isRc4PreAuth) { $rc4Source = 'Ticket+Session+PreAuth' }
        elseif ($isRc4Ticket -and $isRc4Session) { $rc4Source = 'Ticket+Session' }
        elseif ($isRc4Ticket -and $isRc4PreAuth) { $rc4Source = 'Ticket+PreAuth' }
        elseif ($isRc4Session -and $isRc4PreAuth) { $rc4Source = 'Session+PreAuth' }
        elseif ($isRc4Ticket) { $rc4Source = 'Ticket' }
        elseif ($isRc4Session) { $rc4Source = 'Session' }
        elseif ($isRc4PreAuth) { $rc4Source = 'PreAuth' }
        else { $rc4Source = 'Unknown' }

        $acctBlock = Get-SectionBlock -Message $msg -SectionTitle 'Account Information'
        $svcBlock = Get-SectionBlock -Message $msg -SectionTitle 'Service Information'
        $dcBlock = Get-SectionBlock -Message $msg -SectionTitle 'Domain Controller Information'
        $netBlock = Get-SectionBlock -Message $msg -SectionTitle 'Network Information'

        $accountName = $data['TargetUserName']
        if (-not $accountName) { $accountName = Get-FieldValue -Block $acctBlock -Label 'Account Name' }

        $accountDomain = $data['TargetDomainName']
        if (-not $accountDomain) { $accountDomain = Get-FieldValue -Block $acctBlock -Label 'Supplied Realm Name' }

        $serviceName = $data['ServiceName']
        if (-not $serviceName) { $serviceName = Get-FieldValue -Block $svcBlock -Label 'Service Name' }

        $accEncTypes = $data['AccountSupportedEncryptionTypes']
        if (-not $accEncTypes) { $accEncTypes = Get-FieldValue -Block $acctBlock -Label 'MSDS-SupportedEncryptionTypes' }

        $accKeys = $data['AccountAvailableKeys']
        if (-not $accKeys) { $accKeys = Get-FieldValue -Block $acctBlock -Label 'Available Keys' }

        $svcEncTypes = $data['ServiceSupportedEncryptionTypes']
        if (-not $svcEncTypes) { $svcEncTypes = Get-FieldValue -Block $svcBlock -Label 'MSDS-SupportedEncryptionTypes' }

        $svcKeys = $data['ServiceAvailableKeys']
        if (-not $svcKeys) { $svcKeys = Get-FieldValue -Block $svcBlock -Label 'Available Keys' }

        $dcEncTypes = $data['DCSupportedEncryptionTypes']
        if (-not $dcEncTypes) { $dcEncTypes = Get-FieldValue -Block $dcBlock -Label 'MSDS-SupportedEncryptionTypes' }

        $dcKeys = $data['DCAvailableKeys']
        if (-not $dcKeys) { $dcKeys = Get-FieldValue -Block $dcBlock -Label 'Available Keys' }

        $clientAddr = $data['IpAddress']
        if (-not $clientAddr) { $clientAddr = Get-FieldValue -Block $netBlock -Label 'Client Address' }

        $advEtypes = $data['ClientAdvertizedEncryptionTypes']
        if (-not $advEtypes) { $advEtypes = Get-AdvertisedEtypesFromNetworkBlock -NetworkBlock $netBlock }

        $null = $rows.Add([pscustomobject]@{
            DomainController = $dc
            TimeCreated = $evt.TimeCreated
            EventID = $evt.Id
            AccountName = $accountName
            AccountDomain = $accountDomain
            'Account MSDS-SupportedEncryptionTypes' = $accEncTypes
            'Account Available Keys' = $accKeys
            ServiceName = $serviceName
            'Service MSDS-SupportedEncryptionTypes' = $svcEncTypes
            'Service Available Keys' = $svcKeys
            'DC MSDS-SupportedEncryptionTypes' = $dcEncTypes
            'DC Available Keys' = $dcKeys
            ClientAddress = $clientAddr
            AdvertizedEtypes = $advEtypes
            TicketEncryptionType = $ticketEncRaw
            SessionEncryptionType = $sessionEncRaw
            PreAuthenticationType = $preAuthType
            PreAuthenticationEncryptionType = $preAuthEncRaw
            RC4Source = $rc4Source
        })
    }

    return $rows
}

$columns = @(
    'DomainController',
    'TimeCreated',
    'EventID',
    'AccountName',
    'AccountDomain',
    'Account MSDS-SupportedEncryptionTypes',
    'Account Available Keys',
    'ServiceName',
    'Service MSDS-SupportedEncryptionTypes',
    'Service Available Keys',
    'DC MSDS-SupportedEncryptionTypes',
    'DC Available Keys',
    'ClientAddress',
    'AdvertizedEtypes',
    'TicketEncryptionType',
    'SessionEncryptionType',
    'PreAuthenticationType',
    'PreAuthenticationEncryptionType',
    'RC4Source'
)

$OutputCsvFull = if ([IO.Path]::IsPathRooted($OutputCsv)) {
    $OutputCsv
}
else {
    Join-Path -Path (Get-Location).Path -ChildPath $OutputCsv
}

$ErrorLog = "$OutputCsvFull.errors.txt"
$outDir = Split-Path -Path $OutputCsvFull -Parent

if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

if (Test-Path -LiteralPath $OutputCsvFull) {
    $bak = "$OutputCsvFull.$(Get-Date -Format 'yyyyMMdd_HHmmss').bak"
    Copy-Item -LiteralPath $OutputCsvFull -Destination $bak -Force
    Remove-Item -LiteralPath $OutputCsvFull -Force
}

if (Test-Path -LiteralPath $ErrorLog) {
    Remove-Item -LiteralPath $ErrorLog -Force
}

$pool = [RunspaceFactory]::CreateRunspacePool(1, $Throttle)
$pool.Open()

$jobs = @()

foreach ($dc in $DomainControllers) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript($scriptBlock.ToString()).AddArgument($dc).AddArgument($StartTime).AddArgument($Rc4Ints)
    $handle = $ps.BeginInvoke()

    $jobs += [pscustomobject]@{
        DC = $dc
        PS = $ps
        Handle = $handle
    }
}

$headerWritten = $false
$completed = 0
$totalRows = 0
$rc4Counts = @{}
$pending = @($jobs)

while (@($pending).Count -gt 0) {
    $doneNow = @($pending | Where-Object { $_.Handle.IsCompleted })

    if (@($doneNow).Count -eq 0) {
        Start-Sleep -Milliseconds 250
        continue
    }

    foreach ($j in $doneNow) {
        try {
            $r = @($j.PS.EndInvoke($j.Handle))

            if (@($r).Count -gt 0) {
                $chunk = @($r | Sort-Object TimeCreated)

                if (-not $headerWritten) {
                    $chunk | Select-Object $columns | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputCsvFull
                    $headerWritten = $true
                }
                else {
                    $chunk | Select-Object $columns | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputCsvFull -Append
                }

                $totalRows += @($chunk).Count

                foreach ($g in @($chunk | Group-Object RC4Source)) {
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
            $completed++
            $pending = @($pending | Where-Object { $_ -ne $j })

            Write-Host ("Progress: {0}/{1} DCs completed | Rows so far: {2}" -f $completed, @($jobs).Count, $totalRows) -ForegroundColor Yellow
        }
    }
}

$pool.Close()
$pool.Dispose()

if (-not $headerWritten) {
    $empty = [pscustomobject]@{}
    foreach ($c in $columns) {
        $empty | Add-Member -NotePropertyName $c -NotePropertyValue $null
    }
    $empty | Select-Object $columns | Select-Object -First 0 | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputCsvFull
}

Write-Host ("DONE. Rows: {0}  CSV: {1}" -f $totalRows, (Resolve-Path -LiteralPath $OutputCsvFull).Path) -ForegroundColor Green

if ($rc4Counts.Count -gt 0) {
    $summary = ($rc4Counts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
    Write-Host ("RC4 by source: {0}" -f $summary) -ForegroundColor Cyan
}
else {
    Write-Host "RC4 by source: no rows" -ForegroundColor Cyan
}

if (Test-Path -LiteralPath $ErrorLog) {
    Write-Host ("Some DCs had errors. See: {0}" -f (Resolve-Path -LiteralPath $ErrorLog).Path) -ForegroundColor DarkYellow
}
