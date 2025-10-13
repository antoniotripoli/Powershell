<#
.SYNOPSIS
    Validate DNS records (A, SRV, PTR) for all domain controllers and optionally fix missing entries.

.DESCRIPTION
    - Checks A records in forward lookup zone.
    - Checks all key SRV records for AD services.
    - Checks PTR records in reverse lookup zones.
    - Re-registers DNS if records are missing.

.NOTES
    Run as Domain Admin with DNS Admin rights.
#>

$Domain = (Get-ADDomain).DNSRoot
$LogFile = "C:\Temp\DC_DNS_Audit_$(Get-Date -Format 'yyyyMMdd_HHmm').log"
$FixMissing = $true   # Set to $false for report only

$SRVRecords = @(
    "_ldap._tcp.dc._msdcs.$Domain",
    "_kerberos._tcp.$Domain",
    "_kerberos._udp.$Domain",
    "_ldap._tcp.$Domain",
    "_kpasswd._tcp.$Domain",
    "_kpasswd._udp.$Domain"
)

$DCs = Get-ADDomainController -Filter * | Select-Object HostName, IPv4Address

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogFile -Append
}

Write-Log "Starting DNS validation for domain controllers in $Domain"
Write-Log "-----------------------------------------------------------"

foreach ($DC in $DCs) {
    Write-Log "Checking DNS for $($DC.HostName)"

    # Check A record
    if (-not (Resolve-DnsName -Name $DC.HostName -Type A -ErrorAction SilentlyContinue)) {
        Write-Log "❌ Missing A record for $($DC.HostName)"
        if ($FixMissing) {
            Write-Log "Attempting to re-register DNS for $($DC.HostName)"
            Invoke-Command -ComputerName $DC.HostName -ScriptBlock { ipconfig /registerdns }
        }
    } else {
        Write-Log "✔ A record exists for $($DC.HostName)"
    }

    # Check PTR record (reverse lookup)
    $PTR = Resolve-DnsName -Name $DC.IPv4Address -Type PTR -ErrorAction SilentlyContinue
    if (-not $PTR) {
        Write-Log "❌ Missing PTR record for IP $($DC.IPv4Address)"
        if ($FixMissing) {
            Write-Log "Attempting to re-register DNS for $($DC.HostName)"
            Invoke-Command -ComputerName $DC.HostName -ScriptBlock { ipconfig /registerdns }
        }
    } else {
        Write-Log "✔ PTR record exists for $($DC.IPv4Address)"
    }

    # Check SRV records
    foreach ($SRV in $SRVRecords) {
        $SRVCheck = Resolve-DnsName -Name $SRV -Type SRV -ErrorAction SilentlyContinue | Where-Object { $_.NameTarget -eq $DC.HostName }
        if (-not $SRVCheck) {
            Write-Log "❌ Missing SRV record for $($DC.HostName) in $SRV"
            if ($FixMissing) {
                Write-Log "Attempting to re-register DNS for $($DC.HostName)"
                Invoke-Command -ComputerName $DC.HostName -ScriptBlock { ipconfig /registerdns }
            }
        } else {
            Write-Log "✔ SRV record exists for $($DC.HostName) in $SRV"
        }
    }
}

Write-Log "-----------------------------------------------------------"
Write-Log "Validation completed. Log saved to $LogFile"
Write-Host "Process complete. See log file: $LogFile"