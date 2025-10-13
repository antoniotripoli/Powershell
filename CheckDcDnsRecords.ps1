<#
.SYNOPSIS
    Validate all essential SRV records for domain controllers.

.DESCRIPTION
    - Checks A records and all key SRV records:
        * _ldap._tcp.dc._msdcs.<domain>
        * _kerberos._tcp.<domain>
        * _kerberos._udp.<domain>
        * _ldap._tcp.<domain>
        * _kpasswd._tcp.<domain>
        * _kpasswd._udp.<domain>
    - Logs missing entries and optionally re-registers DNS.

.NOTES
    Run as Domain Admin with DNS Admin rights.
#>

$Domain = (Get-ADDomain).DNSRoot
$LogFile = "C:\Temp\DC_SRV_Audit_$(Get-Date -Format 'yyyyMMdd_HHmm').log"
$FixMissing = $true   # Set to $false for report only

$SRVRecords = @(
    "_ldap._tcp.dc._msdcs.$Domain",
    "_kerberos._tcp.$Domain",
    "_kerberos._udp.$Domain",
    "_ldap._tcp.$Domain",
    "_kpasswd._tcp.$Domain",
    "_kpasswd._udp.$Domain"
)

$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Tee-Object -FilePath $LogFile -Append
}

Write-Log "Starting SRV record validation for domain controllers in $Domain"
Write-Log "-----------------------------------------------------------"

foreach ($DC in $DCs) {
    Write-Log "Checking DNS for $DC"

    # Check A record
    if (-not (Resolve-DnsName -Name $DC -Type A -ErrorAction SilentlyContinue)) {
        Write-Log "❌ Missing A record for $DC"
        if ($FixMissing) {
            Write-Log "Attempting to re-register DNS for $DC"
            Invoke-Command -ComputerName $DC -ScriptBlock { ipconfig /registerdns }
        }
    } else {
        Write-Log "✔ A record exists for $DC"
    }

    # Check all SRV records
    foreach ($SRV in $SRVRecords) {
        $SRVCheck = Resolve-DnsName -Name $SRV -Type SRV -ErrorAction SilentlyContinue | Where-Object { $_.NameTarget -eq $DC }
        if (-not $SRVCheck) {
            Write-Log "❌ Missing SRV record for $DC in $SRV"
            if ($FixMissing) {
                Write-Log "Attempting to re-register DNS for $DC"
                Invoke-Command -ComputerName $DC -ScriptBlock { ipconfig /registerdns }
            }
        } else {
            Write-Log "✔ SRV record exists for $DC in $SRV"
        }
    }
}

Write-Log "-----------------------------------------------------------"
Write-Log "SRV validation completed. Log saved to $LogFile"
Write-Host "Audit complete. See log file: $LogFile"