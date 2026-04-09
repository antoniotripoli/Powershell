$DCs = Get-ADDomainController -Filter * |
       Select-Object -ExpandProperty HostName

$Results = Invoke-Command -ComputerName $DCs -ScriptBlock {

    $result = [ordered]@{
        ComputerName            = $env:COMPUTERNAME
        BootMode                = $null
        SecureBootEnabled       = $null
        KEK_2023_Present        = $null
        DB_UEFI_CA_2023_Present = $null
        UEFICA2023Status        = $null
        AvailableUpdates        = $null
        TPMWMI1801Present       = $false
        SecureBootState         = $null
        ActionRequired          = "No"
        Notes                   = $null
    }

    $SecureBootStateKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
    $ServicingKey       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'

    # ------------------------------------------------------------
    # BIOS vs UEFI
    # ------------------------------------------------------------
    if (-not (Test-Path $SecureBootStateKey)) {
        $result.BootMode        = 'BIOS'
        $result.SecureBootState = 'LegacyBIOS'
        $result.ActionRequired  = 'N/A'
        $result.Notes           = 'Legacy BIOS – Secure Boot not supported'
        return [pscustomobject]$result
    }

    $result.BootMode = 'UEFI'
    $sb = Get-ItemProperty $SecureBootStateKey
    $result.SecureBootEnabled = $sb.UEFISecureBootEnabled

    if ($sb.UEFISecureBootEnabled -ne 1) {
        $result.SecureBootState = 'SecureBootDisabled'
        $result.Notes = 'Secure Boot supported but disabled'
        return [pscustomobject]$result
    }

    # ------------------------------------------------------------
    # Secure Boot servicing registry (authoritative)
    # ------------------------------------------------------------
    if (Test-Path $ServicingKey) {
        $sp = Get-ItemProperty $ServicingKey -ErrorAction SilentlyContinue
        $result.UEFICA2023Status = $sp.UEFICA2023Status
        $result.AvailableUpdates = $sp.AvailableUpdates
    }

    # If Microsoft says "Updated", certs ARE present – force flags
    if ($result.UEFICA2023Status -eq 'Updated') {
        $result.DB_UEFI_CA_2023_Present = $true
        $result.KEK_2023_Present        = $true
    }

    # ------------------------------------------------------------
    # DB inspection (canonical string that you validated)
    # ------------------------------------------------------------
    try {
        $dbText = [System.Text.Encoding]::ASCII.GetString(
            (Get-SecureBootUEFI -Name db -ErrorAction Stop).Bytes
        )
        $result.DB_UEFI_CA_2023_Present = 
            $dbText -match 'Windows UEFI CA 2023'
    }
    catch {
        # Leave value as-is
    }

    # ------------------------------------------------------------
    # KEK inspection (may fail on some OEM firmware → isolated)
    # ------------------------------------------------------------
    try {
        $kekText = [System.Text.Encoding]::ASCII.GetString(
            (Get-SecureBootUEFI -Name kek -ErrorAction Stop).Bytes
        )
        $result.KEK_2023_Present =
            $kekText -match 'Microsoft Corporation KEK 2K CA 2023'
    }
    catch {
        # Leave value as-is
    }

    # ------------------------------------------------------------
    # TPM-WMI Event 1801 (authoritative failure signal)
    # ------------------------------------------------------------
    $event1801 = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-TPM-WMI'
        Id           = 1801
    } -MaxEvents 1 -ErrorAction SilentlyContinue

    if ($event1801) {
        $result.TPMWMI1801Present = $true
    }

    # ------------------------------------------------------------
    # Final classification (deterministic, evidence-based)
    # ------------------------------------------------------------
    if ($result.UEFICA2023Status -eq 'Updated') {
        $result.SecureBootState = 'Compliant'
        $result.ActionRequired  = 'No'
        $result.Notes           = 'Secure Boot 2023 remediation completed successfully'
    }
    elseif ($result.TPMWMI1801Present) {
        $result.SecureBootState = 'BlockedByFirmware'
        $result.ActionRequired  = 'Yes'
        $result.Notes           = 'Secure Boot update attempted and blocked by firmware (TPM-WMI 1801)'
    }
    elseif (-not $result.DB_UEFI_CA_2023_Present -and
            -not $result.KEK_2023_Present) {
        $result.SecureBootState = 'NotAttempted'
        $result.ActionRequired  = 'No'
        $result.Notes           = 'Secure Boot update not yet attempted'
    }
    else {
        $result.SecureBootState = 'Unknown'
        $result.Notes           = 'Secure Boot state could not be conclusively determined'
    }

    [pscustomobject]$result
}

$DomainName = (Get-ADDomain).DNSRoot

$Results |
    Select-Object `
        ComputerName,
        BootMode,
        SecureBootEnabled,
        KEK_2023_Present,
        DB_UEFI_CA_2023_Present,
        UEFICA2023Status,
        AvailableUpdates,
        TPMWMI1801Present,
        SecureBootState,
        ActionRequired,
        Notes |
    Export-Csv "SecureBoot-DC-Audit-$DomainName.csv" `
        -NoTypeInformation -Encoding UTF8
