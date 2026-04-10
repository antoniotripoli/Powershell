$DCs = Get-ADDomainController -Filter * |
       Select-Object -ExpandProperty HostName

$Results = Invoke-Command -ComputerName $DCs -ScriptBlock {

    $result = [ordered]@{
        ComputerName                = $env:COMPUTERNAME
        BootMode                    = $null
        SecureBootEnabled           = $null
        ServicingPayloadPresent     = $true
        AvailableUpdates            = $null
        AvailableUpdatesMeaning     = $null
        KEK_2023_Present            = $null
        DB_UEFI_CA_2023_Present     = $null
        UEFICA2023Status            = $null
        TPMWMI1801Present           = $false
        SecureBoot1808Present       = $false
        SecureBootState             = $null
        ActionRequired              = 'No'
        Notes                       = $null
    }

    $SecureBootStateKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
    $SecureBootKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
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
    $sbState = Get-ItemProperty $SecureBootStateKey -ErrorAction SilentlyContinue
    $result.SecureBootEnabled = $sbState.UEFISecureBootEnabled

    if ($sbState.UEFISecureBootEnabled -ne 1) {
        $result.SecureBootState = 'SecureBootDisabled'
        $result.Notes           = 'Secure Boot supported but disabled'
        return [pscustomobject]$result
    }

    # ------------------------------------------------------------
    # Servicing payload presence (authoritative)
    # ------------------------------------------------------------
    if (-not (Test-Path $ServicingKey)) {
        $result.ServicingPayloadPresent = $false
        $result.AvailableUpdates        = 'N/A'
        $result.AvailableUpdatesMeaning = 'Missing payload – Secure Boot servicing framework not present'
        $result.SecureBootState         = 'PayloadMissing'
        $result.ActionRequired          = 'Yes'
        $result.Notes                   = 'Required Secure Boot servicing updates not installed'
        return [pscustomobject]$result
    }

    $sp = Get-ItemProperty $ServicingKey -ErrorAction SilentlyContinue
    $result.UEFICA2023Status = $sp.UEFICA2023Status

    # ------------------------------------------------------------
    # AvailableUpdates (CORRECT LOCATION + explanation)
    # ------------------------------------------------------------
    $sbKey = Get-ItemProperty $SecureBootKey -ErrorAction SilentlyContinue

    if ($sbKey.PSObject.Properties.Name -contains 'AvailableUpdates') {
        $au = [int]$sbKey.AvailableUpdates
        $result.AvailableUpdates = $au

        switch ($au) {
            0        { $result.AvailableUpdatesMeaning = 'Idle – no Secure Boot action requested' }
            16384    { $result.AvailableUpdatesMeaning = 'Completed – remediation finished (server/manual path)' }
            16640    { $result.AvailableUpdatesMeaning = 'Reboot required – servicing in progress' }
            22852    { $result.AvailableUpdatesMeaning = 'Opt-in requested – Secure Boot remediation trigger set' }
            default  { $result.AvailableUpdatesMeaning = ('Unknown value (0x{0:X})' -f $au) }
        }
    }
    else {
        $result.AvailableUpdates        = 'NotPresent'
        $result.AvailableUpdatesMeaning = 'Value not present'
    }

    # ------------------------------------------------------------
    # Firmware inspection (best-effort, non-blocking)
    # ------------------------------------------------------------
    try {
        $dbText = [System.Text.Encoding]::ASCII.GetString(
            (Get-SecureBootUEFI -Name db -ErrorAction Stop).Bytes
        )
        $result.DB_UEFI_CA_2023_Present =
            $dbText -match 'Windows UEFI CA 2023'
    }
    catch {}

    try {
        $kekText = [System.Text.Encoding]::ASCII.GetString(
            (Get-SecureBootUEFI -Name kek -ErrorAction Stop).Bytes
        )
        $result.KEK_2023_Present =
            $kekText -match 'Microsoft Corporation KEK 2K CA 2023'
    }
    catch {}

    # ------------------------------------------------------------
    # TPM-WMI Event 1801 (block signal)
    # ------------------------------------------------------------
    if (Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Id      = 1801
    } -MaxEvents 1 -ErrorAction SilentlyContinue) {

        $result.TPMWMI1801Present = $true
    }

    # ------------------------------------------------------------
    # SecureBoot-Servicing Event 1808 (final success)
    # ------------------------------------------------------------
    if (Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Id      = 1808
    } -MaxEvents 1 -ErrorAction SilentlyContinue) {

        $result.SecureBoot1808Present = $true
    }

    # ------------------------------------------------------------
    # Final classification
    # ------------------------------------------------------------
    if ($result.UEFICA2023Status -eq 'Updated' -and $result.SecureBoot1808Present) {
        $result.SecureBootState = 'Compliant'
        $result.Notes           = 'Secure Boot 2023 remediation completed successfully'
    }
    elseif ($result.UEFICA2023Status -eq 'Updated') {
        $result.SecureBootState = 'PreProvisioned'
        $result.Notes           = 'Certificates present but no OS remediation event'
    }
    elseif ($result.TPMWMI1801Present) {
        $result.SecureBootState = 'BlockedByFirmware'
        $result.ActionRequired  = 'Yes'
        $result.Notes           = 'Secure Boot remediation blocked by firmware'
    }
    else {
        $result.SecureBootState = 'NotAttempted'
        $result.Notes           = 'Servicing payload present but remediation not attempted'
    }

    [pscustomobject]$result
}

$DomainName = (Get-ADDomain).DNSRoot

$Results |
    Select-Object `
        ComputerName,
        BootMode,
        SecureBootEnabled,
        ServicingPayloadPresent,
        AvailableUpdates,
        AvailableUpdatesMeaning,
        KEK_2023_Present,
        DB_UEFI_CA_2023_Present,
        UEFICA2023Status,
        TPMWMI1801Present,
        SecureBoot1808Present,
        SecureBootState,
        ActionRequired,
        Notes |
    Export-Csv "SecureBoot-DC-Audit-$DomainName.csv" `
        -NoTypeInformation -Encoding UTF8