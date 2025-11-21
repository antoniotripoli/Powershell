# Script: Find-DesAccountsAndTrusts.ps1
# Purpose: Identify AD user accounts and trusts using DES/RC4/AES encryption
# Provides a menu to check users, trusts, domain encryption types, export reports, or exit
# Includes a legend for msDS-SupportedEncryptionTypes values

function Get-EncryptionLegend {
    param([int]$value)

    switch ($value) {
        0  { "Not set â†’ Domain defaults (AES128 + AES256)" }
        1  { "DES-CBC-CRC" }
        2  { "DES-CBC-MD5" }
        4  { "RC4-HMAC" }
        8  { "AES128" }
        16 { "AES256" }
        24 { "AES128 + AES256" }
        default { "Unknown/Multiple ($value)" }
    }
}

function Get-DesUsers {
    Write-Host "`nSearching for user accounts using DES flag..."
    $users = Get-ADUser -Filter * -Properties userAccountControl, msDS-SupportedEncryptionTypes |
        Where-Object { ($_.userAccountControl -band 0x200000) -ne 0 }
    if ($users) {
        $users | Select-Object Name, DistinguishedName, userAccountControl,
            @{Name="EncryptionType";Expression={Get-EncryptionLegend $_."msDS-SupportedEncryptionTypes"}},
            @{Name="FlagsLegend";Expression={
                $flags = @()
                $val = $_.userAccountControl
                if ($val -band 0x200000) { $flags += "USE_DES_KEY_ONLY" }
                if ($val -band 0x2)      { $flags += "ACCOUNTDISABLE" }
                if ($val -band 0x20)     { $flags += "PASSWD_NOTREQD" }
                if ($val -band 0x800000) { $flags += "DONT_REQUIRE_PREAUTH" }
                if ($val -band 0x1000000){ $flags += "TRUSTED_FOR_DELEGATION" }
                if ($flags.Count -gt 0) { $flags -join ", " } else { "None" }
            }}
    } else {
        Write-Host "No user accounts found with DES flag."
    }
}

function Get-DesTrusts {
    Write-Host "`nSearching for trusts using DES..."
    $trusts = Get-ADTrust -Filter * -Properties msDS-SupportedEncryptionTypes |
        Where-Object { $_."msDS-SupportedEncryptionTypes" -eq 1 }
    if ($trusts) {
        $trusts | Select-Object Name, Source, Target, msDS-SupportedEncryptionTypes,
            @{Name="EncryptionType";Expression={Get-EncryptionLegend $_."msDS-SupportedEncryptionTypes"}}
    } else {
        Write-Host "No trusts found restricted to DES."
    }
}

function Check-DomainEncryption {
    Write-Host "`n--- Domain Default Kerberos Encryption Types ---"
    $domain = Get-ADDomain
    $raw    = $domain.'msDS-DefaultEncryptionTypes'
    $value  = if ($raw) { [int]$raw } else { 0 }

    $types = @()
    if ($value -band 1)  { $types += "DES-CBC-CRC" }
    if ($value -band 2)  { $types += "DES-CBC-MD5" }
    if ($value -band 4)  { $types += "RC4-HMAC" }
    if ($value -band 8)  { $types += "AES128" }
    if ($value -band 16) { $types += "AES256" }

    $decoded = if ($types.Count -gt 0) { $types -join " + " }
               else { "Not set â†’ Domain defaults (AES128 + AES256)" }

    [PSCustomObject]@{
        DomainName          = $domain.Name
        RawValue            = if ($raw) { $raw } else { "(blank)" }
        EffectiveEncryption = $decoded
    } | Format-Table -AutoSize
}

function Check-TrustEncryption {
    Write-Host "`n--- Trusts Encryption Types ---"
    $trusts = Get-ADTrust -Filter * -Properties msDS-SupportedEncryptionTypes
    if ($trusts) {
        $trusts | ForEach-Object {
            $_ | Add-Member -NotePropertyName "EncryptionType" -NotePropertyValue (Get-EncryptionLegend $_."msDS-SupportedEncryptionTypes") -Force
            $_
        } | Select-Object Name, Source, Target, msDS-SupportedEncryptionTypes, EncryptionType | Format-Table -AutoSize
    } else {
        Write-Host "No trusts found."
    }
}

function Check-ComputerEncryption {
    Write-Host "`n--- Computer Accounts Encryption Types ---"

    Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes |
        Select-Object Name,
            @{Name="RawValue";Expression={$_."msDS-SupportedEncryptionTypes"}},
            @{Name="SupportedEncryption";Expression={
                $value = if ($_."msDS-SupportedEncryptionTypes") { [int]$_."msDS-SupportedEncryptionTypes" } else { 0 }
                $types = @()
                if ($value -band 1)  { $types += "DES-CBC-CRC" }
                if ($value -band 2)  { $types += "DES-CBC-MD5" }
                if ($value -band 4)  { $types += "RC4-HMAC" }
                if ($value -band 8)  { $types += "AES128" }
                if ($value -band 16) { $types += "AES256" }
                if ($types.Count -gt 0) { $types -join " + " } else { "Not set → Domain defaults (AES128 + AES256)" }
            }},
            @{Name="WeakFlag";Expression={
                $value = if ($_."msDS-SupportedEncryptionTypes") { [int]$_."msDS-SupportedEncryptionTypes" } else { 0 }
                if (($value -band 1) -or ($value -band 2)) { "DES" }
                elseif ($value -band 4) { "RC4" }
                else { "None" }
            }} |
        Format-Table Name, RawValue, SupportedEncryption, WeakFlag -AutoSize
}

function Export-DomainReport {
    $domain = Get-ADDomain | Select-Object Name, msDS-SupportedEncryptionTypes
    $domain | ForEach-Object {
        $_ | Add-Member -NotePropertyName "EncryptionType" -NotePropertyValue (Get-EncryptionLegend $_.msDS-SupportedEncryptionTypes) -Force
        $_
    } | Export-Csv -Path ".\Domain_Encryption_Report.csv" -NoTypeInformation -Force
    Write-Host "Domain report saved to Domain_Encryption_Report.csv"
}

function Export-TrustReport {
    $trusts = Get-ADTrust -Filter * -Properties msDS-SupportedEncryptionTypes
    $trusts | ForEach-Object {
        $_ | Add-Member -NotePropertyName "EncryptionType" -NotePropertyValue (Get-EncryptionLegend $_."msDS-SupportedEncryptionTypes") -Force
        $_
    } | Select-Object Name, Source, Target, msDS-SupportedEncryptionTypes, EncryptionType |
        Export-Csv -Path ".\Trusts_Encryption_Report.csv" -NoTypeInformation -Force
    Write-Host "Trusts report saved to Trusts_Encryption_Report.csv"
}

function Export-UserReport {
    $users = Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes, userAccountControl |
        Select-Object Name, DistinguishedName, msDS-SupportedEncryptionTypes,
            @{Name="DESFlag";Expression={($_.userAccountControl -band 0x200000) -ne 0}},
            @{Name="EncryptionType";Expression={Get-EncryptionLegend $_."msDS-SupportedEncryptionTypes"}}
    $users | Export-Csv -Path ".\Users_Encryption_Report.csv" -NoTypeInformation -Force
    Write-Host "Users report saved to Users_Encryption_Report.csv"
}

function Export-ComputerReport {
    $computers = Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes |
        Select-Object Name,
            @{Name="RawValue";Expression={$_."msDS-SupportedEncryptionTypes"}},
            @{Name="SupportedEncryption";Expression={
                $value = if ($_."msDS-SupportedEncryptionTypes") { [int]$_."msDS-SupportedEncryptionTypes" } else { 0 }
                $types = @()
                if ($value -band 1)  { $types += "DES-CBC-CRC" }
                if ($value -band 2)  { $types += "DES-CBC-MD5" }
                if ($value -band 4)  { $types += "RC4-HMAC" }
                if ($value -band 8)  { $types += "AES128" }
                if ($value -band 16) { $types += "AES256" }
                if ($types.Count -gt 0) { $types -join " + " } else { "Not set → Domain defaults (AES128 + AES256)" }
            }},
            @{Name="WeakFlag";Expression={
                $value = if ($_."msDS-SupportedEncryptionTypes") { [int]$_."msDS-SupportedEncryptionTypes" } else { 0 }
                if (($value -band 1) -or ($value -band 2)) { "DES" }
                elseif ($value -band 4) { "RC4" }
                else { "None" }
            }}

    $computers | Export-Csv -Path ".\Computers_Encryption_Report.csv" -NoTypeInformation -Force
    Write-Host "Computers report saved to Computers_Encryption_Report.csv"
}


function Show-Menu {
    Clear-Host
    Write-Host "====================================="
    Write-Host "   DES Encryption Audit Menu"
    Write-Host "====================================="
    Write-Host "1. Check User Accounts (DES flag)"
    Write-Host "2. Check Trusts (DES only)"
    Write-Host "3. Check Domain Encryption Types"
    Write-Host "4. Check Trusts Encryption Types"
    Write-Host "5. Check Computers' Encryption"
    Write-Host "6. Export Domain Report (CSV)"
    Write-Host "7. Export Trusts Report (CSV)"
    Write-Host "8. Export Users Report (CSV)"
    Write-Host "9. Export Computer Report (CSV)"
    Write-Host "10. Exit"
    Write-Host "====================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option (1-10)"

    switch ($choice) {
        "1" { Get-DesUsers | Format-Table -AutoSize }
        "2" { Get-DesTrusts | Format-Table -AutoSize }
        "3" { Check-DomainEncryption }
        "4" { Check-TrustEncryption }
        "5" { Check-ComputerEncryption }
        "6" { Export-DomainReport }
        "7" { Export-TrustReport }
        "8" { Export-UserReport }
        "9" { Export-ComputerReport }
        "10" { Write-Host "Exiting script..."; break }
        default { Write-Host "Invalid choice. Please select 1-9." }
    }

    if ($choice -ne "10") {
        Write-Host "`nPress Enter to continue..."
        Read-Host
    }

} while ($choice -ne "9")
