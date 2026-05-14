# Cutoff date
$cutoff = Get-Date "2012-01-01"
$cutoffFileTime = $cutoff.ToFileTimeUtc()

Get-ADObject `
    -LDAPFilter "(&(pwdLastSet<=$cutoffFileTime)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
    -Properties pwdLastSet, msDS-SupportedEncryptionTypes, sAMAccountName |
Select-Object `
    sAMAccountName,
    ObjectClass,
    @{Name="pwdLastSet";Expression={
        if ($_.pwdLastSet -eq 0) {
            "Never / Must change"
        }
        else {
            [datetime]::FromFileTime($_.pwdLastSet)
        }
    }},
    @{Name="msDS-SupportedEncryptionTypes";Expression={
        $_.'msDS-SupportedEncryptionTypes'
    }} |
Export-Csv "C:\Temp\Accounts_pwdLastSet_pre2012.csv" -NoTypeInformation -Encoding UTF8