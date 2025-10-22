# Get domain max password age
$maxPwdAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
$thresholdDate = (Get-Date).AddDays(-$maxPwdAge)

# Disable accounts with password older than max age
Get-ADComputer -Filter * -Properties PasswordLastSet, Enabled |
Where-Object {
    ($_.PasswordLastSet -lt $thresholdDate) -and
    ($_.Enabled -eq $true)
} |
ForEach-Object {
    Disable-ADAccount -Identity $_.DistinguishedName
    Write-Host "Disabled: $($_.Name)"
}
``