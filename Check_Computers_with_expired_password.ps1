# Import Active Directory module
Import-Module ActiveDirectory

# Get the domain password policy
$domainPolicy = Get-ADDefaultDomainPasswordPolicy
$maxPwdAgeDays = $domainPolicy.MaxPasswordAge.Days

Write-Host "Domain Max Password Age: $maxPwdAgeDays days" -ForegroundColor Cyan

# Calculate threshold date based on max password age
$threshold = (Get-Date).AddDays(-$maxPwdAgeDays)

# Get all computers and compare pwdLastSet with threshold
Get-ADComputer -Filter * -Properties pwdLastSet, OperatingSystem |
Select-Object Name,OperatingSystem,
@{Name="LastPwdSet";Expression={[datetime]::FromFileTime($_.pwdLastSet)}},
@{Name="Status";Expression={
    if ([datetime]::FromFileTime($_.pwdLastSet) -lt $threshold) {
        "EXPIRED (Older than $maxPwdAgeDays days)"
    } else {
        "OK"
    }
}} |
Sort-Object LastPwdSet