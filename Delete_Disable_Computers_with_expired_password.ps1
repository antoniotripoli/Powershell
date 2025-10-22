# Get domain max password age
$maxPwdAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
$thresholdDate = (Get-Date).AddDays(-$maxPwdAge)

# Prepare an array to store results
$results = @()

# Step 1: Disable accounts with old passwords
$oldPwdAccounts = Get-ADComputer -Filter * -Properties PasswordLastSet, Enabled, DistinguishedName |
Where-Object {
    ($_.PasswordLastSet -lt $thresholdDate) -and
    ($_.Enabled -eq $true)
}

foreach ($account in $oldPwdAccounts) {
    Write-Host "DISABLING: $($account.Name)"
    
    # Disable account
    Disable-ADAccount -Identity $account.DistinguishedName
    
    # Add to results with reason and OU
    $results += [PSCustomObject]@{
        Action          = "Disable"
        ComputerName    = $account.Name
        Enabled         = $account.Enabled
        PasswordLastSet = $account.PasswordLastSet
        OU              = $account.DistinguishedName
        Reason          = "Password older than $maxPwdAge days"
        Timestamp       = (Get-Date)
    }
}

# Step 2: Delete disabled accounts
$disabledAccounts = Get-ADComputer -Filter 'Enabled -eq $false' -Properties PasswordLastSet, DistinguishedName

foreach ($account in $disabledAccounts) {
    Write-Host "DELETING: $($account.Name)"
    
    # Delete account
    Remove-ADComputer -Identity $account.DistinguishedName -Confirm:$false
    
    # Add to results with reason and OU
    $results += [PSCustomObject]@{
        Action          = "Delete"
        ComputerName    = $account.Name
        Enabled         = $account.Enabled
        PasswordLastSet = $account.PasswordLastSet
        OU              = $account.DistinguishedName
        Reason          = "Account disabled"
        Timestamp       = (Get-Date)
    }
}

# Export all actions to CSV
$results | Export-Csv "AD_Account_Audit.csv" -NoTypeInformation
Write-Host "`nExecution complete. Results exported to AD_Account_Audit.csv"