# Get domain max password age
$maxPwdAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
$thresholdDate = (Get-Date).AddDays(-$maxPwdAge)

# Prepare an array to store results
$results = @()

# Step 1: Simulate disabling accounts with old passwords
$oldPwdAccounts = Get-ADComputer -Filter * -Properties PasswordLastSet, Enabled |
Where-Object {
    ($_.PasswordLastSet -lt $thresholdDate) -and
    ($_.Enabled -eq $true)
}

foreach ($account in $oldPwdAccounts) {
    Write-Host "SIMULATE: Would disable account $($account.Name)"
    
    # Simulate disable
    Disable-ADAccount -Identity $account.DistinguishedName -WhatIf
    
    # Add to results with reason
    $results += [PSCustomObject]@{
        Action          = "Disable"
        ComputerName    = $account.Name
        Enabled         = $account.Enabled
        PasswordLastSet = $account.PasswordLastSet
        Reason          = "Password older than $maxPwdAge days"
        Timestamp       = (Get-Date)
    }
}

# Step 2: Simulate deleting disabled accounts
$disabledAccounts = Get-ADComputer -Filter 'Enabled -eq $false' -Properties PasswordLastSet

foreach ($account in $disabledAccounts) {
    Write-Host "SIMULATE: Would delete account $($account.Name)"
    
    # Simulate delete
    Remove-ADComputer -Identity $account.DistinguishedName -Confirm:$false -WhatIf
    
    # Add to results with reason
    $results += [PSCustomObject]@{
        Action          = "Delete"
        ComputerName    = $account.Name
        Enabled         = $account.Enabled
        PasswordLastSet = $account.PasswordLastSet
        Reason          = "Account disabled"
        Timestamp       = (Get-Date)
    }
}

# Export all simulated actions to CSV
$results | Export-Csv "AD_Account_Audit_Simulation.csv" -NoTypeInformation

Write-Host "`nSimulation complete. Results exported to AD_Account_Audit_Simulation.csv"
``