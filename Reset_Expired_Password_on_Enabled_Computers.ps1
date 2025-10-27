# Get domain max password age
$maxPwdAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
$thresholdDate = (Get-Date).AddDays(-$maxPwdAge)

# Prepare audit log array
$results = @()

# Find enabled computers with expired passwords
$computers = Get-ADComputer -Filter 'Enabled -eq $true' -Properties PasswordLastSet, DistinguishedName |
Where-Object { $_.PasswordLastSet -lt $thresholdDate }

foreach ($computer in $computers) {
    Write-Host "Checking: $($computer.Name)"

    # Test if computer is reachable
    if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet) {
        Write-Host "Reachable: $($computer.Name) - Resetting password..."
        try {
            # Reset machine password without specifying a DC
            Invoke-Command -ComputerName $computer.Name -ScriptBlock {
                Reset-ComputerMachinePassword
            }
            $status = "Password reset successful"
        } catch {
            $status = "Password reset failed: $($_.Exception.Message)"
        }
    } else {
        $status = "Computer not reachable"
    }

    # Log result
    $results += [PSCustomObject]@{
        ComputerName    = $computer.Name
        PasswordLastSet = $computer.PasswordLastSet
        OU              = $computer.DistinguishedName
        Status          = $status
        Timestamp       = (Get-Date)
    }
}

# Export audit log
$results | Export-Csv "AD_ExpiredPasswordReset_Audit.csv" -NoTypeInformation
Write-Host "`nProcess complete. Audit log saved to AD_ExpiredPasswordReset_Audit.csv"