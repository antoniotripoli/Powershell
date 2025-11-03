# Ensure RSAT tools are installed and run as Domain Admin

# Define critical container distinguished names (adjust for your domain)
$criticalContainers = @(
    "CN=Managed Service Accounts,DC=yourdomain,DC=com",
    "OU=Domain Controllers,DC=yourdomain,DC=com",
    "CN=Users,DC=yourdomain,DC=com",
    "CN=Computers,DC=yourdomain,DC=com",
    "DC=DomainDNSZones,DC=yourdomain,DC=com",
    "DC=ForestDNSZones,DC=yourdomain,DC=com"
)

# Loop through each container and enable protection if not already set
foreach ($container in $criticalContainers) {
    try {
        $obj = Get-ADObject -Identity $container -Properties ProtectedFromAccidentalDeletion
        if ($obj.ProtectedFromAccidentalDeletion -eq $false) {
            Set-ADObject -Identity $container -ProtectedFromAccidentalDeletion $true
            Write-Host "Protection enabled for: $container"
        } else {
            Write-Host "Already protected: $container"
        }
    } catch {
        Write-Host "Failed to process: $container - $_"
    }
}

# Optional: Export status report
$report = foreach ($container in $criticalContainers) {
    $obj = Get-ADObject -Identity $container -Properties ProtectedFromAccidentalDeletion
    [PSCustomObject]@{
        Container = $container
        Protected = $obj.ProtectedFromAccidentalDeletion
    }
}
$report | Export-Csv "CriticalContainersProtectionReport.csv" -NoTypeInformation
Write-Host "Report saved as CriticalContainersProtectionReport.csv"