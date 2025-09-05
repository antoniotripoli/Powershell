To find duplicate User Principal Names (UPNs) in Active Directory using PowerShell, you can use the following script. This script retrieves all users, groups them by their UPN, and identifies duplicates.
# Import Active Directory module
Import-Module ActiveDirectory

# Get all users and their UPNs
$users = Get-ADUser -Filter * -Properties UserPrincipalName | Select-Object UserPrincipalName

# Group by UPN and find duplicates
$duplicates = $users | Group-Object UserPrincipalName | Where-Object { $_.Count -gt 1 }

# Display duplicate UPNs
if ($duplicates) {
    Write-Host "Duplicate UPNs found:" -ForegroundColor Yellow
    $duplicates | ForEach-Object {
        Write-Host "UPN: $($_.Name)" -ForegroundColor Cyan
        $_.Group | ForEach-Object { Write-Host "  User: $($_.DistinguishedName)" }
    }
} else {
    Write-Host "No duplicate UPNs found." -ForegroundColor Green
}