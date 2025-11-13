<#
.SYNOPSIS
    Tests LDAP bind behaviour with different authentication types.

.DESCRIPTION
    This script allows you to test LDAP binding against a specified domain controller
    using various authentication types: None, Secure, and SecureSocketsLayer (LDAPS).
    It helps verify LDAP signing enforcement and LDAPS configuration.

.NOTES
    Author: Refactored by Enterprise Copilot
    Version: 2.0
#>

[CmdletBinding()]
param ()

function Test-LdapBind {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController,

        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.AuthenticationTypes]$AuthType
    )

    Write-Verbose "Starting LDAP bind test for $DomainController using $AuthType"

    # Prompt for credentials
    $cred = Get-Credential -Message "Enter credentials for LDAP bind"
    $ldapPath = "LDAP://$DomainController"

    try {
        # Create DirectoryEntry with selected authentication type
        $entry = New-Object System.DirectoryServices.DirectoryEntry(
            $ldapPath,
            $cred.UserName,
            $cred.GetNetworkCredential().Password,
            $AuthType
        )

        # Attempt bind
        $null = $entry.NativeObject
        Write-Host "`nLDAP bind successful using authentication type: $AuthType" -ForegroundColor Green

        # Attempt to browse directory
        Write-Host "Attempting to browse directory..."
        try {
            $childCount = 0
            foreach ($child in $entry.Children) {
                Write-Output "Found: $($child.Path)"
                $childCount++
            }

            if ($childCount -eq 0) {
                Write-Host "Bind succeeded, but no entries returned. Possible access restriction." -ForegroundColor Yellow
            } else {
                Write-Host "Browsing succeeded. LDAP signing may not be enforced." -ForegroundColor Green
            }
        } catch {
            Write-Host "`nBrowsing failed after bind. Likely due to LDAP signing enforcement." -ForegroundColor Red
            Write-Error $_
        }
    } catch {
        Write-Host "`nLDAP bind failed using authentication type: $AuthType" -ForegroundColor Red
        Write-Error $_
    }
}

# Menu
Write-Host "Choose LDAP bind type to test:`n"
Write-Host "1. Unsigned bind (AuthenticationTypes.None)"
Write-Host "2. Signed bind (AuthenticationTypes.Secure)"
Write-Host "3. Signed bind with SSL (AuthenticationTypes.SecureSocketsLayer)"
$choice = Read-Host "Enter your choice (1-3)"

# Set domain controller
$domainController = Read-Host "Enter your domain controller (e.g., dc01.example.com)"

# Map choices to enum values
$authMap = @{
    '1' = [System.DirectoryServices.AuthenticationTypes]::None
    '2' = [System.DirectoryServices.AuthenticationTypes]::Secure
    '3' = [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
}

if ($authMap.ContainsKey($choice)) {
    Test-LdapBind -DomainController $domainController -AuthType $authMap[$choice] -Verbose
} else {
    Write-Host "Invalid choice. Please run the script again." -ForegroundColor Yellow
    }
