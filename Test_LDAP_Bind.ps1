function Test-LdapBind {
    param (
        [string]$domainController,
        [System.Management.Automation.PSCredential]$cred,
        [System.DirectoryServices.AuthenticationTypes]$authType
    )

    $ldapPath = "LDAP://$domainController"

    try {
        # Create DirectoryEntry with selected authentication type
        $entry = New-Object System.DirectoryServices.DirectoryEntry(
            $ldapPath,
            $cred.UserName,
            $cred.GetNetworkCredential().Password,
            $authType
        )

        # Attempt bind
        $null = $entry.NativeObject
        Write-Host "`nLDAP bind successful using authentication type: $authType" -ForegroundColor Green

        # Attempt to browse directory
        Write-Host "Attempting to browse directory..."
        try {
            $childCount = 0
            foreach ($child in $entry.Children) {
                Write-Host "Found: $($child.Path)"
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
        Write-Host "`nLDAP bind failed using authentication type: $authType" -ForegroundColor Red
        Write-Error $_
    }
}

# Prompt once for domain controller and credentials
$domainController = Read-Host "Enter your domain controller (e.g., dc01.example.com)"
$cred = Get-Credential

# Main Menu Loop
do {
    Clear-Host
    Write-Host "Choose LDAP bind type to test:`n"
    Write-Host "1. Unsigned bind (AuthenticationTypes.None)"
    Write-Host "2. Signed bind (AuthenticationTypes.Secure)"
    Write-Host "3. Signed bind with SSL (AuthenticationTypes.SecureSocketsLayer)"
    Write-Host "4. Exit"
    $choice = Read-Host "Enter your choice (1-4)"

    switch ($choice) {
        '1' {
            Test-LdapBind -domainController $domainController -cred $cred -authType ([System.DirectoryServices.AuthenticationTypes]::None)
        }
        '2' {
            Test-LdapBind -domainController $domainController -cred $cred -authType ([System.DirectoryServices.AuthenticationTypes]::Secure)
        }
        '3' {
            Test-LdapBind -domainController $domainController -cred $cred -authType ([System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer)
        }
        '4' {
            Write-Host "`nExiting script..." -ForegroundColor Cyan
        }
        default {
            Write-Host "`nInvalid choice. Please try again." -ForegroundColor Yellow
        }
    }

    if ($choice -ne '4') {
        Write-Host "`nPress Enter to return to the main menu..."
        Read-Host
    }
} while ($choice -ne "4")