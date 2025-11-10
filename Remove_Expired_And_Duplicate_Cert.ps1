# ============================================
# Certificate Management Script
# ============================================

$LogPath = "C:\Temp\RootCertUpdate.log"
if (!(Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" }

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogPath -Value "$timestamp : $Message"
    Write-Host $Message
}

# ============================================
# Option 2: Show expired and duplicate certificates
# ============================================
function Show-ExpiredAndDuplicates {
    Write-Host "`n[INFO] Checking for expired and duplicate certificates..." -ForegroundColor Cyan
    try {
        $rootCerts = Get-ChildItem Cert:\LocalMachine\Root
        $intermediateCerts = Get-ChildItem Cert:\LocalMachine\CA
        $allCerts = $rootCerts + $intermediateCerts

        # Expired certificates
        $expiredCerts = $allCerts | Where-Object { $_.NotAfter -lt (Get-Date) }
        if ($expiredCerts) {
            Write-Host "`nExpired Certificates:" -ForegroundColor Red
            $expiredCerts | Format-Table Subject, NotAfter, Thumbprint -AutoSize
        } else {
            Write-Host "`nNo expired certificates found." -ForegroundColor Green
        }

        # Duplicate certificates
        $duplicateGroups = $allCerts | Group-Object Thumbprint | Where-Object { $_.Count -gt 1 }
        if ($duplicateGroups) {
            Write-Host "`nDuplicate Certificates:" -ForegroundColor Yellow
            foreach ($group in $duplicateGroups) {
                $group.Group | Format-Table Subject, NotAfter, Thumbprint -AutoSize
                Write-Host "----"
            }
        } else {
            Write-Host "`nNo duplicate certificates found." -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERROR] Unable to check certificates. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Option 3: Cleanup expired and duplicate certificates
# ============================================
function Cleanup-Certificates {
    Write-Host "`n[INFO] Cleaning up expired and duplicate certificates..." -ForegroundColor Cyan
    try {
        $stores = @("Root", "CA")
        foreach ($store in $stores) {
            $certs = Get-ChildItem "Cert:\LocalMachine\$store"
            foreach ($cert in $certs) {
                if ($cert.NotAfter -lt (Get-Date)) {
                    Write-Host "Removing expired certificate: $($cert.Subject)" -ForegroundColor Red
                    Remove-Item $cert.PSPath
                }
            }
            $duplicates = $certs | Group-Object Thumbprint | Where-Object { $_.Count -gt 1 }
            foreach ($dup in $duplicates) {
                Write-Host "Removing duplicate certificate: $($dup.Group[0].Subject)" -ForegroundColor Yellow
                Remove-Item $dup.Group[0].PSPath
            }
        }
        Write-Host "[INFO] Cleanup completed." -ForegroundColor Green
        Write-Log "Expired and duplicate certificates cleaned."
    } catch {
        Write-Host "[ERROR] Cleanup failed. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Option 4: Update certificates from Windows Update
# ============================================
function Update-Certificates-WU {
    Write-Host "`n[INFO] Updating certificates from Windows Update..." -ForegroundColor Cyan
    try {
        $sstPath = "C:\Temp\roots.sst"
        certutil -generateSSTFromWU $sstPath
        if (Test-Path $sstPath) {
            Write-Host "[INFO] Download successful. Importing certificates..." -ForegroundColor Green
            certutil -addstore -f Root $sstPath
            Write-Host "[INFO] Certificates updated from Windows Update." -ForegroundColor Cyan
            Write-Log "Certificates updated from Windows Update."
        } else {
            Write-Host "[ERROR] Failed to download certificates. Check internet connectivity." -ForegroundColor Red
        }
    } catch {
        Write-Host "[ERROR] Unable to update certificates. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Option 5: Update from Active Directory
# ============================================
function Update-Certificates-AD {
    Write-Host "`n[INFO] Updating certificates from Active Directory..." -ForegroundColor Cyan
    try {
        Write-Host "[INFO] Running Group Policy update..." -ForegroundColor Green
        gpupdate /force

        Write-Host "[INFO] Triggering certificate auto-enrolment..." -ForegroundColor Green
        certutil -pulse

        Write-Host "[INFO] Certificates updated from Active Directory." -ForegroundColor Cyan
        Write-Log "Certificates updated from Active Directory using gpupdate and certutil -pulse."
    } catch {
        Write-Host "[ERROR] Unable to update certificates from AD. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Option 6: Verify certificate stores
# ============================================
function Verify-Certificates {
    Write-Host "`n[INFO] Verifying certificate stores..." -ForegroundColor Cyan
    try {
        $rootCount = (Get-ChildItem Cert:\LocalMachine\Root).Count
        $intermediateCount = (Get-ChildItem Cert:\LocalMachine\CA).Count

        Write-Host "`nRoot store certificate count: $rootCount" -ForegroundColor Green
        Write-Host "Intermediate store certificate count: $intermediateCount" -ForegroundColor Green
        Write-Host "[INFO] Verification completed successfully." -ForegroundColor Cyan
        Write-Log "Verification completed: Root=$rootCount, Intermediate=$intermediateCount"
    } catch {
        Write-Host "[ERROR] Verification failed. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Option 7: Create report
# ============================================
function Create-Report {
    Write-Host "`n[INFO] Creating certificate report..." -ForegroundColor Cyan
    try {
        $reportPath = "C:\Temp\CertificateReport.txt"
        Get-ChildItem Cert:\LocalMachine\Root | Format-Table Subject, NotAfter, Thumbprint | Out-File $reportPath
        Get-ChildItem Cert:\LocalMachine\CA | Format-Table Subject, NotAfter, Thumbprint | Out-File -Append $reportPath
        Write-Host "[INFO] Report saved to $reportPath" -ForegroundColor Green
        Write-Log "Certificate report created."
    } catch {
        Write-Host "[ERROR] Report creation failed. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Option 8: Show enrollment policy
# ============================================
function Show-EnrollmentPolicy {
    Write-Host "`n[INFO] Retrieving enrollment policy..." -ForegroundColor Cyan
    try {
        certutil -policy
    } catch {
        Write-Host "[ERROR] Unable to retrieve enrollment policy. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Option 9: AIA/CDP Retrieval
# ============================================
function Show-AIA-CDP {
    $selectedCA = Read-Host "Enter full CA name (e.g., Win2k22CA.antdom.local\antdom-WIN2K22CA-CA)"
    if (-not $selectedCA -or $selectedCA.Trim() -eq "") {
        Write-Host "[ERROR] CA name is invalid." -ForegroundColor Red
        return
    }

    # Split CA name for placeholder replacement
    $parts = $selectedCA -split '\\', 2
    $serverName = $parts[0]
    $caName = $parts[1]
    $domainParts = ($serverName -split "\.")[1..($serverName.Split('.').Length - 1)]
    $domainDN = ($domainParts | ForEach-Object { "DC=$_"} ) -join ","

    Write-Host "`n[INFO] Retrieving AIA/CDP from CA registry and Active Directory for: $selectedCA" -ForegroundColor Cyan

    try {
        # CA Registry URLs
        $aiaRaw = certutil -config "$selectedCA" -getreg CA\CACertPublicationURLs
        $cdpRaw = certutil -config "$selectedCA" -getreg CA\CRLPublicationURLs

        # Extract raw URLs from registry output
        $aiaUrls = $aiaRaw | ForEach-Object {
            if ($_ -match '(ldap://|http://|file://)') {
                ($_ -replace '^\s*\d+:\s*','').Trim()
            }
        }

        $cdpUrls = $cdpRaw | ForEach-Object {
            if ($_ -match '(ldap://|http://|file://)') {
                ($_ -replace '^\s*\d+:\s*','').Trim()
            }
        }

        # Replace placeholders for human-readable format
        $aiaReadable = $aiaUrls `
            -replace '%1', $serverName `
            -replace '%3', $caName `
            -replace '%4', '.crt' `
            -replace '%6', $domainDN `
            -replace '%7', $caName `
            -replace '%8%9', '.crl'

        $cdpReadable = $cdpUrls `
            -replace '%1', $serverName `
            -replace '%3', $caName `
            -replace '%4', '.crt' `
            -replace '%6', $domainDN `
            -replace '%7', $caName `
            -replace '%8%9', '.crl'

        # Display CA Registry URLs
        Write-Host "`n===== AIA URLs (CA Registry) =====" -ForegroundColor Green
        if ($aiaReadable.Count -gt 0) { $aiaReadable | ForEach-Object { Write-Host $_ } } else { Write-Host "No AIA URLs found in CA registry." -ForegroundColor Yellow }

        Write-Host "`n===== CDP URLs (CA Registry) =====" -ForegroundColor Green
        if ($cdpReadable.Count -gt 0) { $cdpReadable | ForEach-Object { Write-Host $_ } } else { Write-Host "No CDP URLs found in CA registry." -ForegroundColor Yellow }

        # LDAP paths for AD
        $aiaADPath = "LDAP://CN=$caName,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"
        $cdpADPath = "LDAP://CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"

        Write-Host "`n[INFO] Querying Active Directory for AIA/CDP entries..." -ForegroundColor Cyan

        $aiaADUrls = @()
        $cdpADUrls = @()

        # Query AIA object
        try {
            $aiaObject = [ADSI]$aiaADPath
            if ($aiaObject -and $aiaObject.distinguishedName) {
                $aiaADUrls += "ldap://$($aiaObject.distinguishedName)"
            }
        } catch {
            Write-Host "[INFO] No AIA entries found in Active Directory." -ForegroundColor Yellow
        }

        # Query CDP container
        try {
            $cdpContainer = [ADSI]$cdpADPath
            foreach ($child in $cdpContainer.psbase.Children) {
                if ($child.distinguishedName) {
                    $cdpADUrls += "ldap://$($child.distinguishedName)"
                }
            }
        } catch {
            Write-Host "[INFO] No CDP entries found in Active Directory." -ForegroundColor Yellow
        }

        # Display AD URLs
        Write-Host "`n===== AIA URLs (Active Directory) =====" -ForegroundColor Green
        if ($aiaADUrls.Count -gt 0) { $aiaADUrls | ForEach-Object { Write-Host $_ } } else { Write-Host "No AIA URLs found in AD." -ForegroundColor Yellow }

        Write-Host "`n===== CDP URLs (Active Directory) =====" -ForegroundColor Green
        if ($cdpADUrls.Count -gt 0) { $cdpADUrls | ForEach-Object { Write-Host $_ } } else { Write-Host "No CDP URLs found in AD." -ForegroundColor Yellow }

        # Export all to file
        $exportPath = "C:\Temp\AIA_CDP_Report.txt"
        ($aiaReadable + "`n" + $cdpReadable + "`nAD AIA:`n" + $aiaADUrls + "`nAD CDP:`n" + $cdpADUrls) | Out-File -FilePath $exportPath -Encoding UTF8
        Write-Host "[INFO] Combined AIA/CDP report exported to $exportPath" -ForegroundColor Cyan
        Write-Log "AIA/CDP report exported (CA + AD)."
    } catch {
        Write-Host "[ERROR] Unable to retrieve AIA/CDP information. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Option 10: Enrollment policy details
# ============================================
function Show-PolicyServer {
    Write-Host "`n[INFO] Retrieving detailed enrollment policy..." -ForegroundColor Cyan
    try {
        # Machine context
        Write-Host "`n===== Machine Enrollment Policy Servers =====" -ForegroundColor Green
        $machinePolicies = Get-CertificateEnrollmentPolicyServer -Scope All -Context Machine
        if ($machinePolicies) {
            $machinePolicies | Format-Table Name, Url, Authentication, AutoEnrollmentEnabled, IsDefault, Priority
            $machinePolicies | Out-File "C:\Temp\MachineEnrollmentPolicies.txt" -Encoding UTF8
            Write-Host "[INFO] Machine policies exported to C:\Temp\MachineEnrollmentPolicies.txt" -ForegroundColor Cyan
        } else {
            Write-Host "No machine enrollment policies found." -ForegroundColor Yellow
        }

        # User context
        Write-Host "`n===== User Enrollment Policy Servers =====" -ForegroundColor Green
        $userPolicies = Get-CertificateEnrollmentPolicyServer -Scope All -Context User
        if ($userPolicies) {
            $userPolicies | Format-Table Name, Url, Authentication, AutoEnrollmentEnabled, IsDefault, Priority
            $userPolicies | Out-File "C:\Temp\UserEnrollmentPolicies.txt" -Encoding UTF8
            Write-Host "[INFO] User policies exported to C:\Temp\UserEnrollmentPolicies.txt" -ForegroundColor Cyan
        } else {
            Write-Host "No user enrollment policies found." -ForegroundColor Yellow
        }

        Write-Log "Enrollment policy details retrieved and exported."
    } catch {
        Write-Host "[ERROR] Unable to retrieve enrollment policy details. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Option 11: Export CA configuration
# ============================================
function Export-FullCAConfig {
    Write-Host "`n[INFO] Exporting CA configuration..." -ForegroundColor Cyan
    try {
        certutil -getreg CA > "C:\Temp\CAConfig.txt"
        Write-Host "[INFO] CA configuration exported to C:\Temp\CAConfig.txt" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Export failed. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Option 12: Certificate Templates
# ============================================
function Show-CertificateTemplates {
    $selectedCA = Read-Host "Enter full CA name (e.g., Win2k22CA.antdom.local\antdom-WIN2K22CA-CA)"
    certutil -config "$selectedCA" -catemplates
}

# ============================================
# Option 13: User/Machine Enrollment Policies
# ============================================
function Show-AllEnrollmentPolicies {
    Write-Host "`n[INFO] Retrieving all enrollment policies..." -ForegroundColor Cyan
    try {
        Get-CertificateEnrollmentPolicyServer -Scope All -Context Machine
        Get-CertificateEnrollmentPolicyServer -Scope All -Context User
    } catch {
        Write-Host "[ERROR] Unable to retrieve enrollment policies. Details: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================
# Interactive Menu
# ============================================
$choice = ""
do {
    Write-Host "`n===== Certificate Management Menu =====" -ForegroundColor Cyan
    Write-Host "1. Display current certificate counts"
    Write-Host "2. View expired and duplicate certificates"
    Write-Host "3. Cleanup expired and duplicate certificates"
    Write-Host "4. Update certificates from Windows Update"
    Write-Host "5. Update trusted root and intermediate from Active Directory"
    Write-Host "6. Verify and show counts"
    Write-Host "7. Create report of expired and duplicate certificates"
    Write-Host "8. View current enrollment policy"
    Write-Host "9. View AIA and CDP from Active Directory"
    Write-Host "10. View Certificate Enrollment Policy details"
    Write-Host "11. Export full CA configuration"
    Write-Host "12. View certificate templates"
    Write-Host "13. View all User and Machine Enrollment Policies"
    Write-Host "14. Exit"

    $choice = Read-Host "Enter your choice (1-14)"

    switch ($choice) {
        "1" {
            Write-Host "`nCurrent certificate counts:" -ForegroundColor Cyan
            Write-Host ("Root: " + (Get-ChildItem Cert:\LocalMachine\Root).Count) -ForegroundColor Green
            Write-Host ("Intermediate: " + (Get-ChildItem Cert:\LocalMachine\CA).Count) -ForegroundColor Green
        }
        "2" { Show-ExpiredAndDuplicates }
        "3" { Cleanup-Certificates }
        "4" { Update-Certificates-WU }
        "5" { Update-Certificates-AD }
        "6" { Verify-Certificates }
        "7" { Create-Report }
        "8" { Show-EnrollmentPolicy }
        "9" { Show-AIA-CDP }
        "10" { Show-PolicyServer }
        "11" { Export-FullCAConfig }
        "12" { Show-CertificateTemplates }
        "13" { Show-AllEnrollmentPolicies }
        "14" { Write-Host "`nExiting script..." -ForegroundColor Yellow }
        default { Write-Host "Invalid choice. Please select 1-14." -ForegroundColor Red }
    }
} while ($choice -ne "14")

