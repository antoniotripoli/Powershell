<#
.SYNOPSIS
    PKI Health Check Script for Active Directory Certificate Services with chain validation.

.DESCRIPTION
    - Checks Certification Authority (CA) status.
    - Validates CRL and AIA distribution points.
    - Tests OCSP responders.
    - Lists certificate templates and enrollment services.
    - Validates certificate chains for recently issued certificates.
    - Generates a health report in HTML and CSV.

.NOTES
    Run as Enterprise Admin or with PKI Admin rights.
    Requires RSAT ADCS tools and PKI module.
#>

# Output paths
$ReportPath = "C:\Temp\PKI_Health_Report_$(Get-Date -Format 'yyyyMMdd_HHmm')"
New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
$HtmlReport = "$ReportPath\PKI_Health.html"
$CsvReport = "$ReportPath\PKI_Health.csv"

# Load PKI module
Import-Module PKI -ErrorAction Stop

# Collect data
$Results = @()

Write-Host "Collecting PKI health information..." -ForegroundColor Cyan

# Get all CAs
$CAs = Get-CertificationAuthority
foreach ($CA in $CAs) {
    # CA Status
    $Results += [PSCustomObject]@{
        Component = "Certification Authority"
        Name      = $CA.DisplayName
        Status    = $CA.Status
        Details   = "CA Service Status"
    }

    # CRL Distribution Points
    $CRLs = Get-CACrlDistributionPoint
    foreach ($CRL in $CRLs) {
        $CRLStatus = Test-Connection -ComputerName ($CRL.URI -replace '^http?://|^ldap://|^file://', '') -Count 1 -Quiet
        $Results += [PSCustomObject]@{
            Component = "CRL Distribution Point"
            Name      = $CRL.URI
            Status    = if ($CRLStatus) { "Reachable" } else { "Unreachable" }
            Details   = "CRL Location"
        }
    }

    # AIA Locations
    $AIAs = Get-CAAuthorityInformationAccess
    foreach ($AIA in $AIAs) {
        $AIAStatus = Test-Connection -ComputerName ($AIA.URI -replace '^http?://|^ldap://|^file://', '') -Count 1 -Quiet
        $Results += [PSCustomObject]@{
            Component = "AIA Location"
            Name      = $AIA.URI
            Status    = if ($AIAStatus) { "Reachable" } else { "Unreachable" }
            Details   = "AIA Location"
        }
    }

    # OCSP Responders
    $OCSPs = Get-OCSPResponseSigning
    foreach ($OCSP in $OCSPs) {
        $Results += [PSCustomObject]@{
            Component = "OCSP Responder"
            Name      = $OCSP.Subject
            Status    = if ($OCSP.Status -eq "Good") { "Healthy" } else { "Issue Detected" }
            Details   = "OCSP Signing Certificate"
        }
    }

    # Certificate Chain Validation for last 10 issued certs
    Write-Host "Validating certificate chains for $($CA.DisplayName)..."
    $IssuedCerts = certutil -view -restrict "Disposition=20" -out "RequestID,SerialNumber,NotAfter" -config $CA.ConfigString | Select-String "SerialNumber" -Context 0,2 | Select-Object -First 10
    foreach ($CertLine in $IssuedCerts) {
        $Serial = ($CertLine.ToString() -split ":")[1].Trim()
        $TempFile = "$ReportPath\$Serial.cer"
        certutil -config $CA.ConfigString -retrieve $Serial $TempFile | Out-Null
        if (Test-Path $TempFile) {
            $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($TempFile)
            $Valid = $Chain.Build($Cert)
            $Results += [PSCustomObject]@{
                Component = "Certificate Chain"
                Name      = "Serial: $Serial"
                Status    = if ($Valid) { "Valid" } else { "Invalid" }
                Details   = "Chain Elements: $($Chain.ChainElements.Count)"
            }
            Remove-Item $TempFile -Force
        }
    }
}

# Certificate Templates
$Templates = Get-CATemplate
foreach ($Template in $Templates) {
    $Results += [PSCustomObject]@{
        Component = "Certificate Template"
        Name      = $Template.Name
        Status    = "Available"
        Details   = "Template Version: $($Template.SchemaVersion)"
    }
}

# Export reports
$Results | Export-Csv -Path $CsvReport -NoTypeInformation -Encoding UTF8
$Results | ConvertTo-Html -Title "PKI Health Report" -PreContent "<h1>PKI Health Report</h1><p>Generated on $(Get-Date)</p>" | Out-File $HtmlReport

Write-Host "PKI Health Check Complete!" -ForegroundColor Green
Write-Host "HTML Report: $HtmlReport"
Write-Host "CSV Report: $CsvReport"