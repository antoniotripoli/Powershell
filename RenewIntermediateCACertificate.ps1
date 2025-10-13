
# Step 1: Define Variables
$CAName = "IssuingCA"                # Replace with your CA name
$NewCertPath = "C:\CA\NewCert.cer"   # Path to store new certificate
$CSRPath = "C:\CA\IssuingCA.req"     # Path for CSR
$CAPolicyPath = "C:\Windows\CAPolicy.inf"

# Step 2: Generate Renewal Request (CSR)
Write-Host "Generating CSR for $CAName..."
certutil -renewCert ReuseKeys
certutil -crl

# Export CSR for submission to Root CA
certutil -renewCert ReuseKeys $CSRPath
Write-Host "CSR saved at $CSRPath. Submit this to Root CA."

# Step 3: Pause for Manual Approval
Read-Host "Press Enter after Root CA issues the new certificate and you have downloaded it to $NewCertPath"

# Step 4: Install New Certificate
Write-Host "Installing new CA certificate..."
certutil -installCert $NewCertPath

# Step 5: Publish Certificate and CRL to AD
Write-Host "Publishing CA certificate and CRL to Active Directory..."
certutil -dspublish $NewCertPath CA
certutil -dspublish

# Step 6: Verify PKI Health
Write-Host "Verifying PKI health..."
pkiview.msc

# Step 7: Restart Certificate Services
Write-Host "Restarting Certificate Services..."
Restart-Service CertSvc

# Step 8: Backup CA Configuration
Write-Host "Backing up CA configuration..."
$BackupPath = "C:\CA\Backup"
mkdir $BackupPath
certutil -backup $BackupPath
certutil -backupKey $BackupPath
Write-Host "Backup completed at $BackupPath"
