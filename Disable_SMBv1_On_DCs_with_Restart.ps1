# Define log file
$LogFile = "C:\SMB1_SequentialRemoval_Log.txt"
Add-Content -Path $LogFile -Value "=== SMBv1 Sequential Removal Started: $(Get-Date) ==="

# Get all Domain Controllers
$DCs = Get-ADDomainController -Filter *

foreach ($DC in $DCs) {
    $Server = $DC.HostName
    Add-Content -Path $LogFile -Value "`nProcessing $Server..."

    try {
        # Disable SMBv1 protocol before removal
        Invoke-Command -ComputerName $Server -ScriptBlock {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false
        }
        Add-Content -Path $LogFile -Value "SMBv1 protocol disabled on $Server."

        # Remove SMBv1 feature
        Invoke-Command -ComputerName $Server -ScriptBlock {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        }
        Add-Content -Path $LogFile -Value "SMBv1 feature removed on $Server. Restart required."
        restart-computer -ComputerName $Server -Force
        # Wait 10 minutes before moving to next DC
        Add-Content -Path $LogFile -Value "Waiting 10 minutes before next server..."
        Start-Sleep -Seconds 600

    } catch {
        Add-Content -Path $LogFile -Value "Error processing $($Server): $_"
    }
}

Add-Content -Path $LogFile -Value "`n=== Script Completed: $(Get-Date) ==="
Write-Host "Sequential SMBv1 removal completed. Check $LogFile for details."