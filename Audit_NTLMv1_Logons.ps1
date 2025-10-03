
# PowerShell Script: Audit NTLMv1 Logons Across All Domain Controllers
# This script queries Security Event Logs for Event IDs 4624 and 4776 where NTLMv1 was used
# and exports the results to a central CSV report.

# Define the list of domain controllers
$DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

# Define the output CSV file path
$OutputPath = "\\CentralServer\Reports\NTLMv1_Audit_Report.csv"

# Initialize an array to store results
$Results = @()

foreach ($DC in $DomainControllers) {
    Write-Host "Collecting NTLMv1 logon events from $DC..."

    # Query Event ID 4624 (Logon) and 4776 (NTLM Authentication)
    $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
        LogName = 'Security'
        Id = 4624, 4776
        StartTime = (Get-Date).AddDays(-7) # Last 7 days
    } -ErrorAction SilentlyContinue

    foreach ($Event in $Events) {
        $Xml = [xml]$Event.ToXml()
        $AuthPackage = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'AuthenticationPackageName' } | Select-Object -ExpandProperty '#text'
        $LmPackage = $Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LmPackageName' } | Select-Object -ExpandProperty '#text'

        if ($AuthPackage -eq 'NTLM' -and $LmPackage -eq 'NTLMv1') {
            $Record = [PSCustomObject]@{
                TimeCreated = $Event.TimeCreated
                Computer    = $DC
                EventID     = $Event.Id
                UserName    = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text')
                IPAddress   = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -ExpandProperty '#text')
                Workstation = ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' } | Select-Object -ExpandProperty '#text')
            }
            $Results += $Record
        }
    }
}

# Export results to CSV
if ($Results.Count -gt 0) {
    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Audit completed. Report saved to $OutputPath"
} else {
    Write-Host "No NTLMv1 logons found in the last 7 days."
}
