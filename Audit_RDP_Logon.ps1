param (
    [Parameter(Mandatory = $true)]
    [string]$UserName,
    [string]$CsvPath = "C:\Temp\RDP_Audit.csv",
    [string]$HtmlPath = "C:\Temp\RDP_Audit.html"
)

# Prepare result object
$results = @()

# Get domain user object and groups
$User = Get-ADUser -Identity $UserName -Properties MemberOf
$allGroups = Get-ADPrincipalGroupMembership $UserName | Select-Object -ExpandProperty Name

Write-Host "Auditing RDP access for user: $UserName" -ForegroundColor Cyan

# --- 1. Direct membership in Remote Desktop Users ---
$rdpGroup = "Remote Desktop Users"
$isInRDPGroup = $allGroups -contains $rdpGroup
$results += [PSCustomObject]@{
    Check   = "Direct membership in Remote Desktop Users"
    Status  = if ($isInRDPGroup) { "PASS" } else { "FAIL" }
    Details = if ($isInRDPGroup) { "User is in RDP group" } else { "User not in RDP group" }
}

# --- 2. Nested group membership ---
$results += [PSCustomObject]@{
    Check   = "Nested group RDP rights"
    Status  = if ($isInRDPGroup) { "PASS" } else { "FAIL" }
    Details = if ($isInRDPGroup) { "Has RDP rights via group" } else { "No nested group grants RDP rights" }
}

# --- 3. Local logon rights ---
secedit /export /cfg C:\Windows\Temp\secpol.cfg | Out-Null
$logonRights = Select-String -Path C:\Windows\Temp\secpol.cfg -Pattern "SeInteractiveLogonRight"
Remove-Item C:\Windows\Temp\secpol.cfg -Force

$localLogonAllowed = $false
if ($logonRights) {
    foreach ($line in $logonRights) {
        if ($line.Line -match $UserName) { $localLogonAllowed = $true }
    }
}
$results += [PSCustomObject]@{
    Check   = "Local logon rights"
    Status  = if ($localLogonAllowed) { "PASS" } else { "FAIL" }
    Details = if ($localLogonAllowed) { "User allowed to logon locally" } else { "Not explicitly allowed" }
}

# --- 4. GPO-based RDP permissions using gpresult ---
Write-Host "`nChecking GPO-based RDP permissions via gpresult..."
$xmlPath = "C:\Windows\Temp\gpresult.xml"
gpresult /scope computer /x $xmlPath | Out-Null
[xml]$gpoXml = Get-Content $xmlPath
Remove-Item $xmlPath -Force

$rdpPolicy = $gpoXml.Rsop.Computer.ExtensionData.Extension.Policy | Where-Object { $_.Name -eq "SeRemoteInteractiveLogonRight" }
$gpoRdpAllowed = $false
if ($rdpPolicy) {
    foreach ($principal in $rdpPolicy.PrincipalNames) {
        if ($principal -eq $UserName -or ($allGroups -contains $principal)) {
            $gpoRdpAllowed = $true
        }
    }
}
$results += [PSCustomObject]@{
    Check   = "GPO-based RDP rights"
    Status  = if ($gpoRdpAllowed) { "PASS" } else { "FAIL" }
    Details = if ($gpoRdpAllowed) { "User has RDP rights via GPO" } else { "No GPO grants RDP rights" }
}

# --- 5. Check Deny Policies ---
$denyPolicyRemote = $gpoXml.Rsop.Computer.ExtensionData.Extension.Policy | Where-Object { $_.Name -eq "SeDenyRemoteInteractiveLogonRight" }
$denyPolicyLocal  = $gpoXml.Rsop.Computer.ExtensionData.Extension.Policy | Where-Object { $_.Name -eq "SeDenyInteractiveLogonRight" }

$deniedAccess = $false
$denyDetails = @()

foreach ($policy in @($denyPolicyRemote, $denyPolicyLocal)) {
    if ($policy) {
        foreach ($principal in $policy.PrincipalNames) {
            if ($principal -eq $UserName -or ($allGroups -contains $principal)) {
                $deniedAccess = $true
                $denyDetails += $policy.Name
            }
        }
    }
}

$results += [PSCustomObject]@{
    Check   = "Deny policies"
    Status  = if ($deniedAccess) { "FAIL" } else { "PASS" }
    Details = if ($deniedAccess) { "User denied by: $($denyDetails -join ', ')" } else { "No deny policies apply" }
}

# --- 6. Effective Access ---
$effectiveAccess = if (($isInRDPGroup -or $gpoRdpAllowed) -and (-not $deniedAccess)) { "ALLOWED" } else { "DENIED" }
$results += [PSCustomObject]@{
    Check   = "Effective RDP Access"
    Status  = if ($effectiveAccess -eq "ALLOWED") { "PASS" } else { "FAIL" }
    Details = "Final verdict: $effectiveAccess"
}

# --- Add timestamp and machine info ---
$timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
$computerName = $env:COMPUTERNAME
$results | ForEach-Object { $_ | Add-Member -NotePropertyName "Timestamp" -NotePropertyValue $timestamp }
$results | ForEach-Object { $_ | Add-Member -NotePropertyName "Computer" -NotePropertyValue $computerName }

# --- Export to CSV ---
$results | Export-Csv -Path $CsvPath -NoTypeInformation
Write-Host "`nCSV report saved to: $CsvPath" -ForegroundColor Yellow

# --- Export to HTML with colour coding ---
$html = $results | ConvertTo-Html -Title "RDP Audit Report for $UserName" -PreContent "<h2>RDP Audit Report for $UserName</h2><p>Generated on $timestamp from $computerName</p>"
$html = $html -replace "<td>PASS</td>", "<td style='color:green;font-weight:bold;'>PASS</td>"
$html = $html -replace "<td>FAIL</td>", "<td style='color:red;font-weight:bold;'>FAIL</td>"
$html | Out-File $HtmlPath
Write-Host "HTML report saved to: $HtmlPath" -ForegroundColor Yellow

# --- Display summary ---
Write-Host "`nAudit Summary:" -ForegroundColor Cyan
$results | Format-Table Check, Status, Details, Timestamp, Computer -AutoSize