function Get-RemoteLocalGroups {
    param([string]$ComputerName)

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        @{
            RDPGroup = (Get-LocalGroupMember -Group "Remote Desktop Users" | Select-Object Name, ObjectClass, SID)
            AdminGroup = (Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, SID)
        }
    }
}

function Resolve-ADGroupBySIDOrName {
    param([string]$SID,[string]$Name)

    if ($SID) {
        try {
            $obj = Get-ADObject -Identity $SID -Properties SamAccountName
            if ($obj) { return $obj.SamAccountName }
        } catch {}
    }

    if ($Name) {
        $cleanName = ($Name -split "\\")[-1]
        try {
            $group = Get-ADGroup -Filter "SamAccountName -eq '$cleanName'" -ErrorAction SilentlyContinue
            if ($group) { return $group.SamAccountName }
        } catch {}
    }
    return $null
}

function Test-ADGroupRecursiveMembership {
    param([string]$UserName,[string]$GroupName)

    try {
        $members = Get-ADGroupMember -Identity $GroupName -Recursive
        return ($members | Where-Object { $_.SamAccountName -eq $UserName }) -ne $null
    } catch { return $false }
}

function Test-GPORestrictedGroupMembership {
    param([string]$UserName)

    $xmlPath = "C:\Windows\Temp\gpresult.xml"
    try {
        gpresult /scope computer /x $xmlPath | Out-Null
        [xml]$gpoXml = Get-Content $xmlPath
        Remove-Item $xmlPath -Force
    } catch { return $false }

    $userGroups = (Get-ADUser -Filter "SamAccountName -eq '$UserName' -or UserPrincipalName -eq '$UserName'" | Get-ADPrincipalGroupMembership).Name
    $restrictedGroups = $gpoXml.Rsop.Computer.ExtensionData.Extension.Policy | Where-Object { $_.Name -like "*RestrictedGroups*" }

    foreach ($policy in $restrictedGroups) {
        foreach ($principal in $policy.PrincipalNames) {
            if ($principal -match "Remote Desktop Users") {
                foreach ($member in $policy.MemberNames) {
                    if ($member -eq $UserName -or ($userGroups -contains $member)) { return $true }
                    $adGroup = Get-ADGroup -Identity $member -ErrorAction SilentlyContinue
                    if ($adGroup) {
                        $members = Get-ADGroupMember -Identity $adGroup -Recursive
                        if ($members | Where-Object { $_.SamAccountName -eq $UserName }) { return $true }
                    }
                }
            }
        }
    }
    return $false
}

function Start-RDPAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$UserName,
        [string]$ComputerName=$env:COMPUTERNAME,
        [string]$CsvPath="C:\Temp\RDP_Audit.csv",
        [string]$HtmlPath="C:\Temp\RDP_Audit.html"
    )

    Write-Host "Starting RDP Audit for user '$UserName' on computer '$ComputerName'..."

    # Local AD checks
    $user = Get-ADUser -Filter "SamAccountName -eq '$UserName' -or UserPrincipalName -eq '$UserName'" -ErrorAction SilentlyContinue
    if (-not $user) {
        Write-Host "ERROR: User '$UserName' not found in AD." -ForegroundColor Red
        return
    }

    $isDomainAdmin = (Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object { $_.SamAccountName -eq $UserName }) -ne $null
    $gpoRestrictedGroupMembership = Test-GPORestrictedGroupMembership -UserName $UserName

    # Remote local group checks
    $remoteGroups = Get-RemoteLocalGroups -ComputerName $ComputerName

    $isInRDPGroup = $false
    foreach ($member in $remoteGroups.RDPGroup) {
        if ($member.ObjectClass -eq 'User' -and $member.Name -match $UserName) { $isInRDPGroup = $true }
        elseif ($member.ObjectClass -eq 'Group') {
            $resolvedName = Resolve-ADGroupBySIDOrName -SID $member.SID -Name $member.Name
            if ($resolvedName -and (Test-ADGroupRecursiveMembership -UserName $UserName -GroupName $resolvedName)) {
                $isInRDPGroup = $true
            }
        }
    }

    $isLocalAdmin = $false
    foreach ($member in $remoteGroups.AdminGroup) {
        if ($member.ObjectClass -eq 'User' -and $member.Name -match $UserName) { $isLocalAdmin = $true }
        elseif ($member.ObjectClass -eq 'Group') {
            $resolvedName = Resolve-ADGroupBySIDOrName -SID $member.SID -Name $member.Name
            if ($resolvedName -and (Test-ADGroupRecursiveMembership -UserName $UserName -GroupName $resolvedName)) {
                $isLocalAdmin = $true
            }
        }
    }

    # Compile results
    $results = @()
    $results += [PSCustomObject]@{Check="Remote Desktop Users";Status=if($isInRDPGroup){"PASS"}else{"FAIL"};Details=if($isInRDPGroup){"User has RDP rights"}else{"No RDP group membership"}}
    $results += [PSCustomObject]@{Check="Local Administrators";Status=if($isLocalAdmin){"PASS"}else{"FAIL"};Details=if($isLocalAdmin){"User is local admin"}else{"Not in local Administrators"}}
    $results += [PSCustomObject]@{Check="Domain Admins";Status=if($isDomainAdmin){"PASS"}else{"FAIL"};Details=if($isDomainAdmin){"User is domain admin"}else{"Not in Domain Admins"}}
    $results += [PSCustomObject]@{Check="GPO Restricted Groups";Status=if($gpoRestrictedGroupMembership){"PASS"}else{"FAIL"};Details=if($gpoRestrictedGroupMembership){"User is in AD group added via GPO"}else{"No GPO Restricted Group membership"}}

    $effectiveAccess = if (($isInRDPGroup -or $isLocalAdmin -or $isDomainAdmin -or $gpoRestrictedGroupMembership)) {"ALLOWED"} else {"DENIED"}
    $results += [PSCustomObject]@{Check="Effective RDP Access";Status=if($effectiveAccess -eq "ALLOWED"){"PASS"}else{"FAIL"};Details="Final verdict: $effectiveAccess"}

    # Export results
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $computerName = $ComputerName
    $results | ForEach-Object { $_ | Add-Member -NotePropertyName "Timestamp" -NotePropertyValue $timestamp }
    $results | ForEach-Object { $_ | Add-Member -NotePropertyName "Computer" -NotePropertyValue $computerName }

    $results | Export-Csv -Path $CsvPath -NoTypeInformation
    $style = "<style>table{border-collapse:collapse;} td,th{padding:8px;border:1px solid #ccc;} .PASS{color:green;font-weight:bold;} .FAIL{color:red;font-weight:bold;}</style>"
    $html = $results | ConvertTo-Html -Title "RDP Audit Report for $UserName" -PreContent "$style<h2>RDP Audit Report for $UserName</h2><p>Generated on $timestamp from $computerName</p>"
    $html = $html -replace "<td>PASS</td>", "<td class='PASS'>PASS</td>"
    $html = $html -replace "<td>FAIL</td>", "<td class='FAIL'>FAIL</td>"
    $html | Out-File $HtmlPath

    Write-Host "`nAudit Summary:" -ForegroundColor Cyan
    $results | Format-Table Check,Status,Details,Timestamp,Computer -AutoSize
}