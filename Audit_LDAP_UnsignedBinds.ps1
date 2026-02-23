$DaysBack = 7
$Since    = (Get-Date).AddDays(-$DaysBack)
$Throttle = 20

$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

$results = Invoke-Command -ComputerName $DCs -ThrottleLimit $Throttle -ScriptBlock {
    param($Since)

    # Enable LDAP interface auditing (basic) if needed
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
    $name    = '16 LDAP Interface Events'
    if ((Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue).$name -ne 2) {
        New-ItemProperty -Path $regPath -Name $name -PropertyType DWord -Value 2 -Force | Out-Null
    }

    Get-WinEvent -FilterHashtable @{
        LogName   = 'Directory Service'
        Id        = 2889
        StartTime = $Since
    } | ForEach-Object {
        [pscustomobject]@{
            DomainController = $env:COMPUTERNAME
            TimeCreated      = $_.TimeCreated
            ClientIP         = $_.Properties[0].Value
            Identity         = $_.Properties[1].Value
            RecordId         = $_.RecordId
        }
    }
} -ArgumentList $Since

$results | Export-Csv .\LDAP_2889.csv -NoTypeInformation -Encoding UTF8