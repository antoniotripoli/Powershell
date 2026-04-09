Import-Module ActiveDirectory

$DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName

$Results = foreach ($DC in $DCs) {
    Invoke-Command -ComputerName $DC -ScriptBlock {
        $events = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-Kernel-Boot'
            Id           = 1801
        } -ErrorAction SilentlyContinue

        if ($events) {
            foreach ($event in $events) {
                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    TimeCreated  = $event.TimeCreated
                    EventID      = $event.Id
                    Message      = $event.Message
                }
            }
        }
        else {
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                TimeCreated  = $null
                EventID      = 'None'
                Message      = 'No Secure Boot update failure detected'
            }
        }
    }
}

$Results | Export-Csv .\SecureBoot_Event1801_DCs.csv -NoTypeInformation -Encoding UTF8
