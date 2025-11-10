$LogFile = "C:\Temp\SMBv1_Connections_Log.txt"  # Path to log file
$Interval = 300 
$LogDirectory = Split-Path -Path $LogFile
if (!(Test-Path -Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force
}
 
 
function Log-SMBv1Connections {
       $Sessions = Get-SmbSession | Where-Object { $_.Dialect -like "1*" }  
 
    if ($Sessions) {
        foreach ($Session in $Sessions) {
            $LogEntry = "Client=$($Session.ClientComputerName), User=$($Session.ClientUserName), Dialect=$($Session.Dialect)"
            Add-Content -Path $LogFile -Value $LogEntry
        }
    } 
}
 
while ($true) {
    Log-SMBv1Connections
    Start-Sleep -Seconds $Interval
}
