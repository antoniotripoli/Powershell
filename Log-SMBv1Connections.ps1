$LogFile = "C:\Temp\SMBv1_Connections_Log.txt"  # Path to log file
$Interval = 300  # Interval in seconds (e.g., 300 seconds = 5 minutes)

# Ensure the log directory exists
$LogDirectory = Split-Path -Path $LogFile
if (!(Test-Path -Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force
}

# Function to log SMBv1 connections
function Log-SMBv1Connections {
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Sessions = Get-SmbSession | Where-Object { $_.Dialect -like "1*" }  # Filter for SMBv1 (Dialect 1.0)

    if ($Sessions) {
        foreach ($Session in $Sessions) {
            $LogEntry = "$Timestamp - SMBv1 Connection Detected: Client=$($Session.ClientComputerName), User=$($Session.ClientUserName), Dialect=$($Session.Dialect)"
            Add-Content -Path $LogFile -Value $LogEntry
        }
    } else {
        Add-Content -Path $LogFile -Value "$Timestamp - No SMBv1 connections detected."
    }
}

# Infinite loop to run the script at the specified interval
while ($true) {
    Log-SMBv1Connections
    Start-Sleep -Seconds $Interval
}

