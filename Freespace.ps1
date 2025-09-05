$percent = 25
$Freespace = Get-Volume | Where-Object { $_.DriveLetter -ne $null } |select Driveletter,@{N="Size";Expression={[Math]::Round($_.size/1GB)}},@{N="FreeSpace";Expression={[Math]::Round($_.SizeRemaining/1GB)}}
if ($Freespace.FreeSpace -lt $Freespace.Size*$percent/100)
{
    Write-Host Freespace on $Freespace.Driveletter is Less than $percent% - ($Freespace.FreeSpace)GB left -ForegroundColor Red
}
else 
{
    Write-Host Freespace on $Freespace.Driveletter is more than $percent% - ($Freespace.FreeSpace)GB left -ForegroundColor Green
}