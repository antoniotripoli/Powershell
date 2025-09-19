$sid = "S-1-5-21-2097162578-1784092286-618671499-57435"
$sidObject = New-Object System.Security.Principal.SecurityIdentifier($sid)
$user = $sidObject.Translate([System.Security.Principal.NTAccount])
$user.Value