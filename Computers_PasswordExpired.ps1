
Import-Module ActiveDirectory

# --- Settings ---
$MaxAgeDays = 90
$Now        = Get-Date
$Cutoff     = $Now.AddDays(-$MaxAgeDays)

# Get only Windows Server computer accounts with machine password older than 90 days
$stale = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, PasswordLastSet, Enabled, `
                                   DNSHostName, LastLogonDate, primaryGroupID, userAccountControl |
  Where-Object {
    $_.OperatingSystem -like '*Server*' -and
    $_.PasswordLastSet -and
    $_.PasswordLastSet -lt $Cutoff
  }

if (-not $stale) {
  Write-Host "No Windows Server computer accounts found with PasswordLastSet older than $MaxAgeDays days."
  return
}

$report = foreach ($c in $stale) {

  $isDC = ($c.primaryGroupID -eq 516)

  # PasswordNeverExpires flag for computer accounts (UAC bit 65536 / 0x10000)
  $pwdNeverExpires = (($c.userAccountControl -band 65536) -ne 0)

  # Prefer DNSHostName; fallback to Name
  $target = if ($c.DNSHostName) { $c.DNSHostName } else { $c.Name }

  $ping = $false
  try {
    $ping = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction Stop
  } catch {
    $ping = $false
  }

  [pscustomobject]@{
    Name                 = $c.Name
    DNSHostName          = $c.DNSHostName
    Enabled              = $c.Enabled
    IsDomainController   = $isDC
    OperatingSystem      = $c.OperatingSystem
    OSVersion            = $c.OperatingSystemVersion
    PasswordNeverExpires = $pwdNeverExpires
    PasswordLastSet      = $c.PasswordLastSet
    PasswordAgeDays      = ($Now - $c.PasswordLastSet).Days
    LastLogonDate        = $c.LastLogonDate
    PingResponding       = $ping
  }
}

# Sort (PS 5.1 compatible)
$reportSorted = $report | Sort-Object `
  @{Expression='PingResponding';Descending=$false}, `
  @{Expression='PasswordAgeDays';Descending=$true}, `
  @{Expression='IsDomainController';Descending=$true}, `
  @{Expression='Name';Descending=$false}

# Export ONE report
$csvPath = Join-Path $PWD "Servers_PasswordOlderThan90Days_WithPing.csv"
$reportSorted | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

Write-Host "Exported: $csvPath"
