# Cutoff date
$cutoff = Get-Date "2012-01-01"
$cutoffFileTime = $cutoff.ToFileTimeUtc()
 
# Output file
$outputFile = "C:\Temp\Accounts_pwdLastSet_pre2012.csv"
 
# Abbiamo aggiunto 'ntSecurityDescriptor' alle proprietà da recuperare
Get-ADObject -LDAPFilter "(&(pwdLastSet<=$cutoffFileTime)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -Properties pwdLastSet, lastLogonTimestamp, msDS-SupportedEncryptionTypes, sAMAccountName, ntSecurityDescriptor |
   Select-Object sAMAccountName,
   ObjectClass,
   @{Name="pwdLastSet";Expression={
       if ($_.pwdLastSet -eq 0 -or !$_.pwdLastSet) {
           "Never / Must change"
       } else {
          [datetime]::FromFileTime($_.pwdLastSet)
       }
   }},
   @{Name="lastLogon";Expression={
       if ($_.lastLogonTimestamp -eq 0 -or !$_.lastLogonTimestamp) {
           "Never"
       } else {
          [datetime]::FromFileTime($_.lastLogonTimestamp)
       }
   }},
  @{Name="msDS-SupportedEncryptionTypes";Expression={
      $_."msDS-SupportedEncryptionTypes"
   }},
  @{Name="UserCannotChangePassword";Expression={
       # Verifica se esiste un blocco esplicito del cambio password nei permessi dell'oggetto
       if ($_.ntSecurityDescriptor) {
           $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0") # SID del gruppo 'Everyone'
           $guid = New-Object Guid("ab721a53-1e2f-11d0-9819-00aa0040529b")          # GUID del diritto 'Change Password'
          
           # Cerca una regola di tipo 'Deny' (Diniego) per Everyone sul cambio password
           $cannotChange = $false
           foreach ($ace in $_.ntSecurityDescriptor.DiscretionaryAcl) {
               if ($ace.AceType -eq "AccessDeniedObject" -and $ace.SecurityIdentifier -eq $sid -and $ace.ObjectType -eq $guid) {
                   $cannotChange = $true
                   break
               }
           }
           $cannotChange
       } else {
           $null
       }
   }} |
   Export-Csv $outputFile -NoTypeInformation -Encoding UTF8
has context menu