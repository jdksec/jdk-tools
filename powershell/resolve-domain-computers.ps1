$outputFile = "dns-ips.txt"
Clear-Content $outputFile

Write-Host "Retrieving domain computer IP addresses..."

try {
    $computers = net group "domain computers" /domain | ForEach-Object {$_.Trim().Split()} | Sort-Object -unique | findstr "\$" | foreach-object {$_.TrimEnd('$')}
    if ($computers) {
        foreach ($comp in $computers) {
            try {
                $ipAddress = (Resolve-DnsName -Name $comp -Type A -ErrorAction Stop).IPAddress | Select-Object -First 1

                if ($ipAddress) {
                    "$comp,$ipAddress" | Out-File $outputFile -Append
                    Write-Host "Resolved $comp to $ipAddress"
                } else {
                    Write-Warning "Could not resolve IP for $comp"
                }
            }
            catch {
            }
        }
        Write-Host "IP addresses saved to $outputFile"
    } else {
        Write-Warning "No enabled domain computers found."
    }
}
catch {
    #Write-Error "Failed to retrieve computers from Active Directory. Error: $($_.Exception.Message)"
}
