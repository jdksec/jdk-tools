<#
.SYNOPSIS
    Retrieves domain computers via LDAP and resolves their IP addresses.

.DESCRIPTION
    This script uses the .NET System.DirectoryServices.DirectorySearcher class to connect to 
    an LDAP path for the current (or specified) domain and retrieves all computer objects.
    It then attempts to resolve each computer's DNS name to one or more IP addresses.

.PARAMETER Domain
    (Optional) The fully qualified domain name (FQDN) to search.
    If not specified, the script attempts to auto-detect the current domain.

.EXAMPLE
    .\Get-DomainComputers.ps1
    Retrieves all computer objects from the current domain, displaying their names and IPs.

.EXAMPLE
    .\Get-DomainComputers.ps1 -Domain "mycompany.local"
    Retrieves all computer objects from "mycompany.local" domain, displaying their names and IPs.
#>

[CmdletBinding()]
param (
    [string]$Domain
)

BEGIN {
    Write-Host "Starting search for domain computers..." -ForegroundColor Cyan

    # If no domain is specified, attempt to get the current domain
    if (-not $Domain) {
        try {
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        }
        catch {
            Write-Error "Could not determine current domain. Please specify one using -Domain."
            break
        }
    }

    Write-Host "Using domain: $Domain"
}

PROCESS {
    try {
        # Create a DirectoryEntry object for the specified domain
        $ldapPath = "LDAP://$Domain"
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)

        # Create a DirectorySearcher object using the DirectoryEntry
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        
        # Set a filter for computers (objectCategory=computer)
        $searcher.Filter = "(objectCategory=computer)"
        
        # Optionally set PageSize to handle large results
        $searcher.PageSize = 1000

        Write-Host "Querying LDAP for computers..."
        
        # Perform the search
        $results = $searcher.FindAll()

        Write-Host "Found $($results.Count) computer objects." -ForegroundColor Green
        Write-Host "Listing computer names and IP addresses (if resolvable):"
        Write-Host "-------------------------------------------------------"

        foreach ($result in $results) {
            # Each result is a SearchResult object
            $entry = $result.GetDirectoryEntry()
            
            # Computer's display name
            $computerName = $entry.Properties["name"].Value 
            
            # Fully qualified DNS name (could be used to resolve IP)
            $dnsHostName = $entry.Properties["dNSHostName"].Value
            
            # Attempt to resolve IP addresses
            $ipAddresses = @()
            if ($dnsHostName) {
                try {
                    # Resolve all host addresses
                    $resolvedAddresses = [System.Net.Dns]::GetHostAddresses($dnsHostName)

                    # Convert them to strings
                    $ipAddresses = $resolvedAddresses | ForEach-Object { $_.IPAddressToString }
                }
                catch {
                    # If DNS resolution fails, handle or just show a note
                    Write-Verbose "Could not resolve IP for $dnsHostName."
                }
            }

            # If no IP found or DNS not set, it might be offline or no DNS record
            if (-not $ipAddresses) {
                $ipAddresses = "N/A"
            }
            
            Write-Host ("Computer: {0}   |   DNS: {1}   |   IP: {2}" -f $computerName, $dnsHostName, ($ipAddresses -join ", "))
        }
    }
    catch {
        Write-Error "Error querying domain: $_"
    }
}

END {
    Write-Host "LDAP search complete." -ForegroundColor Cyan
}

