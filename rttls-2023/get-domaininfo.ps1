<#
.SYNOPSIS
    Retrieves domain computers, users, groups, and any user in groups containing "adm" in the name.

.DESCRIPTION
    - Grabs all computers via (objectCategory=computer)
    - Grabs all users via (&(objectCategory=Person)(objectClass=User))
    - Grabs all groups via (objectCategory=group)
    - Finds any group with "adm" in its CN and retrieves all user members
    - Fetches user descriptions

.PARAMETER Domain
    (Optional) The fully qualified domain name (FQDN) to search.
    If not specified, the script attempts to auto-detect the current domain.

.EXAMPLE
    .\Get-DomainInfo.ps1
    Retrieves objects from the current domain.

.EXAMPLE
    .\Get-DomainInfo.ps1 -Domain "mycompany.local"
    Retrieves objects from "mycompany.local".
#>

[CmdletBinding()]
param (
    [string]$Domain
)

BEGIN {
    Write-Host "Starting LDAP queries..." -ForegroundColor Cyan

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
    
    # Create a DirectoryEntry object for the specified domain
    $ldapPath = "LDAP://$Domain"
    try {
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    }
    catch {
        Write-Error "Error creating DirectoryEntry: $_"
        break
    }
}

PROCESS {

    # region --- GET DOMAIN COMPUTERS ---
    Write-Host "`n--- DOMAIN COMPUTERS ---" -ForegroundColor Yellow
    try {
        $searcherComputers = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcherComputers.Filter   = "(objectCategory=computer)"
        $searcherComputers.PageSize = 1000
        
        $computerResults = $searcherComputers.FindAll()
        Write-Host "Found $($computerResults.Count) computer objects."
        foreach ($result in $computerResults) {
            $entry = $result.GetDirectoryEntry()
            $computerName = $entry.Properties["name"].Value
            Write-Host "Computer: $computerName"
        }
    }
    catch {
        Write-Error "Error querying computers: $_"
    }
    # endregion

    # region --- GET DOMAIN USERS (WITH DESCRIPTION) ---
    Write-Host "`n--- DOMAIN USERS ---" -ForegroundColor Yellow
    try {
        $searcherUsers = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        # Filter for actual user objects
        $searcherUsers.Filter   = "(&(objectCategory=Person)(objectClass=User))"
        $searcherUsers.PageSize = 1000
        
        $userResults = $searcherUsers.FindAll()
        Write-Host "Found $($userResults.Count) user objects."
        foreach ($result in $userResults) {
            $entry          = $result.GetDirectoryEntry()
            $userName       = $entry.Properties["name"].Value
            $userDescription= $entry.Properties["description"].Value

            Write-Host "User: $userName"
            Write-Host "  Description: $userDescription"
        }
    }
    catch {
        Write-Error "Error querying users: $_"
    }
    # endregion

    # region --- GET DOMAIN GROUPS ---
    Write-Host "`n--- DOMAIN GROUPS ---" -ForegroundColor Yellow
    try {
        $searcherGroups = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcherGroups.Filter   = "(objectCategory=group)"
        $searcherGroups.PageSize = 1000

        $groupResults = $searcherGroups.FindAll()
        Write-Host "Found $($groupResults.Count) group objects."
        foreach ($result in $groupResults) {
            $entry      = $result.GetDirectoryEntry()
            $groupName  = $entry.Properties["name"].Value
            Write-Host "Group: $groupName"
        }
    }
    catch {
        Write-Error "Error querying groups: $_"
    }
    # endregion

    # region --- GET USERS IN 'ADM' GROUPS ---
    Write-Host "`n--- USERS IN GROUPS WITH 'ADM' IN THE NAME ---" -ForegroundColor Yellow
    try {
        # Filter for groups whose CN contains 'adm' (case-insensitive search typically works in AD)
        $searcherAdmGroups = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
        $searcherAdmGroups.Filter   = "(&(objectCategory=group)(cn=*adm*))"
        $searcherAdmGroups.PageSize = 1000

        $admGroupResults = $searcherAdmGroups.FindAll()
        Write-Host "Found $($admGroupResults.Count) group(s) whose name contains 'adm'."

        foreach ($admGroupResult in $admGroupResults) {
            $admGroupEntry = $admGroupResult.GetDirectoryEntry()
            $admGroupName  = $admGroupEntry.Properties["name"].Value

            Write-Host "`nGroup: $admGroupName"
            
            # "member" property is a list of distinguished names (DNs)
            $members = $admGroupEntry.Properties["member"]
            if ($members -and $members.Count -gt 0) {
                foreach ($memberDN in $members) {
                    try {
                        # Create a DirectoryEntry for each DN
                        $memberEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$memberDN")

                        # Check if it’s a user (objectClass could be "user" or "contact" etc.)
                        if ($memberEntry.Properties["objectClass"] -contains "user") {
                            $userName        = $memberEntry.Properties["name"].Value
                            $userDescription = $memberEntry.Properties["description"].Value
                            Write-Host "  User: $userName  |  Description: $userDescription"
                        }
                        else {
                            # Could be another group or something else
                            $memberName = $memberEntry.Properties["name"].Value
                            Write-Host "  Non-user member: $memberName"
                        }
                    }
                    catch {
                        Write-Host "  Could not retrieve member for $memberDN"
                    }
                }
            }
            else {
                Write-Host "  (No members found in this group.)"
            }
        }
    }
    catch {
        Write-Error "Error querying 'adm' groups: $_"
    }
    # endregion
}

END {
    Write-Host "`nLDAP queries complete." -ForegroundColor Cyan
}

