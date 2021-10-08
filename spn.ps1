[CmdletBinding()]
Param(
  [Parameter(Mandatory=$False,Position=1)] [string]$GCName,
  [Parameter(Mandatory=$False)] [string]$Filter,
  [Parameter(Mandatory=$False)] [switch]$Request,
  [Parameter(Mandatory=$False)] [switch]$UniqueAccounts
)

Add-Type -AssemblyName System.IdentityModel

$GCs = @()

If ($GCName) {
  $GCs += $GCName
} else { # find them
  $ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
  $CurrentGCs = $ForestInfo.FindAllGlobalCatalogs()
  ForEach ($GC in $CurrentGCs) {
    #$GCs += $GC.Name
    $GCs += $ForestInfo.ApplicationPartitions[0].SecurityReferenceDomain
  }
}

if (-not $GCs) {
  # no Global Catalogs Found
  Write-Host "No Global Catalogs Found!"
  Exit
}

ForEach ($GC in $GCs) {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = "LDAP://" + $GC
    $searcher.PageSize = 1000
    $searcher.Filter = "(&(!objectClass=computer)(servicePrincipalName=*))"
    $searcher.PropertiesToLoad.Add("serviceprincipalname") | Out-Null
    $searcher.PropertiesToLoad.Add("name") | Out-Null
    $searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
    #$searcher.PropertiesToLoad.Add("userprincipalname") | Out-Null
    #$searcher.PropertiesToLoad.Add("displayname") | Out-Null
    $searcher.PropertiesToLoad.Add("memberof") | Out-Null
    $searcher.PropertiesToLoad.Add("pwdlastset") | Out-Null
    #$searcher.PropertiesToLoad.Add("distinguishedname") | Out-Null

    $searcher.SearchScope = "Subtree"

    $results = $searcher.FindAll()
    
    [System.Collections.ArrayList]$accounts = @()
        
    foreach ($result in $results) {
        foreach ($spn in $result.Properties["serviceprincipalname"]) {
            $o = Select-Object -InputObject $result -Property `
                @{Name="ServicePrincipalName"; Expression={$spn.ToString()} }, `
                @{Name="Name";                 Expression={$result.Properties["name"][0].ToString()} }, `
                #@{Name="UserPrincipalName";   Expression={$result.Properties["userprincipalname"][0].ToString()} }, `
                @{Name="SAMAccountName";       Expression={$result.Properties["samaccountname"][0].ToString()} }, `
                #@{Name="DisplayName";         Expression={$result.Properties["displayname"][0].ToString()} }, `
                @{Name="MemberOf";             Expression={$result.Properties["memberof"][0].ToString()} }, `
                @{Name="PasswordLastSet";      Expression={[datetime]::fromFileTime($result.Properties["pwdlastset"][0])} } #, `
                #@{Name="DistinguishedName";   Expression={$result.Properties["distinguishedname"][0].ToString()} }
            if ($UniqueAccounts) {
                if (-not $accounts.Contains($result.Properties["samaccountname"][0].ToString())) {
                    $accounts.Add($result.Properties["samaccountname"][0].ToString()) | Out-Null
                    $o
                    if ($Request) {
                        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ToString() | Out-Null
                    }
                }
            } else {
                $o
                if ($Request) {
                    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ToString() | Out-Null
                }
            }
        }
    }
}
