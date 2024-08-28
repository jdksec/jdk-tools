@echo off

ECHO Checking permissions...
net session > NUL 2>&1
if not %ERRORLEVEL% == 0 (
  echo ******************************************************************************
  echo   ERROR Script must be executed from an elevated administrator command prompt
  echo ******************************************************************************
  pause
  exit /b 1
)
ECHO Setting up...
set host=%COMPUTERNAME%
IF NOT EXIST %host% MKDIR %host%
IF %ERRORLEVEL% NEQ 0 GOTO ERROR
CD %host%
time /t > starttime.txt
date /t > startdate.txt

ECHO Running main checks...
auditpol /get /category:* >auditpol.txt
bcdedit /enum all > bootconfigurationenum.txt
cacls "c:\Users\All Users\Sophos\AutoUpdate\Config\iconn.cfg" > sophoscalciconn.txt 2>&1
hostname > hostname.txt
ipconfig /all > ipconfig.txt
net accounts  > net_accounts.txt 2>&1
net accounts /domain  > net_accounts_domain.txt 2>&1
net localgroup Administrators > admins.txt
net user epoadmin /domain > epoadmindomainuser.txt 2>&1
net user > net_users.txt
net user Administrator > net_user_Administrator.txt 2>&1
net user Guest > net_user_Guest.txt 2>&1
netsh advfirewall show allprofiles > netsh_advfirewall_show_allprofiles.txt
path > path.txt
powershell -c Get-WindowsFeature PowerShell-V2 > powershellv2server.txt 2>&1
powershell -c Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 > powershellv2desktop.txt 2>&1
powershell -c $PSVersionTable.PSVersion > powershellver.txt 2>&1
powershell -version 2 -c $PSVersionTable.PSVersion > powershellv2ver.txt
reg query HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL > RQK-RunAsPPL.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions\ProcessMitigationOptions" > RQ-ProcessMitigationOptions.txt 
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v MSAOptional > RQK-MSAOptional.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v UndockWithoutLogon > RQK-UndockWithoutLogon.txt
reg query HKLM\SYSTEM\CurrentControlSet\Control\LSA /v restrictanonymous > RQK-restrictanonymous.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters /v RestrictNullSessAccess > RQK-RestrictNullSessAccess.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters /v NullSessionPipes > RQK-NullSessionPipes.txt 2>&1
reg query hklm\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate > RQK-NoAutoUpdate.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun > RQK-NoDriveTypeAutoRun.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows\AppCompat /v DisableInventory > RQK-DisableInventory.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWebServices > RQK-NoWebServices.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoPublishingWizard > RQK-NoPublishingWizard.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\SearchCompanion /v DisableContentFileUpdates > RQK-DisableContentFileUpdates.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Messenger\Client /v CEIP > RQK-CEIP.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\SQMClient\Windows /v CEIPEnable > RQK-CEIPEnable.txt 2>&1
reg query HKLM\Software\policies\Microsoft\Peernet /v Disabled >RQK-p2pDisabled.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v InactivityTimeoutSecs > RQK-InactivityTimeoutSecs.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DontDisplayLastUserName > RQK-DontDisplayLastUserName.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows\CredUI /v DisablePasswordReveal > RQK-DisablePasswordReveal.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows\System /v EnableSmartScreen > RQK-EnableSmartScreen.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation /v AllowInsecureGuestAuth > RQK-AllowInsecureGuestAuth.txt 2>&1
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v NoConnectedUser > RQK-NoConnectedUser.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging >> RQK-EnableScriptBlockLogging.txt 2>&1
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging >> RQK-EnableScriptBlockLogging.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fPromptForPassword > RQK-fPromptForPassword.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm > RQK-fDisableCdm.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry >> RQK-AllowTelemetry.txt 2>&1
reg query HKCU\Software\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry >> RQK-AllowTelemetry.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell /v EnableScripts >> RQK-EnableScripts.txt 2>&1
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell /v EnableScripts >> RQK-EnableScripts.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell /v ExecutionPolicy >> RQK-ExecutionPolicy.txt 2>&1
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell /v ExecutionPolicy >> RQK-ExecutionPolicy.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging >> RQK-EnableModuleLogging.txt 2>&1
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging >> RQK-EnableModuleLogging.txt 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount > RQK-CachedLogonsCount.txt 2>&1
echo HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application: >> RQK-MaxSize.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application /v MaxSize >> RQK-MaxSize.txt 2>&1
echo HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security: >> RQK-MaxSize.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security /v MaxSize >> RQK-MaxSize.txt 2>&1
echo HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Setup: >> RQK-MaxSize.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Setup /v MaxSize >> RQK-MaxSize.txt 2>&1
echo HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System: >> RQK-MaxSize.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System /v MaxSize >> RQK-MaxSize.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\LSA /v SuppressExtendedProtection > RQK-SuppressExtendedProtection.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\LSA /v LmCompatibilityLevel > RQK-LmCompatibilityLevel.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\LanManServer\Parameters /v SmbServerNameHardeningLevel > RQK-SmbServerNameHardeningLevel.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI /v EnumerateAdministrators > RQK-EnumerateAdministrators.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0 /v ClientAllowedNTLMServers > RQK-ClientAllowedNTLMServers.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Netlogon\Parameters /v DCAllowedNTLMServers > RQK-DCAllowedNTLMServers.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0 /v AuditReceivingNTLMTraffic > RQK-AuditReceivingNTLMTraffic.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Netlogon\Parameters /v AuditNTLMInDomain > RQK-AuditNTLMInDomain.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0 /v RestrictReceivingNTLMTraffic > RQK-RestrictReceivingNTLMTraffic.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Netlogon\Parameters /v RestrictNTLMInDomain > RQK-RestrictNTLMInDomain.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0 /v RestrictSendingNTLMTraffic > RQK-RestrictSendingNTLMTraffic.txt 2>&1
reg query "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers > RQK-AddPrinterDrivers.txt 2>&1
reg query "HKLM\SOFTWARE\policies\Microsoft\windows NT\Printers" /v DisableHTTPPrinting > RQK-DisableHTTPPrinting.txt 2>&1
reg query "HKLM\SOFTWARE\policies\Microsoft\windows NT\Printers" /v DisableWebPnPDownload > RQK-DisableWebPnPDownload.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters /v EnableSecuritySignature > RQK-EnableSecuritySignature.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\LanManServer\Parameters /v EnableSecuritySignature > RQK-EnableSecuritySignature.txt 2>&1 
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CWDIllegalInDllSearch" > RQK-CWDIllegalInDllSearch.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD > RQK-DisableCAD.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\Lsa /v NoLMHash > RQK-NoLMHash.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DontDisplayLastUserName > RQK-DontDisplayLastUserName.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel > RQK-LmCompatibilityLevel.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\SecurityProviders\Wdigest /v UseLogonCredential > RQK-UseLogonCredential.txt 2>&1
reg query "HKLM\Software\Policies\Microsoft\Windows Defender ExploitGuard\Exploit Protection" /v ExploitProtectionSettings > RQK-ExploitProtectionSettings.txt 2>&1
reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" /v ExploitGuard_ASR_ASROnlyExclusions > RQK-ExploitGuard_ASR_ASROnlyExclusions.txt 2>&1
reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v EnableNetworkProtection > RQK-EnableNetworkProtection.txt 2>&1
reg query "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v EnableControlledFolderAccess > RQK-EnableControlledFolderAccess.txt 2>&1
reg query "hklm\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyExclusions" >> ASROnlyExclusions.txt 2>&1
reg query "hklm\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\AllowedApplications" > defenderallowedapps.txt 2>&1
reg query "hklm\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\ProtectedFolders" > defenderproctfolders.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard /v EnableVirtualizationBasedSecurity > RQK-EnableVirtualizationBasedSecurity.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard /v RequirePlatformSecurityFeatures > RQK-RequirePlatformSecurityFeatures.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard /v HypervisorEnforcedCodeIntegrity > RQK-HypervisorEnforcedCodeIntegrity.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard /v LsaCfgFlags > RQK-LsaCfgFlags.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard /v DeployConfigCIPolicy > RQK-DeployConfigCIPolicy.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard /v ConfigCIPolicyFilePath > RQK-ConfigCIPolicyFilePath.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\AppHVSI /v AllowAppHVSI_ProviderSet > RQK-AllowAppHVSI_ProviderSet.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation /v DomainSubnets > RQK-DomainSubnets.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation /v CloudResources > RQK-CloudResources.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation /v NeutralResources > RQK-NeutralResources.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters /v DisableIPSourceRouting > RQK-DisableIPSourceRouting.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters /v DisableIPSourceRouting > RQK-DisableIPSourceRouting.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters /v DisableIPSourceRouting > RQK-IP6DisableIPSourceRouting.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters /v PerformRouterDiscovery > RQK-PerformRouterDiscovery.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters /v PerformRouterDiscovery > RQK-IP6PerformRouterDiscovery.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters /v EnableICMPRedirect > RQK-EnableICMPRedirect.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters /v EnableICMPRedirect > RQK-IP6EnableICMPRedirect.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters /v EnableDeadGWDetect > RQK-EnableDeadGWDetect.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters /v EnableDeadGWDetect > RQK-IP6EnableDeadGWDetect.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\Netbt\Parameters /v NoNameReleaseOnDemand > RQK-NoNameReleaseOnDemand.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LegalNoticeCaption > RQK-LegalNoticeCaption.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LegalNoticeText > RQK-LegalNoticeText.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin > RQK-ConsentPromptBehaviorAdmin.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorUser > RQK-ConsentPromptBehaviorUser.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA > RQK-EnableLUA.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken > RQK-FilterAdministratorToken.txt 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod > RQK-ScreenSaverGracePeriod.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\FileSystem /v NtfsDisable8dot3NameCreation > RQK-NtfsDisable8dot3NameCreation.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v NtlmMinClientSec > RQK-NtlmMinClientSec.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v NtlmMinServerSec > RQK-NtlmMinServerSec.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Cryptography /v ForceKeyProtection > RQK-ForceKeyProtection.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows\Personalization /v NoLockScreenSlideshow > RQK-NoLockScreenSlideshow.txt 2>&1
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableAutomaticRestartSignOn > RQK-DisableAutomaticRestartSignOn.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\LanManServer\Parameters /v EnableSecuritySignature > RQK-EnableSecuritySignature.txt 2>&1
reg query HKLM\System\CurrentControlSet\Services\LanManServer\Parameters /v RequireSecuritySignature > RQK-RequireSecuritySignature.txt 2>&1
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon /v AllocateCDRoms > RQK-AllocateCDRoms.txt 2>&1
reg query HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services /v fAllowToGetHelp > RQK-fAllowToGetHelp.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services /v fAllowUnsolicited > RQK-fAllowUnsolicited.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v DisablePasswordSaving > RQK-DisablePasswordSaving.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fPromptForPassword > RQK-fPromptForPassword.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel > RQK-MinEncryptionLevel.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v CertTemplateName > RQK-CertTemplateName.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v SecurityLayer > RQK-SecurityLayer.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication > RQK-UserAuthentication.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm > RQK-fDisableCdm.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableClip > RQK-fDisableClip.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisablePNPRedir > RQK-fDisablePNPRedir.txt 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ForceUnlockLogon > RQK-ForceUnlockLogon.txt 2>&1
reg query "HKLM\Software\Policies\Microsoft\Windows\Network Connections" /v NC_StdDomainUserSetLocation > RQK-NC_StdDomainUserSetLocation.txt 2>&1
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients > RQK-RestrictRemoteClients.txt 2>&1
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Rpc" /v EnableAuthEpResolution > RQK-EnableAuthEpResolution.txt 2>&1
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive > RQK-ScreenSaveActive.txt 2>&1
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" /v SCRNSAVE.EXE > RQK-SCRNSAVE.EXE.txt 2>&1
reg query "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaverIsSecure > RQK-ScreenSaverIsSecure.txt 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v NoDispScrSavPage > RQK-NoDispScrSavPage.txt 2>&1
reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\desktop" /v ScreenSaveTimeOut> RQK-ScreenSaveTimeOut.txt 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScRemoveOption > RQK-ScRemoveOption.txt 2>&1
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion /v SafeModeBlockNonAdmins > RQK-SafeModeBlockNonAdmins.txt 2>&1
reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableDomainCreds > RQK-DisableDomainCreds.txt 2>&1
reg query "HKLM\System\CurrentControlSet\Control\Session Manager\SubSystems" /v Optional > RQK-Optional.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" /v MitigationOptions_FontBocking > RQK-MitigationOptions_FontBocking.txt 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLockedUserId > RQK-DontDisplayLockedUserId.txt 2>&1
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateDASD > RQK-AllocateDASD.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters /v BasicAuthLevel > RQK-BasicAuthLevel.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters /v DisableBasicOverClearChannel > RQK-DisableBasicOverClearChannel.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters /v UseBasicAuth > RQK-UseBasicAuth.txt 2>&1
reg query HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config /v AutoConnectAllowedOEM > RQK-AutoConnectAllowedOEM.txt 2>&1
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v DontDisplayNetworkSelectionUI > RQK-DontDisplayNetworkSelectionUI.txt 2>&1
powershell -c "Get-ChildItem 'HKLM:Software\Policies\Microsoft\Windows\SrpV2'" > RQK-applocker.txt
powershell -c "Get-AppLockerPolicy -Effective -Xml" > applocker_policy.txt
secedit /export /log security_log.txt /cfg security_config.txt > security_policy.txt
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >winversion.txt
systeminfo > systeminfo.txt
w32tm /query /configuration > w32_time.txt
wmic nicconfig get caption,ipaddress,TCpipnetbiosoptions > netbiostcpip.txt
wmic OS GET DataExecutionPrevention_supportpolicy > DEP_policy.txt
wmic OS GET DataExecutionPrevention_available > DEP_available.txt
wmic product get name,version,vendor > softwareversion.txt
wmic service get name, displayname, startname, pathname, startmode > wmic_service.txt
wmic service where started=true get  name, startname >wmic_serviceuser.txt
wmic share get description,name,path > wmic_shares2.txt

ECHO Running extra checks with dependencies...
..\deps\autorunsc.exe /accepteula -ct > autorunsc.txt
..\deps\autorunsc.exe /accepteula -a * -ct > autorunscall.txt
..\deps\procdump.exe -accepteula -ma lsass.exe %COMPUTERNAME%_lsass.dmp

ECHO Running additional checks for brevity...
cacls c:\ > cacls_c_drive.txt
dir /ad /s /b "%ProgramFiles%" "%ProgramFiles(x86)%" > dir_program_files.txt
for /f eol^=^"^ delims^=^" %%a in ('wmic service get pathname^|find /i /v "system32"') do cmd.exe /c icacls "%%a" > service_perms.txt 2>&1
gpresult /v > gpresult.txt
GPRESULT /V /SCOPE Computer >localgpresult.txt
ipconfig /displaydns > ipconfig_displaydns.txt
net group "domain admins" /domain > net_group_da.txt 2>&1
net group "enterprise admins" /domain > net_group_ea.txt 2>&1
net localgroup > net_localgroup.txt
net share > shares.txt
net start > net_start.txt
netsh advfirewall export netsh_advfirewall_export.txt >netsh_advfirewall_export_log.txt
netsh advfirewall firewall show rule name=all > netsh_advfirewall_show_rule.txt
netstat -an > netstat-an.txt
netstat -baon > netstat-baon.txt
netstat -oan > netstat-oan.txt
netstat -rn > netstat-rn.txt
powershell -c "Get-WmiObject -Class Win32_UserAccount  -Filter "LocalAccount='True'" | Export-Csv wmiobject_users.csv" > wmiobject_users.txt 2>&1
reg query HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters > w32tm_config.txt
route print > route_print.txt
sc query > services.txt
set > set.txt
systeminfo > sysinfo.txt 2>&1
tasklist > tasklist.txt
tasklist /fi "USERNAME eq NT AUTHORITY\SYSTEM" > high_services.txt
TYPE regqueries.txt | find "IPEnableRouter" >ipforward.txt
wmic bios > wmic_bios.txt
wmic bootconfig > wmic_bootconfig.txt
wmic cpu > wmic_cpu.txt
wmic diskdrive > wmic_diskdrive.txt
wmic group > wmic_group.txt
wmic logon > wmic_logon.txt
wmic memphysical > wmic_memphysical.txt
wmic /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayname,pathtosignedproductexe > antivirus.txt 2>&1
wmic os get /format:value > wmic_os_formatted.txt
wmic os get lastbootuptime > wmic_bootuptime.txt 2>&1
wmic pagefile > wmic_pagefile.txt
wmic partition > wmic_partition.txt
wmic process get Description,ExecutablePath,processid > wmic_process2.txt
wmic process > wmic_process.txt
wmic os > wmic_os.txt
wmic product > software.txt
wmic qfe > wmic_qfe.txt
wmic qfe list > wmic_qfe_list.txt
wmic share list > wmic_shares.txt
wmic startup > startupall.txt
wmic service get name,started,startname,pathname | find "TRUE" > localservices.txt
wmic startup get name,command > startup.txt
wmic useraccount > wmic_useracc.txt
wmic qfe list brief /format:htable > MS_Hotfix_List.html
schtasks /query /v /fo LIST > schtaskslist.txt
schtasks /query /v /fo CSV > schtaskslist.csv
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast > llmnr.txt


