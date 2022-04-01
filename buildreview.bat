echo Running Build Review Commands, please wait....
@echo off

echo -------- >> buildreview.txt
echo [+] System Info >> buildreview.txt
systeminfo >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Patches >> buildreview.txt
wmic qfe list >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] User privs >> buildreview.txt
whoami /priv >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Shares >> buildreview.txt
net share >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Localgroups >> buildreview.txt
net localgroup >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Local Users >> buildreview.txt
net users >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Password Policy >> buildreview.txt
net accounts >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] GP-Results >> buildreview.txt
GPResult /R >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Software >> buildreview.txt
wmic /output:"Software.txt" product get Name, Version, Vendor

echo -------- >> buildreview.txt
echo [+] IP Info >> buildreview.txt
ipconfig /all >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Internet Connectivity >> buildreview.txt
PING www.google.com >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Route >> buildreview.txt
route PRINT >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Traceroute >> buildreview.txt
tracert google.com >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Domain PW Policy >> buildreview.txt
net accounts /domain >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Domain Users >> buildreview.txt
net users /domain >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Domain groups >> buildreview.txt
net groups /domain >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Domain Admins >> buildreview.txt
net group "Domain admins" /domain >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] ARP Known Hosts >> buildreview.txt
arp -A >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Netstat >> buildreview.txt
netstat -ano >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Hosts >> buildreview.txt
type C:\WINDOWS\System32\drivers\etc\hosts >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] DNS Records >> buildreview.txt
ipconfig /displaydns | findstr "Record" | findstr "Name Host" >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Logged In Users >> buildreview.txt
qwinsta >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] List Sessions >> buildreview.txt
klist sessions >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Stored Credentials >> buildreview.txt
cmdkey /list >> buildreview.txt

echo -------- >> buildreview.txt
echo [+] Logged In Users >> buildreview.txt
query user >> buildreview.txt

