
ftp anon allowed

```
ftp 10.10.239.154 
```

```                 
Connected to 10.10.239.154.
220 (vsFTPd 3.0.3)
Name (10.10.239.154:devel): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

strange directory labeled "*...*"
```
ftp> ls -la
229 Entering Extended Passive Mode (|||7095|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        114          4096 Jun 18  2021 .
drwxr-xr-x    3 0        114          4096 Jun 18  2021 ..
drwxr-xr-x    2 0        0            4096 Jun 18  2021 ...
```

strange file named "*-*"

```
ftp> ls
229 Entering Extended Passive Mode (|||53721|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             151 Jun 18  2021 -
226 Directory send OK.
ftp> cd -
550 Failed to change directory.
ftp> get -
local: - remote: -
229 Entering Extended Passive Mode (|||46769|)
150 Opening BINARY mode data connection for - (151 bytes).
100% |**********************************|   151      140.70 KiB/s    00:00 ETA
226 Transfer complete.
151 bytes received in 00:00 (1.22 KiB/s)

```

renamed the file to "strange" so its not messing with any terminal tools

```
└─$ file strange                       
strange: ASCII text
```

contents of the file

```
Hey john,
I have reset the password as you have asked. Please use the default password to login. 
Also, please take care of the image file ;)
- drac.
```

users

```
john
drac
```



http://10.10.239.154/

apache 2 default page


http://10.10.239.154:62337

some sort of login form


![[web62337.png]]

```
gobuster dir -u http://10.10.239.154:62337 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /opt/THM/ide/2-enum/web/gob_dir_2.3_med_62337.md
```


```
/themes               (Status: 301) [Size: 324] [--> http://10.10.239.154:62337/themes/]
```


http://10.10.239.154:62337/themes/

![[themes.png]]

also a version disclosure

view-source:http://10.10.239.154:62337/


```
<title>Codiad 2.8.4</title>
```
