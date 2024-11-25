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

