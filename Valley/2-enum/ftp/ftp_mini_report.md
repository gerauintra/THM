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




