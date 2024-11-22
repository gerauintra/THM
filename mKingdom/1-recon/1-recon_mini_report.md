```
nmap -vvv -Pn -sC -sV -oN /opt/THM/mKingdom/1-recon/nmap/nmap_init.md 10.10.210.78
```

```
PORT   STATE SERVICE REASON  VERSION
85/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 0H N0! PWN3D 4G4IN
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```