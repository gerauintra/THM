# Nmap 7.94SVN scan initiated Sun Nov 24 07:55:47 2024 as: nmap -vvv -Pn -sC -sV -oN /opt/THM/ide/1-recon/nmap/nmap_init.md 10.10.239.154
Increasing send delay for 10.10.239.154 from 5 to 10 due to 11 out of 13 dropped probes since last increase.
Nmap scan report for 10.10.239.154
Host is up, received user-set (0.14s latency).
Scanned at 2024-11-24 07:55:48 EST for 46s
Not shown: 988 closed tcp ports (conn-refused)
PORT      STATE    SERVICE       REASON      VERSION
21/tcp    open     ftp           syn-ack     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.6.24.127
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp    open     ssh           syn-ack     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:be:d3:3c:e8:76:81:ef:47:7e:d0:43:d4:28:14:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC94RvPaQ09Xx+jMj32opOMbghuvx4OeBVLc+/4Hascmrtsa+SMtQGSY7b+eyW8Zymxi94rGBIN2ydPxy3XXGtkaCdQluOEw5CqSdb/qyeH+L/1PwIhLrr+jzUoUzmQil+oUOpVMOkcW7a00BMSxMCij0HdhlVDNkWvPdGxKBviBDEKZAH0hJEfexz3Tm65cmBpMe7WCPiJGTvoU9weXUnO3+41Ig8qF7kNNfbHjTgS0+XTnDXk03nZwIIwdvP8dZ8lZHdooM8J9u0Zecu4OvPiC4XBzPYNs+6ntLziKlRMgQls0e3yMOaAuKfGYHJKwu4AcluJ/+g90Hr0UqmYLHEV
|   256 a8:82:e9:61:e4:bb:61:af:9f:3a:19:3b:64:bc:de:87 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBzKTu7YDGKubQ4ADeCztKu0LL5RtBXnjgjE07e3Go/GbZB2vAP2J9OEQH/PwlssyImSnS3myib+gPdQx54lqZU=
|   256 24:46:75:a7:63:39:b6:3c:e9:f1:fc:a4:13:51:63:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ+oGPm8ZVYNUtX4r3Fpmcj9T9F2SjcRg4ansmeGR3cP
80/tcp    open     http          syn-ack     Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
514/tcp   filtered shell         no-response
1063/tcp  filtered kyoceranetdev no-response
1077/tcp  filtered imgames       no-response
1494/tcp  filtered citrix-ica    no-response
1583/tcp  filtered simbaexpress  no-response
3324/tcp  filtered active-net    no-response
3325/tcp  filtered active-net    no-response
4848/tcp  filtered appserv-http  no-response
33354/tcp filtered unknown       no-response
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 24 07:56:34 2024 -- 1 IP address (1 host up) scanned in 47.15 seconds
