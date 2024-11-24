# Nmap 7.94SVN scan initiated Sun Nov 24 04:22:57 2024 as: nmap -vvv -Pn -sC -sV -A -oN /opt/THM/Archangel/1-recon/nmap/nmap_agress.md 10.10.93.86
Increasing send delay for 10.10.93.86 from 0 to 5 due to 30 out of 98 dropped probes since last increase.
Increasing send delay for 10.10.93.86 from 5 to 10 due to 11 out of 21 dropped probes since last increase.
Warning: Hit PCRE_ERROR_MATCHLIMIT when probing for service http with the regex '^HTTP/1\.1 \d\d\d (?:[^\r\n]*\r\n(?!\r\n))*?.*\r\nServer: Virata-EmWeb/R([\d_]+)\r\nContent-Type: text/html; ?charset=UTF-8\r\nExpires: .*<title>HP (Color |)LaserJet ([\w._ -]+)&nbsp;&nbsp;&nbsp;'
Nmap scan report for 10.10.93.86
Host is up, received user-set (0.14s latency).
Scanned at 2024-11-24 04:22:57 EST for 46s
Not shown: 984 closed tcp ports (conn-refused)
PORT      STATE    SERVICE        REASON      VERSION
22/tcp    open     ssh            syn-ack     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f:1d:2c:9d:6c:a4:0e:46:40:50:6f:ed:cf:1c:f3:8c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPrwb4vLZ/CJqefgxZMUh3zsubjXMLrKYpP8Oy5jNSRaZynNICWMQNfcuLZ2GZbR84iEQJrNqCFcbsgD+4OPyy0TXV1biJExck3OlriDBn3g9trxh6qcHTBKoUMM3CnEJtuaZ1ZPmmebbRGyrG03jzIow+w2updsJ3C0nkUxdSQ7FaNxwYOZ5S3X5XdLw2RXu/o130fs6qmFYYTm2qii6Ilf5EkyffeYRc8SbPpZKoEpT7TQ08VYEICier9ND408kGERHinsVtBDkaCec3XmWXkFsOJUdW4BYVhrD3M8JBvL1kPmReOnx8Q7JX2JpGDenXNOjEBS3BIX2vjj17Qo3V
|   256 63:73:27:c7:61:04:25:6a:08:70:7a:36:b2:f2:84:0d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKhhd/akQ2OLPa2ogtMy7V/GEqDyDz8IZZQ+266QEHke6vdC9papydu1wlbdtMVdOPx1S6zxA4CzyrcIwDQSiCg=
|   256 b6:4e:d2:9c:37:85:d6:76:53:e8:c4:e0:48:1c:ae:6c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBE3FV9PrmRlGbT2XSUjGvDjlWoA/7nPoHjcCXLer12O
80/tcp    open     http           syn-ack     Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Wavefire
1070/tcp  filtered gmrupdateserv  no-response
1137/tcp  filtered trim           no-response
1259/tcp  filtered opennl-voice   no-response
1972/tcp  filtered intersys-cache no-response
3011/tcp  filtered trusted-web    no-response
4045/tcp  filtered lockd          no-response
4321/tcp  filtered rwhois         no-response
5999/tcp  filtered ncd-conf       no-response
7001/tcp  filtered afs3-callback  no-response
10004/tcp filtered emcrmirccd     no-response
13722/tcp filtered netbackup      no-response
27355/tcp filtered unknown        no-response
32781/tcp filtered unknown        no-response
57797/tcp filtered unknown        no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov 24 04:23:43 2024 -- 1 IP address (1 host up) scanned in 46.74 seconds
