# Nmap 7.94SVN scan initiated Fri Nov 22 05:55:32 2024 as: nmap -vvv -Pn -sC -sV -oN /opt/THM/mKingdom/1-recon/nmap/nmap_init.md 10.10.210.78
Nmap scan report for mkingdom.thm (10.10.210.78)
Host is up, received user-set (0.098s latency).
Scanned at 2024-11-22 05:55:32 EST for 23s
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
85/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 0H N0! PWN3D 4G4IN
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov 22 05:55:55 2024 -- 1 IP address (1 host up) scanned in 23.94 seconds
