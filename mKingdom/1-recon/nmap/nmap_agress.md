# Nmap 7.94SVN scan initiated Fri Nov 22 05:55:34 2024 as: nmap -vvv -Pn -sC -sV -A -oN /opt/THM/mKingdom/1-recon/nmap/nmap_agress.md 10.10.210.78
Increasing send delay for 10.10.210.78 from 0 to 5 due to 50 out of 166 dropped probes since last increase.
Nmap scan report for mkingdom.thm (10.10.210.78)
Host is up, received user-set (0.097s latency).
Scanned at 2024-11-22 05:55:35 EST for 21s
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
85/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: 0H N0! PWN3D 4G4IN
|_http-server-header: Apache/2.4.7 (Ubuntu)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov 22 05:55:56 2024 -- 1 IP address (1 host up) scanned in 21.55 seconds
