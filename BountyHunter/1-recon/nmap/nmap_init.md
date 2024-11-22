# Nmap 7.94SVN scan initiated Fri Nov 22 00:09:13 2024 as: nmap -vvv -Pn -sC -sV -oN /opt/THM/BountyHunter/1-recon/nmap/nmap_init.md 10.10.188.195
Nmap scan report for 10.10.188.195
Host is up, received user-set (0.099s latency).
Scanned at 2024-11-22 00:09:14 EST for 43s
Not shown: 967 filtered tcp ports (no-response)
PORT      STATE  SERVICE         REASON       VERSION
20/tcp    closed ftp-data        conn-refused
21/tcp    open   ftp             syn-ack      vsftpd 3.0.3
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
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp    open   ssh             syn-ack      OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgcwCtWTBLYfcPeyDkCNmq6mXb/qZExzWud7PuaWL38rUCUpDu6kvqKMLQRHX4H3vmnPE/YMkQIvmz4KUX4H/aXdw0sX5n9jrennTzkKb/zvqWNlT6zvJBWDDwjv5g9d34cMkE9fUlnn2gbczsmaK6Zo337F40ez1iwU0B39e5XOqhC37vJuqfej6c/C4o5FcYgRqktS/kdcbcm7FJ+fHH9xmUkiGIpvcJu+E4ZMtMQm4bFMTJ58bexLszN0rUn17d2K4+lHsITPVnIxdn9hSc3UomDrWWg+hWknWDcGpzXrQjCajO395PlZ0SBNDdN+B14E0m6lRY9GlyCD9hvwwB
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMCu8L8U5da2RnlmmnGLtYtOy0Km3tMKLqm4dDG+CraYh7kgzgSVNdAjCOSfh3lIq9zdwajW+1q9kbbICVb07ZQ=
|   256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICqmJn+c7Fx6s0k8SCxAJAoJB7pS/RRtWjkaeDftreFw
80/tcp    open   http            syn-ack      Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
990/tcp   closed ftps            conn-refused
40193/tcp closed unknown         conn-refused
40911/tcp closed unknown         conn-refused
41511/tcp closed unknown         conn-refused
42510/tcp closed caerpc          conn-refused
44176/tcp closed unknown         conn-refused
44442/tcp closed coldfusion-auth conn-refused
44443/tcp closed coldfusion-auth conn-refused
44501/tcp closed unknown         conn-refused
45100/tcp closed unknown         conn-refused
48080/tcp closed unknown         conn-refused
49152/tcp closed unknown         conn-refused
49153/tcp closed unknown         conn-refused
49154/tcp closed unknown         conn-refused
49155/tcp closed unknown         conn-refused
49156/tcp closed unknown         conn-refused
49157/tcp closed unknown         conn-refused
49158/tcp closed unknown         conn-refused
49159/tcp closed unknown         conn-refused
49160/tcp closed unknown         conn-refused
49161/tcp closed unknown         conn-refused
49163/tcp closed unknown         conn-refused
49165/tcp closed unknown         conn-refused
49167/tcp closed unknown         conn-refused
49175/tcp closed unknown         conn-refused
49176/tcp closed unknown         conn-refused
49400/tcp closed compaqdiag      conn-refused
49999/tcp closed unknown         conn-refused
50000/tcp closed ibm-db2         conn-refused
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov 22 00:09:57 2024 -- 1 IP address (1 host up) scanned in 43.51 seconds
