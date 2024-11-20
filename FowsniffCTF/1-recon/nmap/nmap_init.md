# Nmap 7.94SVN scan initiated Wed Nov 20 01:58:42 2024 as: /usr/lib/nmap/nmap --privileged -vvv -Pn -sC -sV -oN /opt/THM/FowsniffCTF/1-recon/nmap/nmap_init.md 10.10.191.213
Nmap scan report for 10.10.191.213
Host is up, received user-set (0.10s latency).
Scanned at 2024-11-20 01:58:43 EST for 12s
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE REASON         VERSION
22/tcp  open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsEu5DAulaUX38ePQyI/MzevdyvWR3AXyrddVqbu9exD/jVVKZopquTfkbNwS5ZkADUvggwHnjZiLdOZO378azuUfSp5geR9WQMeKR9xJe8swjKINBtwttFgP2GrG+7IO+WWpxBSGa8akgmLDPZHs2XXd6MXY9swqfjN9+eoLX8FKYVGmf5BKfRcg4ZHW8rQZAZwiMDqQLYechzRPnePiGCav99v0X5B8ehNCCuRTQkm9DhkAcxVBlkXKq1XuFgUBF9y+mVoa0tgtiPYC3lTOBgKuwVZwFMSGoQStiw4n7Dupa6NmBrLUMKTX1oYwmN0wnYVH2oDvwB3Y4n826Iymh
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPowlRdlwndVdJLnQjxm5YLEUTZZfjfZO7TCW1AaiEjkmNQPGf1o1+iKwQJOZ6rUUJglqG8h3UwddXw75eUx5WA=
|   256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHU5PslBhG8yY6H4dpum8qgwUn6wE3Yrojnu4I5q0eTd
80/tcp  open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Fowsniff Corp - Delivering Solutions
|_http-server-header: Apache/2.4.18 (Ubuntu)
110/tcp open  pop3    syn-ack ttl 61 Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) TOP CAPA PIPELINING USER AUTH-RESP-CODE RESP-CODES UIDL
143/tcp open  imap    syn-ack ttl 61 Dovecot imapd
|_imap-capabilities: LITERAL+ more ENABLE OK post-login AUTH=PLAINA0001 capabilities IMAP4rev1 SASL-IR listed LOGIN-REFERRALS Pre-login have IDLE ID
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Nov 20 01:58:55 2024 -- 1 IP address (1 host up) scanned in 12.50 seconds
