# Nmap 7.94SVN scan initiated Fri Nov 22 02:41:21 2024 as: nmap -vvv -Pn -sC -sV -oN /opt/THM/Creative/1-recon/nmap/nmap_init.md 10.10.164.66
Nmap scan report for 10.10.164.66
Host is up, received user-set (0.100s latency).
Scanned at 2024-11-22 02:41:21 EST for 22s
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:5c:1c:4e:b4:86:cf:58:9f:22:f9:7c:54:3d:7e:7b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCsXwQrUw2YlhqFRnJpLvzHz5VnTqQ/Xr+IMJmnIyh82p1WwUsnFHgAELVccD6DdB1ksKH5HxD8iBoY83p3d/UfM8xlPzWGZkTAfZ+SR1b6MJEJU/JEiooZu4aPe4tiRdNQKB09stTOfaMUFsbXSYGjvf5u+gavNZOOTCQxEoKeZzPzxUJ0baz/Vx5Elihfm3MoR0nrE2XFTY6HV2cwLojeWCww3njG+P1E4salm86MAswQWxOeHLk/a0wXJ343X5NaHNuF4Xo3PpqiUr+qEZUyZJKNrH4O8hErH/2h7AUEPpPIo7zEK1ZzqFNWcpOqguYOFVZMagHS//ASg3ikzouZS1nUmS7ehA9bGrhCbqMRSin1QJ/mnwYBylW6IsPyfuJfl9KFnbTITa56URmudd999UzNEj8Wx8Qj4LfTWKLubcYS9iKN+exbAxXOIdbpolVtIFh0mP/cm9WRhf0z9WR9tX1FvJYi013rcaMpy62pjPCO20nbNsnEG6QckMk/4RM=
|   256 47:d5:bb:58:b6:c5:cc:e3:6c:0b:00:bd:95:d2:a0:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOIFbjvSW+v5RoDWDKFI//sn2LxlSxk2ovUPyUzpB1g/XQLlbF1oy3To2D8N8LAWwrLForz4IJ4JrZXR5KvRK8Y=
|   256 cb:7c:ad:31:41:bb:98:af:cf:eb:e4:88:7f:12:5e:89 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFf4qwz85WzZVwohJm4pYByLpBj7j2JiQp4cBqmaBwYV
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://creative.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Nov 22 02:41:43 2024 -- 1 IP address (1 host up) scanned in 22.53 seconds
