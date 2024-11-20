
Open 10.10.195.175:22
Open 10.10.195.175:80
[1;34m[~][0m Starting Script(s)
[1;34m[~][0m Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-20 09:15 UTC
Initiating Ping Scan at 09:15
Scanning 10.10.195.175 [2 ports]
Completed Ping Scan at 09:15, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:15
Completed Parallel DNS resolution of 1 host. at 09:15, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 09:15
Scanning 10.10.195.175 [2 ports]
Discovered open port 80/tcp on 10.10.195.175
Discovered open port 22/tcp on 10.10.195.175
Completed Connect Scan at 09:15, 0.10s elapsed (2 total ports)
Nmap scan report for 10.10.195.175
Host is up, received syn-ack (0.10s latency).
Scanned at 2024-11-20 09:15:02 UTC for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds

