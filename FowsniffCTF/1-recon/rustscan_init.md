


Open 10.10.191.213:22
Open 10.10.191.213:80
Open 10.10.191.213:110
Open 10.10.191.213:143

Initiating Ping Scan at 06:38
Scanning 10.10.191.213 [2 ports]
Completed Ping Scan at 06:38, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 06:38
Completed Parallel DNS resolution of 1 host. at 06:38, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 06:38
Scanning 10.10.191.213 [4 ports]
Discovered open port 22/tcp on 10.10.191.213
Discovered open port 143/tcp on 10.10.191.213
Discovered open port 110/tcp on 10.10.191.213
Discovered open port 80/tcp on 10.10.191.213
Completed Connect Scan at 06:38, 0.10s elapsed (4 total ports)
Nmap scan report for 10.10.191.213
Host is up, received conn-refused (0.098s latency).
Scanned at 2024-11-20 06:38:56 UTC for 0s

PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack
80/tcp  open  http    syn-ack
110/tcp open  pop3    syn-ack
143/tcp open  imap    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds

