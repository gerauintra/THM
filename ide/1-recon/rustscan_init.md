[1;34m[~][0m The config file is expected to be at "/home/rustscan/.rustscan.toml"
[1;34m[~][0m File limit higher than batch size. Can increase speed by increasing batch size '-b 1073741716'.
Open 10.10.239.154:21
Open 10.10.239.154:22
Open 10.10.239.154:80
Open 10.10.239.154:62337
[1;34m[~][0m Starting Script(s)
[1;34m[~][0m Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-24 12:56 UTC
Initiating Ping Scan at 12:56
Scanning 10.10.239.154 [2 ports]
Completed Ping Scan at 12:56, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:56
Completed Parallel DNS resolution of 1 host. at 12:56, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:56
Scanning 10.10.239.154 [4 ports]
Discovered open port 80/tcp on 10.10.239.154
Discovered open port 21/tcp on 10.10.239.154
Discovered open port 22/tcp on 10.10.239.154
Discovered open port 62337/tcp on 10.10.239.154
Completed Connect Scan at 12:56, 0.16s elapsed (4 total ports)
Nmap scan report for 10.10.239.154
Host is up, received syn-ack (0.18s latency).
Scanned at 2024-11-24 12:56:13 UTC for 0s

PORT      STATE SERVICE REASON
21/tcp    open  ftp     syn-ack
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
62337/tcp open  unknown syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds

