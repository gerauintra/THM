
RustScan: Where scanning meets swagging. 😎

[1;34m[~][0m The config file is expected to be at "/home/rustscan/.rustscan.toml"
[1;34m[~][0m File limit higher than batch size. Can increase speed by increasing batch size '-b 1073741716'.
Open 10.10.32.158:22
Open 10.10.32.158:80
Open 10.10.32.158:8765
[1;34m[~][0m Starting Script(s)
[1;34m[~][0m Starting Nmap 7.95 ( https://nmap.org ) at 2024-11-22 09:21 UTC
Initiating Ping Scan at 09:21
Scanning 10.10.32.158 [2 ports]
Completed Ping Scan at 09:21, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:21
Completed Parallel DNS resolution of 1 host. at 09:21, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 09:21
Scanning 10.10.32.158 [3 ports]
Discovered open port 80/tcp on 10.10.32.158
Discovered open port 8765/tcp on 10.10.32.158
Discovered open port 22/tcp on 10.10.32.158
Completed Connect Scan at 09:21, 0.10s elapsed (3 total ports)
Nmap scan report for 10.10.32.158
Host is up, received syn-ack (0.099s latency).
Scanned at 2024-11-22 09:21:08 UTC for 1s

PORT     STATE SERVICE        REASON
22/tcp   open  ssh            syn-ack
80/tcp   open  http           syn-ack
8765/tcp open  ultraseek-http syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds

