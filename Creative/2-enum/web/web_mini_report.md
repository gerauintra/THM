
```bash
gobuster dir -u http://creative.thm:80 -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/Creative/2-enum/web/gob_dir_host_big.md
```

```bash
gobuster dir -u http://creative.thm:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /opt/THM/Creative/2-enum/web/gob_dir_host_2.3_med.md
```

```
gobuster dns -d creative.thm -t 50 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o /opt/THM/Creative/2-enum/dns/gob_dns_sub1.md
```

```
gobuster dns -d creative.thm -t 50 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o /opt/THM/Creative/2-enum/dns/gob_dns_sub2.md
```

```
gobuster vhost --append-domain -u http://creative.thm/ -t 50 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o /opt/THM/Creative/2-enum/dns/gob_vhost_sub1.md
```

```
gobuster vhost --append-domain -u http://creative.thm/ -t 50 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o /opt/THM/Creative/2-enum/dns/gob_vhost_sub2.md
```


```
Found: beta.creative.thm Status: 200 [Size: 591]
```

add to /etc/hosts

```
10.10.164.66        creative.thm beta.creative.thm
```


http://beta.creative.thm/

![[beta thm.png]]
