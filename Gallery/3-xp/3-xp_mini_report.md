https://www.exploit-db.com/exploits/50214

the payload is an SQL injection, resulting in a login

the password is left blank, the username is set to something that is true

```py
username": "admin' or '1'='1'#", "password": ""
```

http://10.10.82.219/gallery/

we will login with the following credentials (no password)

```
admin' or '1'='1'#

```

![[suclogin.png]]

we navigate to the account section for the admin

![[admin_acc.png]]

http://10.10.82.219/gallery/?page=user

from here, we can upload file by using the change avatar function of the admin

![[admin_info.png]]

we can use php bash, a tool that will give us basic command line access to the machine.

https://github.com/Arrexel/phpbash/blob/master/phpbash.php

upload phpbash, then navigate to it. to navigate to it, right click on the avatar picture (it is blank because it is not a real image jus tthe php file) and click open in new tab

for this example the url is at the following address

http://10.10.82.219/gallery/uploads/1732115340_phpbash.php

the upload url might change, so make sure to find it using the navigation teqnique shared previously

![[malavatar.png]]

and we have a shell as www-data


![[phpbashworking.png]]