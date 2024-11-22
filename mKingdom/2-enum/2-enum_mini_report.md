http://10.10.210.78:85/

![[web85.png]]

```
gobuster dir -u http://10.10.210.78:85 -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/mKingdom/2-enum/web/gob_dir_big.md
```

```
/app                  (Status: 301) [Size: 308] [--> http://10.10.210.78:85/app/]
```

http://10.10.210.78:85/app

![[appdir.png]]

looking at the source

```
<button onclick="buttonClick()">JUMP</button>  
  
    <script>  
        function buttonClick() {  
            alert("Make yourself confortable and enjoy my place.");  
            window.location.href = 'castle';  
        }  
    </script>
```

when clicking the jump button, we get a javascript alert

![[js alert.png]]

nothing much

more directory searching

```
gobuster dir -u http://10.10.210.78:85/app/ -w /usr/share/wordlists/dirb/big.txt -o /opt/THM/mKingdom/2-enum/web/gob_dir_big.md
```

```
/castle               (Status: 301) [Size: 315] [--> http://10.10.210.78:85/app/castle/]
```

http://10.10.210.78:85/app/castle/

![[castledir.png]]

```
Built with [concrete5](http://www.concrete5.org) CMS.
```

```
<meta name="generator" content="concrete5 - 8.5.2"/>
```

```
searchsploit concrete5 cms         
--------------------------------------------- ---------------------------------
 Exploit Title                               |  Path
--------------------------------------------- ---------------------------------
Concrete CMS 5.4.1.1 - Cross-Site Scripting  | php/webapps/15915.py
Concrete5 CMS 5.5.2.1 - Information Disclosu | php/webapps/37103.txt
Concrete5 CMS 5.6.1.2 - Multiple Vulnerabili | php/webapps/26077.txt
Concrete5 CMS 5.6.2.1 - 'index.php?cID' SQL  | php/webapps/31735.txt
Concrete5 CMS 5.7.3.1 - 'Application::dispat | php/webapps/40045.txt
Concrete5 CMS 8.1.0 - 'Host' Header Injectio | php/webapps/41885.txt
Concrete5 CMS < 5.4.2.1 - Multiple Vulnerabi | php/webapps/17925.txt
Concrete5 CMS < 8.3.0 - Username / Comments  | php/webapps/44194.py
Concrete5 CMS FlashUploader - Arbitrary '.SW | php/webapps/37226.txt
--------------------------------------------- ---------------------------------
Shellcodes: No Results
```

not very helpful 

looking at the blog

```
http://10.10.210.78:85/app/castle/index.php/blog
```

index.php is actually a directory

checking ZAPROXY we can see there is a login page

http://10.10.210.78:85/app/castle/index.php/login

![[login.png]]
