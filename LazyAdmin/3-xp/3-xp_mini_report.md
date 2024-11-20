
searchsploit sweetrice 1.5.1
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                              |  Path
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
SweetRice 1.5.1 - Arbitrary File Download                                                                                   | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                                                                                     | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                                                                                         | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery                                                                                | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution                                                           | php/webapps/40700.html
---------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

https://www.exploit-db.com/exploits/40716

could not get it to work, moving through the list

https://www.exploit-db.com/exploits/40700

seeing code execution in the name, i'd prefer to give this a try, we might be able to get a reverse shell

```html
# In SweetRice CMS Panel In Adding Ads Section SweetRice Allow To Admin Add
PHP Codes In Ads File
# A CSRF Vulnerabilty In Adding Ads Section Allow To Attacker To Execute
PHP Codes On Server .
# In This Exploit I Just Added a echo '<h1> Hacked </h1>'; phpinfo(); 
Code You Can
```

this is the url on our target machine

http://10.10.195.175/content/as/?type=ad

code to run phpinfo from the demo exploit

![[phpinfo.png]]

from the published exploit

```html
# After HTML File Executed You Can Access Page In
http://localhost/sweetrice/inc/ads/hacked.php
```

so we will go to this url for our instance

```
http://10.10.195.175/content/inc/ads/phpinfo.php
```


![[phpinfoad.png]]

the vulnerability works, now we need to exploit it. PHPbash is a sweet tool for certain php code execution vulnerabilities. basically for when you upload php code in some way, then to execute it all you do is visit the url where that code was uploaded

https://github.com/Arrexel/phpbash/blob/master/phpbash.php

make a new ad and paste the php bash code

![[phpbashad.png]]


http://10.10.195.175/content/inc/ads/phpbash.php

![[phpbashadurl.png]]

/home/itguy/user.txt

```
THM{63e5bce9271952aad1113b6f1ac28a07}
```

and we have a basic shell running on the target machine