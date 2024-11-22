# Recon

### Nmap


```
nmap -vvv -Pn -sC -sV -oN /opt/THM/Anthem/1-recon/nmap/nmap_init.md 10.10.206.242
```

```
PORT     STATE SERVICE       REASON  VERSION
80/tcp   open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
|_ssl-date: 2024-11-22T05:52:23+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Issuer: commonName=WIN-LU09299160F
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-21T05:50:29
| Not valid after:  2025-05-23T05:50:29
| MD5:   6058:7a17:a001:ba5f:9a53:a8cf:6036:de8e
| SHA-1: bc38:052a:9d1c:1b56:0e56:ad61:bdad:601e:30ae:7195
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQcgdp57WQpqJDtQQt62sW3TANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9XSU4tTFUwOTI5OTE2MEYwHhcNMjQxMTIxMDU1MDI5WhcNMjUw
| NTIzMDU1MDI5WjAaMRgwFgYDVQQDEw9XSU4tTFUwOTI5OTE2MEYwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDNtOKZVw5cFKNPq+5qrdNvIKTRDn1cBly0
| PXa2vpkDvd0i+GqTGnB1yKk6sImihcugVFd8o2xc80JzrMvrO2l7j4qW5t8XSZUf
| DpVG9xwLnTFrWh1ROsD0ZN9iz7HcewNMdbgJaemrlhdzsZSgyV03hQDZxQAsK9FX
| bUh8WXjmnQAjHwKqCuIXRujsVPONDMSWdzpNUjEhaQLcNO1V31n1znRDhAFx7SuJ
| b7yOrpYupeTMCNnSYZpakNPw5WuDWl+KODBVr8Y0Bs1MUxrzi0u9kTr8odmu/Rvo
| 7Vlli4jyr1ARUsEHqjsUYcOCUVex5gFzyGgxhhnjvIRAVrumtcpZAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAHXmExKLpIJfeakzDD9Zct0Oh4xnPoBJG7Yupq4rt6sVF9Nhv2NPsQ80y
| BmH7CWRyEtUVacG5wnTfSQBSrdClJAmKIvC0Ta5AkkWPR1ujyqe2SoK0GYmz+X+n
| bdqQVG9eFQbsz46ptC6H5+tEklWOJoQBIYYz7AbhlRA1YvC/D2WKI557EwtuTSNk
| wl6OZ6m4/6Lrx8mw4iE/Ro47gEs8ckTR1ZcR866K93wY87vdvUZqhu9fCaOjDUTe
| zwzaydowEwXcrLrWlhQZ/7iljWRX39m54D79ebamFwkUkQveSu8BOLvJMUxxqW2x
| Ms4Bo9TcCUUiUYKUeBs4B5XLZATSkQ==
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2024-11-22T05:51:16+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# Enumeration

### WEB

http://10.10.206.242 

might need to edit /etc/hosts

![[mainweb.png]]

/etc/hosts
```
10.10.206.242    anthem.com
```

```
UmbracoIsTheBest!
  
  
# Use for all search robots
  
User-agent: *
  
  
# Define the directories not to crawl
  
Disallow: /bin/
  
Disallow: /config/
  
Disallow: /umbraco/
  
Disallow: /umbraco_client/
```

http://10.10.206.242/robots.txt

possible password
```
UmbracoIsTheBest!
```

http://anthem.com/umbraco

http://anthem.com/umbraco#/login/false?returnPath=%252Fumbraco

![[umbraco-login.png]]

seems to be umbraco cms

http://10.10.206.242/archive/we-are-hiring/

```
# We are hiring

Monday, January 20, 2020

Hi fellow readers,

We are currently hiring. We are looking for young talented to join a good cause and keep this community alive!

If you have an interest in being a part of the movement send me your CV at JD@anthem.com
```

possible user info
```
James Orchard Halliwell
jane doe
JD@anthem.com
```

http://10.10.206.242/archive/a-cheers-to-our-it-department/

strange poem

```
Born on a Monday,  
Christened on Tuesday,  
Married on Wednesday,  
Took ill on Thursday,  
Grew worse on Friday,  
Died on Saturday,  
Buried on Sunday.  
That was the end…
```

https://en.wikipedia.org/wiki/Solomon_Grundy_(nursery_rhyme)

written by solomon grundy

updaetd possible user info
```
James Orchard Halliwell
jane doe
JD@anthem.com
solomon grundy
```

tryhackme says solomon is an administrator of the site

![[adminname.png]]

going through zaproxy urls found

http://10.10.206.242/authors/jane-doe/

```
<header>
  
            <h1 class="post-title">Jane Doe</h1>              
        </header>
  
        <section class="post-content">
  
                <img class="postImage" src="/media/articulate/default/random-mask.jpg?anchor=center&amp;mode=crop&amp;width=1024&amp;height=512&amp;rnd=132305946760000000" />
  
            <p>Author for Anthem blog</p>
  
                <p>Website: <a href="THM{L0L_WH0_D15}">THM{L0L_WH0_D15}</a>
  
                </p>
  
              
        </section>
```

possible flag

```
THM{L0L_WH0_D15}
```

![[jane doe.png]]

searching for more flags

http://10.10.206.242/

```
<form method="get" action="/search">
  
        <input type="text" name="term" placeholder="Search...                                 THM{G!T_G00D}" />
  
        <button type="submit" class="fa fa-search fa"></button>
  
    </form>
```

```
THM{G!T_G00D}
```

http://10.10.206.242/archive/we-are-hiring/

```
<meta content="THM{L0L_WH0_US3S_M3T4}" property="og:description" />
```

```
THM{L0L_WH0_US3S_M3T4}
```

http://10.10.206.242/archive/a-cheers-to-our-it-department/

```
<meta content="THM{AN0TH3R_M3TA}" property="og:description" />
```

```
THM{AN0TH3R_M3TA}
```

the email address cannot be found on the website, however, Jane Doe's email address is JD@anthem.com, here initials. so trying Solomon Gundy, SG@anthem.com


http://10.10.206.242/umbraco

```
SG@anthem.com
UmbracoIsTheBest!
```

http://10.10.206.242/umbraco#/umbraco

![[umbraco-login.png]]
### Remote Desktop

just use the credentials for remote desktop...

```
rdesktop -u SG -p UmbracoIsTheBest! 10.10.206.242
```
# Privilege Escalation

### User

just use the credentials for remote desktop...

```
rdesktop -u SG -p UmbracoIsTheBest! 10.10.206.242
```

C:\Users\SG\user.txt
```
THM{N00T_NO0T}
```

### Root

copy and paste the contents of the winpeas bat file into winpeas.bat in the user documetns folder.

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

