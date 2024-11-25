
opening the pcap files in wireshark

siemFTP pcap

![[ftppcap.png]]


```
220 (vsFTPd 3.0.3)

USER anonymous

331 Please specify the password.

PASS anonymous

230 Login successful.

SYST

215 UNIX Type: L8

FEAT

211-Features:

EPRT

EPSV

MDTM

PASV

REST STREAM

SIZE

TVFS

211 End

EPSV

229 Entering Extended Passive Mode (|||20349|)

LIST

150 Here comes the directory listing.

226 Directory send OK.

EPSV

229 Entering Extended Passive Mode (|||6658|)

NLST

150 Here comes the directory listing.

226 Directory send OK.

QUIT

221 Goodbye.
```


this is not helpful as the anonymous ftp login does not work


siemHTTP1 pcap seems to just be some external (out of scope) testing website, only get requests nothing interesting

http2

not interested in get requests, looking for login attempts on the site, so posts requests

```
http.request.method==POST
```

![[http2post.png]]

from that stream we get a snippet containing 

```
POST /index.html HTTP/1.1

Host: 192.168.111.136

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 42

Origin: http://192.168.111.136

Connection: keep-alive

Referer: http://192.168.111.136/index.html

Upgrade-Insecure-Requests: 1

  

uname=valleyDev&psw=ph0t0s1234&remember=onHTTP/1.1 200 OK
```

credentials

```
valleyDev
ph0t0s1234
```