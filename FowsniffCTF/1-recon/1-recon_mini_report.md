banner grabbing
```
nc -nv 10.10.191.213 110


(UNKNOWN) [10.10.191.213] 110 (pop3) open
+OK Welcome to the Fowsniff Corporate Mail Server!
```


```
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -port 110 10.10.191.213 
```
