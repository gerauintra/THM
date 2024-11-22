
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