
```bash
cd 5-misc-tools/nuclei/

export tpls=("cnvd" "credential-stuffing" "cves" "default-logins" "exposed-panels" "exposures" "fuzzing" "honeypot" "iot" "miscellaneous" "misconfiguration" "osint" "takeovers" "technologies" "token-spray" "vulnerabilities")

for tpl in ${tpls[@]}; do touch /opt/THM/Gallery/5-misc-tools/nuclei/${tpl}_80.md; docker run projectdiscovery/nuclei -v -t $tpl -u http://10.10.82.219:80 -o ${tpl}_80_ip.md; done
```

```bash
cd 5-misc-tools/nuclei/

export tpls=("cnvd" "credential-stuffing" "cves" "default-logins" "exposed-panels" "exposures" "fuzzing" "honeypot" "iot" "miscellaneous" "misconfiguration" "osint" "takeovers" "technologies" "token-spray" "vulnerabilities")

for tpl in ${tpls[@]}; do touch /opt/THM/Gallery/5-misc-tools/nuclei/${tpl}_8080.md; docker run projectdiscovery/nuclei -v -t $tpl -u http://10.10.82.219:8080 -o ${tpl}_8080_ip.md; done
```

searchsploit simple image gallery   
--------------------------------------------- ---------------------------------
 Exploit Title                               |  Path
--------------------------------------------- ---------------------------------
Joomla Plugin Simple Image Gallery Extended  | php/webapps/49064.txt
Joomla! Component Kubik-Rubik Simple Image G | php/webapps/44104.txt
Simple Image Gallery 1.0 - Remote Code Execu | php/webapps/50214.py
Simple Image Gallery System 1.0 - 'id' SQL I | php/webapps/50198.txt
--------------------------------------------- ---------------------------------
Shellcodes: No Results
