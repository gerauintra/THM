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

seems to be umbraco cms