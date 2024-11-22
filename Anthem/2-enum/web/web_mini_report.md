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

