http://10.10.207.39/

```
gobuster dir -u http://10.10.207.39:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /opt/THM/LianYu/2-enum/web/gob_dir_2.3_med.md
```


```
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/island               (Status: 301) [Size: 235] [--> http://10.10.207.39/island/]
/server-status        (Status: 403) [Size: 199]
```

http://10.10.207.39/island/

```
<p>You should find a way to <b> Lian_Yu</b> as we are planed. The Code Word is: </p><h2 style="color:white"> vigilante</style></h2>
```


```
gobuster dir -u http://10.10.207.39:80/island/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /opt/THM/LianYu/2-enum/web/gob_dir_2.3_med_island.md
```


```
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/2100                 (Status: 301) [Size: 240] [--> http://10.10.207.39/island/2100/]
```


http://10.10.207.39/island/2100/


```
<!-- you can avail your .ticket here but how?   -->
```


```
gobuster dir -u http://10.10.207.39:80/island/2100/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x ticket -o /opt/THM/LianYu/2-enum/web/gob_files_dir23_island_2100.md
```

```
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/green_arrow.ticket   (Status: 200) [Size: 71]
```

http://10.10.207.39/island/2100/green_arrow.ticket

```
This is just a token to get into Queen's Gambit(Ship)


RTy8yhBQdscX
```

bas58 decoding
```
!#th3h00d
```

ftp credentials
```
vigilante
!#th3h00d
```

ftp login successful

```
Connected to 10.10.207.39.
220 (vsFTPd 3.0.2)
Name (10.10.207.39:devel): vigilante
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||59874|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0          511720 May 01  2020 Leave_me_alone.png
-rw-r--r--    1 0        0          549924 May 05  2020 Queen's_Gambit.png
-rw-r--r--    1 0        0          191026 May 01  2020 aa.jpg
226 Directory send OK.
ftp> 
```


download all files on ftp server (need to escape the !)
```
wget -m --user="vigilante" --password="\!#th3h00d" ftp://10.10.207.39
```


```
FINISHED --2024-11-20 14:13:49--
Total wall clock time: 9.4s
Downloaded: 9 files, 1.2M in 4.8s (256 KB/s)

```


```
docker run --rm -it -v $(pwd):/steg rickdejager/stegseek aa.jpg ./rockyou.txt
```

```
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "password"
[i] Original filename: "ss.zip".
[i] Extracting to "aa.jpg.out".
```


```
file aa.jpg.out 
```

```
aa.jpg.out: Zip archive data, at least v2.0 to extract, compression method=deflate
```

```
unzip aa.jpg.out
```

```
Archive:  aa.jpg.out
  inflating: passwd.txt              
  inflating: shado 
```


passwd.txt

```
This is your visa to Land on Lian_Yu # Just for Fun ***


a small Note about it


Having spent years on the island, Oliver learned how to be resourceful and 
set booby traps all over the island in the common event he ran into dangerous
people. The island is also home to many animals, including pheasants,
wild pigs and wolves.
```

shado

```
M3tahuman
```

.other_user from the main ftp directory
```
Slade Wilson was 16 years old when he enlisted in the United States Army, having lied about his age. After serving a stint in Korea, he was later assigned to Camp Washington where he had been promoted to the rank of major. In the early 1960s, he met Captain Adeline Kane, who was tasked with training young soldiers in new fighting techniques in anticipation of brewing troubles taking place in Vietnam. Kane was amazed at how skilled Slade was and how quickly he adapted to modern conventions of warfare. She immediately fell in love with him and realized that he was without a doubt the most able-bodied combatant that she had ever encountered. She offered to privately train Slade in guerrilla warfare. In less than a year, Slade mastered every fighting form presented to him and was soon promoted to the rank of lieutenant colonel. Six months later, Adeline and he were married and she became pregnant with their first child. The war in Vietnam began to escalate and Slade was shipped overseas. In the war, his unit massacred a village, an event which sickened him. He was also rescued by SAS member Wintergreen, to whom he would later return the favor.

Chosen for a secret experiment, the Army imbued him with enhanced physical powers in an attempt to create metahuman super-soldiers for the U.S. military. Deathstroke became a mercenary soon after the experiment when he defied orders and rescued his friend Wintergreen, who had been sent on a suicide mission by a commanding officer with a grudge.[7] However, Slade kept this career secret from his family, even though his wife was an expert military combat instructor.

A criminal named the Jackal took his younger son Joseph Wilson hostage to force Slade to divulge the name of a client who had hired him as an assassin. Slade refused, claiming it was against his personal honor code. He attacked and killed the kidnappers at the rendezvous. Unfortunately, Joseph's throat was slashed by one of the criminals before Slade could prevent it, destroying Joseph's vocal cords and rendering him mute.

After taking Joseph to the hospital, Adeline was enraged at his endangerment of her son and tried to kill Slade by shooting him, but only managed to destroy his right eye. Afterwards, his confidence in his physical abilities was such that he made no secret of his impaired vision, marked by his mask which has a black, featureless half covering his lost right eye. Without his mask, Slade wears an eyepatch to cover his eye.
```

possible users
```
vigilante
joseph
adeline
wilson
slade
kane
jackal
```
