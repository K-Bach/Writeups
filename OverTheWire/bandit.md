# Bandit Writeups
https://overthewire.org/wargames/bandit/bandit0.html
## Bandit 0

> The goal of this level is for you to log into the game using SSH. The host to which you need to connect is `bandit.labs.overthewire.org`, on port 2220. The username is `bandit0` and the password is `bandit0`. Once logged in, go to the Level 1 page to find out how to beat Level 1.

Command to login: 
```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```
Use password `bandit0` to login.

## Bandit 1
> The password for the next level is stored in a file called `readme` located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.

Command to login: 

```bash
ssh bandit1@bandit.labs.overthewire.org -p 2220
```

To read the password, use:
```bash
cat readme
```
![password](pics/bandit/image.png)

Password: ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If

## Bandit 2
> The password for the next level is stored in a file called `-` located in the home directory.

I tried to use `cat -` but it didn't work. Instead, I used:
```bash
cat ./-
```

![password](pics/bandit/image-1.png)

Password: 263JGJPfgU6LtdEvgfWU1XP5yac29mFx

## Bandit 3

> The password for the next level is stored in a file called `spaces in this filename` located in the home directory.

To read the file with spaces in its name, you can use quotes or escape the spaces. Here, I used quotes:

```bash
cat "spaces in this filename"
```

![password](pics/bandit/image-2.png)

Password: MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx

## Bandit 4

> The password for the next level is stored in a hidden file in the `inhere` directory.

To find hidden files, you can use the `ls -a` command. The hidden file is usually prefixed with a dot (`.`).

```bash
cd inhere
ls -a
```

To read the hidden file, you can use:

```bash
cat .hidden
```

![alt text](pics/bandit/image-3.png)

Password: 2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ

## Bandit 5

> The password for the next level is stored in the only human-readable file in the `inhere` directory.

To find human-readable files, you can use the `file` command to check the file types in the directory:

```bash
cd inhere
file ./*
```

![files](pics/bandit/2025-06-24-12-09-08.png)

To read the human-readable file, you can use:

```bash
cat ./inhere/-file07
```

![password](pics/bandit/2025-06-24-12-20-46.png)

Password: 4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw

## Bandit 6

> The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:
> - human-readable
> - 1033 bytes in size
> - not executable

To find files that match these criteria, you can use the `find` command with specific options:

```bash
cd inhere
find . -type f -size 1033c ! -executable -readable
```
This command searches for files (`-type f`) that are exactly 1033 bytes in size (`-size 1033c`), not executable (`! -executable`), and human-readable.

![file](pics/bandit/2025-06-24-12-26-31.png)

To read the file, you can use:

```bash
cat ./maybehere07/.file2
```

![password](pics/bandit/2025-06-24-12-27-28.png)

Password: HWasnPhtq9AVKe0dmk45nxy20cvUa6EG

## Bandit 7

> The password for the next level is stored somewhere on the server and has all of the following properties:
> - owned by user bandit7
> - owned by group bandit6
> - 33 bytes in size

To find files that match these criteria, you can use the `find` command with specific options:

```bash
find / -user bandit7 -group bandit6 -size 33c 2>/dev/null
```

This command searches for files owned by user `bandit7`, group `bandit6`, and exactly 33 bytes in size (`-size 33c`). The `2>/dev/null` part is used to suppress error messages about permission denied for directories you cannot access.

![password](pics/bandit/2025-06-24-12-34-42.png)

Password: morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj

## Bandit 8

> The password for the next level is stored in the file data.txt next to the word millionth

To find the password, you can use the `grep` command to search for the word "millionth" in the `data.txt` file:

```bash
grep millionth data.txt
```

![password](pics/bandit/2025-06-24-12-43-34.png)

Password: dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc

## Bandit 9

> The password for the next level is stored in the file data.txt and is the only line of text that occurs only once

To find the password, you can use the `uniq` command in combination with `sort` to filter out lines that occur only once:

```bash
sort data.txt | uniq -u
```

![password](pics/bandit/2025-06-24-12-58-10.png)

Password: 4CKMh1JI91bUIZZPXDqGanal4xvAg0JM

## Bandit 10

> The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.

To find the password, you can use the `grep` command to search for human-readable strings preceded by `=` characters in the `data.txt` file:

```bash
strings data.txt | grep '='
```

![password](pics/bandit/2025-06-24-13-11-05.png)

Password: FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey

## Bandit 11

> The password for the next level is stored in the file data.txt, which contains base64 encoded data.

To find the password, you can use the `base64` command to decode the contents of the `data.txt` file:

```bash
base64 -d data.txt
```
![password](pics/bandit/2025-06-24-13-13-54.png)

Password: dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr

## Bandit 12

> The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions.

To find the password, you can use the `tr` command to rotate the letters:

```bash
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

![password](pics/bandit/2025-06-24-14-12-02.png)

Password: 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4

## Bandit 13

> The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work. Use mkdir with a hard to guess directory name. Or better, use the command “mktemp -d”. Then copy the datafile using cp, and rename it using mv (read the manpages!)

First, create a random directory in `/tmp`:

```bash
mktemp -d
cp data.txt /tmp/tmp.JpxkZDWV3M/data.txt
```

![](pics/bandit/2025-06-24-14-21-06.png)

This is the content of `data.txt`:

![data](pics/bandit/2025-06-24-14-43-04.png)

The hint tells us that it's a hexdump. We can convert it back to binary using `xxd`:

```bash
xxd -r data.txt > binary_data
```

The content is unreadable, so we have to figure out witch compression algorithm was used. To tell witch compression algorithm was used, we can check the first bytes of the file and see if we can find a match using a [list of signatures](https://en.wikipedia.org/wiki/List_of_file_signatures).

And we have a match with `gzip`:

![gzip signature](pics/bandit/2025-06-24-14-49-28.png)

so we can decompress it using `gzip`:

```bash
cp binary_data binary_data.gz
gzip -d binary_data.gz
```

The content is still unreadable, so we can try to decompress it again. This time the signature is `bzip2`:

![bzip2 signature](pics/bandit/2025-06-24-14-57-44.png)
    
```bash
cp binary_data binary_data.bz2
bzip2 -d binary_data.bz2
```

The content is still unreadable, so we can try to decompress it again. This time the signature is `gzip` again:

```bash
cp binary_data binary_data.gz
gzip -d binary_data.gz
```

Now the head of the file perfectly matches the structure defined by the POSIX tar header, so we can extract the content using `tar`:

```bash
cp binary_data binary_data.tar
tar -xf binary_data.tar
```

The output is an other tar file, so we can repeat the process:

```bash
cp data5.bin data5.tar
tar -xf data5.tar
```

The content is still unreadable, so we can try to decompress it again. This time the signature is `bzip2` again:

```bash
cp data6.bin data6.bz2
bzip2 -d data6.bz2
```

Now the head of the file perfectly matches the structure defined by the POSIX tar header again, so we can extract the content using `tar`:

```bash
cp data6 data6.tar
tar -xf data6.tar
```

The content is still unreadable, so we can try to decompress it again. This time the signature is `gzip` again:

```bash
cp data8.bin data8.gz
gzip -d data8.gz
```

Finally we have a readable file:

```bash
cat data8
```

![password](pics/bandit/2025-06-24-15-32-39.png)

Password: FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn

## Bandit 14

> The password for the next level is stored in `/etc/bandit_pass/bandit14` and can only be read by user bandit14. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level.

The ssh key is called `sshkey.private` and is located in the home directory. To login to the next level, you can use the following command:

```bash
ssh -i sshkey.private bandit14@localhost -p 2220
```

Now retrieve the password from `/etc/bandit_pass/bandit14`:

```bash
cat /etc/bandit_pass/bandit14
```

![password](pics/bandit/2025-06-24-16-58-14.png)

Password: MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS

## Bandit 15
> The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.

```bash
cat /etc/bandit_pass/bandit14 | nc localhost 30000
```

![password](pics/bandit/2025-06-27-11-42-45.png)

Password: 8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo

## Bandit 16

> The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL/TLS encryption.

To connect to a service using SSL/TLS, you can use the `openssl` command:

```bash
openssl s_client -connect localhost:30001
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
```

This command connects to the service on port 30001 and sends the password. The response will contain the password for the next level.

![password](pics/bandit/2025-06-27-12-08-13.png)

Password: kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

## Bandit 17

> The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL/TLS and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

To find out which ports are open and speak SSL/TLS in the range 31000 to 32000, you can use the `nmap` command (-sV option is used to detect service versions):

```bash
nmap -sV -p 31000-32000 localhost
```

![nmap results](pics/bandit/2025-06-27-12-26-03.png)

As we can see:
- ports 31046/tcp, 31518/tcp, 31691/tcp, 31790/tcp, and 31960/tcp are open. 
- ports 31518 and 31790 are SSL/TLS ports.
- port 31790 responds with "Please enter the current password"

Let's connect to port 31790 using `openssl` and send the current password:

```bash
openssl s_client -connect localhost:31790
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
```

![response](pics/bandit/2025-06-27-12-29-20.png)

We get a KEYUPDATE message back. This happens because when openssl is used interactively (which means neither -quiet nor -ign_eof have been given), then certain commands are also recognized which perform special operations. These commands are a letter which must appear at the start of a line. They are listed below.

- `k` - Send a key update message to the server (TLSv1.3 only)
- `K` - Send a key update message to the server and request one back (TLSv1.3 only)
- `Q` - End the current SSL connection and exit.
- `R` - Renegotiate the SSL session (TLSv1.2 and below only).

To get the password, we can use the `-quiet` option to suppress the interactive mode and just get the response:

```bash
openssl s_client -connect localhost:31790 -quiet
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
```

![response](pics/bandit/2025-06-27-12-44-55.png)

We get and RSA private key back. To use the key to login to the next level, we have to logout from bandit16, save the key to a file and use it with the `ssh` command:

```bash
exit
echo "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----" > bandit17_key
chmod 600 bandit17_key
ssh -i bandit17_key bandit17@bandit.labs.overthewire.org -p 2220
```

## Bandit 18

> There are 2 files in the homedirectory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new.  
NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19

To find the changed line between the two files, you can use the `diff` command:

```bash
diff passwords.old passwords.new
```

![password](pics/bandit/2025-06-27-12-54-31.png)

Password: x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO

## Bandit 19

> The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.

To bypass the `.bashrc` modification that logs you out, you can use the `ssh` command with the `-T` option, which disables pseudo-terminal allocation:

```bash
ssh -T bandit19@bandit.labs.overthewire.org -p 2220
```

![password](pics/bandit/2025-06-27-22-51-19.png)

Password: cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8

## Bandit 20

> To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

If we run the binary without arguments it says that it executes commands as user bandit20. So we just have to execute the command `cat /etc/bandit_pass/bandit20` to get the password for the next level:   

```bash
./bandit20-do cat /etc/bandit_pass/bandit20
```

![password](pics/bandit/2025-06-27-23-03-20.png)

Password: 0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO

## Bandit 21

> There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).  
NOTE: Try connecting to your own network daemon to see if it works as you think

First lets try to run the program without arguments to see how it works:

![output](pics/bandit/2025-06-27-23-13-19.png)

Ok so we can connect to a port on localhost and send the password for the previous level. Let's start a simple TCP server on port 30000 using `nc` (netcat):

```bash
nc -l -p 30003
```

Now we can run the setuid binary and connect to our server:

```bash
./suconnect 30003
```

Now we can send the password for the previous level:

![password](pics/bandit/2025-06-27-23-22-12.png)

![ok](pics/bandit/2025-06-27-23-22-50.png)

Password: EeoULMCra2q0dSkYj561DX7s1CpBuOBt

## Bandit 22

> A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.

Let's check the cronjob configuration in `/etc/cron.d/`:

![process](pics/bandit/2025-06-27-23-58-53.png)

```bash
cat /etc/cron.d/bandit22
```

The cronjob runs cronjob_bandit22.sh at every reboot and every minute. Let's check the script:

```bash
cat /usr/bin/cronjob_bandit22.sh
```

So every minute, the cron job copies the password for bandit22 into /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv. Let's check the file:

```bash
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

![password](pics/bandit/2025-06-28-00-01-53.png)

Password: tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q

## Bandit 23

> A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.  
NOTE: Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.

Let's check the cronjob configuration in `/etc/cron.d/`:

```bash
cat /etc/cron.d/cronjob_bandit23
```
The cronjob runs cronjob_bandit23.sh at every reboot and every minute. Let's check the script:

```bash
cat /usr/bin/cronjob_bandit23.sh
```

![script](pics/bandit/2025-06-28-00-16-28.png)

As we can see, the script stores a password in a file called as the output of echo ```echo I am user bandit23 $myname | md5sum | cut -d ' ' -f 1```, with $myname being the username of the user running the script. So we can just compute the md5 hash of our username and check the file:

```bash
echo I am user bandit23 | md5sum | cut -d ' ' -f 1
cat /tmp/8ca319486bfbbc3663ea0fbe81326349
```

and the password we get is: 0Zf11ioIjMVN551jX3CmStKLYqjk54Ga

## Bandit 24

> A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.    
NOTE: Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…

Let's check the cronjob configuration in `/etc/cron.d/`:

```bash
cat /etc/cron.d/cronjob_bandit24
cat /usr/bin/cronjob_bandit24.sh
```

![script](pics/bandit/2025-06-28-11-15-26.png)

The code does the following:
1. Enters the directory `/var/spool/$myname/foo`, where $myname is the username of the user running the script (bandit24).
2. Loops over all files and directories, including hidden files (because of .*).
3. Skips special entries:
   - . → current directory
   - .. → parent directory
4. If the owner of the file is bandit23, it executes the file with for maximum 60 seconds. If the file doesn’t exit within 60 seconds, it sends signal 9 (SIGKILL) to force kill it.
5. It deletes the file unconditionally, after running it or skipping it.

This means that we can create a file in the directory `/var/spool/bandit24/foo` and it will be executed by the script with the permissions of bandit24. We can use this to read the password for the next level, which is stored in `/etc/bandit_pass/bandit24`.

Let's create a script called `kbkScript` in the directory `/var/spool/bandit24/foo` with the following content:

```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/kbkScriptOutput.txt
```

Make sure to give it execute permissions:

```bash
chmod +x /var/spool/bandit24/foo/kbkScript
```

Now we wait for the cron job to run, and then we can check the output file:

```bash
cat /tmp/kbkScriptOutput.txt
```

![password](pics/bandit/2025-06-28-11-45-05.png)

Password: gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8

## Bandit 25

> A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing. You do not need to create new connections each time

First, let's check the service on port 30002:

```bash
nc -N localhost 30002
```

It asks the password for user bandit24 and the secret pincode on a single line, separated by a space.

To brute-force the 4-digit pincode, we can use a simple bash script that iterates over all possible combinations from 0000 to 9999. For each combination, it sends the password for bandit24 and the current combination to the service on port 30002. If the response does not contain the word "Wrong", it means we have found the correct combination.

If the server doesn't allow persistent connections, we have to connect to the service for each combination:

```bash
#!/bin/bash
for n in $(seq -f "%04g" 0 9999)
do
  password="gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 $n"
  echo -ne "Trying: $password\r"
  reply=$(echo "$password" | nc -N localhost 30002)
  if [[ "$reply" != *Wrong* ]]; then
    echo -e "\n$reply"
    break
  fi 
done
```

Or

```bash
#!/bin/bash
password_base="gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8"

for ((n=0; n<=9999; n++)); do
    printf -v pin "%04d" "$n"
    attempt="$password_base $pin"

    echo -ne "Trying: $attempt\r"
    reply=$(echo "$attempt" | nc -N localhost 30002)

    if [[ "$reply" != *Wrong* ]]; then
        echo -e "\nSuccess: $reply"
        break
    fi
done
```

If the server allows persistent connections:

```bash
#!/bin/bash

password_base="gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8"

# Prepare a list of all attempts
# We'll feed them into nc's stdin
for n in $(seq -f "%04g" 0 9999); do
    echo "$password_base $n"
done | nc localhost 30002 | while read -r reply; do
    if [[ "$reply" != *Wrong* ]]; then
        echo "$reply"
    fi
done
```

Or:

```bash
#!/bin/bash

password_base="gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8"

# Open a single connection to the server
# Use process substitution so we can read and write
exec 3<>/dev/tcp/localhost/30002

# Check connection opened
if [[ $? -ne 0 ]]; then
    echo "Failed to connect to server"
    exit 1
fi

for ((n=0; n<=9999; n++)); do
    printf -v pin "%04d" "$n"
    attempt="$password_base $pin"

    echo -ne "Trying: $attempt\r"

    # Send attempt into socket
    echo "$attempt" >&3

    # Read reply line from server
    IFS= read -r reply <&3

    if [[ "$reply" != *Wrong* && "$reply" != *"I am"* ]]; then
        echo -e "\nSuccess: $attempt"
        break
    fi1
done

# Close socket
exec 3<&-
exec 3>&-
```

Now run the script:

```bash
/path/to/your/script.sh
```

The script will try all combinations and print the current combination being tried. When it finds the correct combination, it will print the response from the service.

![Password](pics/bandit/2025-06-28-12-35-20.png)

Password: iCi86ttT4KSNe1armKiwbQNmB3YJP3q4

## Bandit 26

> Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.  
NOTE: if you’re a Windows user and typically use Powershell to ssh into bandit: Powershell is known to cause issues with the intended solution to this level. You should use command prompt instead.

If we check the files in the home directory of bandit25, we can see there is a key for ssh. We can probably use it to login to bandit26. So we exit bandit25, download the key using scp and then login to bandit26 using the key:

```bash
scp -P 2220 bandit25@bandit.labs.overthewire.org:/home/bandit25/bandit26.sshkey ./bandit26.sshkey
ssh -i bandit26.sshkey bandit26@bandit.labs.overthewire.org -p 2220
```

But as we connect, the session is closed immediately. This is probably because the shell for user bandit26 is not /bin/bash, but something else.

To find out what shell is used for user bandit26, we can check the `/etc/passwd` file:

```bash
cat /etc/passwd | grep bandit26
```

It seems like bandit26 uses `/usr/bin/showtext` as its shell. Let's check the file:

```bash
cat /usr/bin/showtext
```

![showtext](pics/bandit/2025-06-28-16-02-36.png)

The code executes the comand more on text.txt. So why does the session close immediately? What if the file content is too short to be displayed with more? In this case minimizing the terminal window would force more to page the content. Let's try it:

![it worked](pics/bandit/2025-06-28-16-13-09.png)

It worked! Now we need to find a way to exploit this.  
Looking on google for "more" subcommands we find that we can use the `v` command to open the file in the default editor, which is usually `vi`. Now that we are in `vi` we can open a file using the `:e` command followed by the file path.

```bash
:e /etc/bandit_pass/bandit26
```

This will open the file with the password for bandit26. We can then read the password and exit `vi` using `:q`.

Password: s0773xxkk0MXfdqOfPRVr9L3jJBUOgCZ

If we want a shell, we can use the `:shell` command to spawn a shell. But this will not work because the shell is not `/bin/bash`, but `/usr/bin/showtext`. So we can use the `:set` command in vi to change the shell:

```bash
:set shell=/bin/bash
```

Now we can spawn a shell using the `:shell` command, and get the password.

## Bandit 27

> Good job getting a shell! Now hurry and grab the password for bandit27!

In the home directory of bandit26, there is a file called `bandit27-do`. This file is a setuid binary that allows us to execute commands as user bandit27. We can use this binary to read the password for bandit27 from `/etc/bandit_pass/bandit27`.

To do this, we can run the following command:

```bash
./bandit27-do cat /etc/bandit_pass/bandit27
```

And we get the password: upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB

## Bandit 28

> There is a git repository at `ssh://bandit27-git@localhost/home/bandit27-git/repo` via the port 2220. The password for the user bandit27-git is the same as for the user bandit27.  
Clone the repository and find the password for the next level.

To clone the git repository, we can use the `git clone` command with the provided URL and port. In my case, I will clone it into a directory called `pippo`:

```bash
git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo pippo
```

When prompted for the password, we enter the password for bandit27: upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB

After cloning the repository, we can check the files in the cloned directory. There is a README file that contains the password for the next level.

![password](pics/bandit/2025-06-28-23-06-31.png)

Password: Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN

## Bandit 29

> There is a git repository at ssh://bandit28-git@localhost/home/bandit28-git/repo via the port 2220. The password for the user bandit28-git is the same as for the user bandit28.  
Clone the repository and find the password for the next level.

To clone the git repository, we can use the `git clone` command with the provided URL and port. In my case, I will clone it into a directory called `pippo1`:

```bash
git clone ssh://bandit28-git@localhost:2220/home/bandit28-git/repo pippo1
```

When prompted for the password, we enter the password for bandit28: Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN

This time the README.md file contains the credentials for the next level, the password is not specified though.

![hidden password](pics/bandit/2025-06-28-23-10-09.png)

To find the password, we can use the `git log` command to check the commit history and see if there are any commits that contain the password:

![commits](pics/bandit/2025-06-28-23-11-07.png)

There is a commit, with id 674690a00a0056ab96048f7317b9ec20c057c06b, that says "fix info leak". This commit likely contains the password for the next level.

To check the commit, we can use the `git show` command:

```bash
git show 674690a00a0056ab96048f7317b9ec20c057c06b
```

![password](pics/bandit/2025-06-28-23-12-25.png)

And we found the password: 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7

## Bandit 30

> There is a git repository at ssh://bandit29-git@localhost/home/bandit29-git/repo via the port 2220. The password for the user bandit29-git is the same as for the user bandit29.  
Clone the repository and find the password for the next level.

To clone the git repository, we can use the `git clone` command with the provided URL and port. In my case, I will clone it into a directory called `pippo2`:

```bash
git clone ssh://bandit29-git@localhost:2220/home/bandit29-git/repo pippo2
```

When prompted for the password, we enter the password for bandit29: 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7

This time the README.md file contains the credentials for the next level, the password is not specified though. It says "<no passwords in production!>". This propably means that the password is stored in another branch. Maybe master or development. Let's check the branches:

```bash
git branch -a
```

![branches](pics/bandit/2025-06-28-23-16-51.png)

There is a branch called `dev`. Let's switch to that branch:

```bash
git checkout dev
```

Now we can check the README.md file in the branch. The password is there:

![password](pics/bandit/2025-06-28-23-18-13.png)

Password: qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL

## Bandit 31

> There is a git repository at ssh://bandit30-git@localhost/home/bandit30-git/repo via the port 2220. The password for the user bandit30-git is the same as for the user bandit30.  
Clone the repository and find the password for the next level.

To clone the git repository, we can use the `git clone` command with the provided URL and port. In my case, I will clone it into a directory called `pippo3`:

```bash
git clone ssh://bandit30-git@localhost:2220/home/bandit30-git/repo pippo3
```

When prompted for the password, we enter the password for bandit30: qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL

This time the README.md doesn't seem to give any usefull information.

![no info](pics/bandit/2025-06-28-23-37-47.png)

The commit history has only the initial commit and we have only one branch. Even the .git folder seems to not contain any useful info...unless the packed-refs file that mentions a "secret" tag. Let's list the tags:

```bash
git tag
```

![tags](pics/bandit/2025-06-28-23-55-36.png)

Let's check the tag "secret":

```bash
git show secret
```

We get the password for the next level: fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy

## Bandit 32

> There is a git repository at ssh://bandit31-git@localhost/home/bandit31-git/repo via the port 2220. The password for the user bandit31-git is the same as for the user bandit31.  
Clone the repository and find the password for the next level.

To clone the git repository, we can use the `git clone` command with the provided URL and port. In my case, I will clone it into a directory called `pippo4`:

```bash
git clone ssh://bandit31-git@localhost:2220/home/bandit31-git/repo pippo4
```

When prompted for the password, we enter the password for bandit31: fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy

The README.md file says that we need to push a file called key.txt containing the string "May I come in?" to master:

![readme file](pics/bandit/2025-06-28-23-59-23.png)

While listing the files in the repo i noticed a gitignore file. The file ignores .txt files, so we need to remove it from the .gitignore file to be able to add our key.txt file. 

Now let's create the file `key.txt` with the content "May I come in?":

```bash
echo "May I come in?" > key.txt
```

Now we can add the file to the repository, commit it and push it to the master branch:

```bash
git add key.txt
git commit -m "Add key.txt"
git push origin master
```

After pushing the file, we are asked for the bandit31 password. We enter the password for bandit31: fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy.

Now we get the password: 3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K

![password](pics/bandit/2025-06-29-00-04-49.png)

## Bandit 33

> After all this git stuff, it’s time for another escape. Good luck!

It seems like everything we write gets uppercased:

![uppercased](pics/bandit/2025-06-29-00-06-58.png)

There is probably a script that uppercases everything we type and just executes it. So what if we pass a variable containing the bash name? $0 for example:

![got the shell](pics/bandit/2025-06-29-00-23-15.png)

Now that we have the shell we can read the password for the next level from `/etc/bandit_pass/bandit33`:

```bash
cat /etc/bandit_pass/bandit33
```

Password: tQdtbs5D5i2vJwkO8mEyYEyTL8izoeJ0

## Bandit 34

![last level](pics/bandit/2025-06-29-00-27-28.png)