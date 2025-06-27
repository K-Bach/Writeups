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
![password](pics/image.png)

Password: ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If

## Bandit 2
> The password for the next level is stored in a file called `-` located in the home directory.

I tried to use `cat -` but it didn't work. Instead, I used:
```bash
cat ./-
```

![password](pics/image-1.png)

Password: 263JGJPfgU6LtdEvgfWU1XP5yac29mFx

## Bandit 3

> The password for the next level is stored in a file called `spaces in this filename` located in the home directory.

To read the file with spaces in its name, you can use quotes or escape the spaces. Here, I used quotes:

```bash
cat "spaces in this filename"
```

![password](pics/image-2.png)

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

![alt text](pics/image-3.png)

Password: 2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ

## Bandit 5

> The password for the next level is stored in the only human-readable file in the `inhere` directory.

To find human-readable files, you can use the `file` command to check the file types in the directory:

```bash
cd inhere
file ./*
```

![files](pics/2025-06-24-12-09-08.png)

To read the human-readable file, you can use:

```bash
cat ./inhere/-file07
```

![password](pics/2025-06-24-12-20-46.png)

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

![file](pics/2025-06-24-12-26-31.png)

To read the file, you can use:

```bash
cat ./maybehere07/.file2
```

![password](pics/2025-06-24-12-27-28.png)

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

![password](pics/2025-06-24-12-34-42.png)

Password: morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj

## Bandit 8

> The password for the next level is stored in the file data.txt next to the word millionth

To find the password, you can use the `grep` command to search for the word "millionth" in the `data.txt` file:

```bash
grep millionth data.txt
```

![password](pics/2025-06-24-12-43-34.png)

Password: dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc

## Bandit 9

> The password for the next level is stored in the file data.txt and is the only line of text that occurs only once

To find the password, you can use the `uniq` command in combination with `sort` to filter out lines that occur only once:

```bash
sort data.txt | uniq -u
```

![password](pics/2025-06-24-12-58-10.png)

Password: 4CKMh1JI91bUIZZPXDqGanal4xvAg0JM

## Bandit 10

> The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.

To find the password, you can use the `grep` command to search for human-readable strings preceded by `=` characters in the `data.txt` file:

```bash
strings data.txt | grep '='
```

![password](pics/2025-06-24-13-11-05.png)

Password: FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey

## Bandit 11

> The password for the next level is stored in the file data.txt, which contains base64 encoded data.

To find the password, you can use the `base64` command to decode the contents of the `data.txt` file:

```bash
base64 -d data.txt
```
![password](pics/2025-06-24-13-13-54.png)

Password: dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr

## Bandit 12

> The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions.

To find the password, you can use the `tr` command to rotate the letters:

```bash
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

![password](pics/2025-06-24-14-12-02.png)

Password: 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4

## Bandit 13

> The password for the next level is stored in the file data.txt, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work. Use mkdir with a hard to guess directory name. Or better, use the command “mktemp -d”. Then copy the datafile using cp, and rename it using mv (read the manpages!)

First, create a random directory in `/tmp`:

```bash
mktemp -d
cp data.txt /tmp/tmp.JpxkZDWV3M/data.txt
```

![](pics/2025-06-24-14-21-06.png)

This is the content of `data.txt`:

![data](pics/2025-06-24-14-43-04.png)

The hint tells us that it's a hexdump. We can convert it back to binary using `xxd`:

```bash
xxd -r data.txt > binary_data
```

The content is unreadable, so we have to figure out witch compression algorithm was used. To tell witch compression algorithm was used, we can check the first bytes of the file and see if we can find a match using a [list of signatures](https://en.wikipedia.org/wiki/List_of_file_signatures).

And we have a match with `gzip`:

![gzip signature](pics/2025-06-24-14-49-28.png)

so we can decompress it using `gzip`:

```bash
cp binary_data binary_data.gz
gzip -d binary_data.gz
```

The content is still unreadable, so we can try to decompress it again. This time the signature is `bzip2`:

![bzip2 signature](pics/2025-06-24-14-57-44.png)
    
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

![password](pics/2025-06-24-15-32-39.png)

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

![password](pics/2025-06-24-16-58-14.png)

Password: MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS

## Bandit 15
> The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.

```bash
cat /etc/bandit_pass/bandit14 | nc localhost 30000
```

![password](pics/2025-06-27-11-42-45.png)

Password: 8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo

## Bandit 16

> The password for the next level can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL/TLS encryption.

To connect to a service using SSL/TLS, you can use the `openssl` command:

```bash
openssl s_client -connect localhost:30001
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
```

This command connects to the service on port 30001 and sends the password. The response will contain the password for the next level.

![password](pics/2025-06-27-12-08-13.png)

Password: kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

## Bandit 17

> The credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL/TLS and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

To find out which ports are open and speak SSL/TLS in the range 31000 to 32000, you can use the `nmap` command (-sV option is used to detect service versions):

```bash
nmap -sV -p 31000-32000 localhost
```

![nmap results](pics/2025-06-27-12-26-03.png)

As we can see:
- ports 31046/tcp, 31518/tcp, 31691/tcp, 31790/tcp, and 31960/tcp are open. 
- ports 31518 and 31790 are SSL/TLS ports.
- port 31790 responds with "Please enter the current password"

Let's connect to port 31790 using `openssl` and send the current password:

```bash
openssl s_client -connect localhost:31790
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
```

![response](pics/2025-06-27-12-29-20.png)

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

![response](pics/2025-06-27-12-44-55.png)

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

![password](pics/2025-06-27-12-54-31.png)

Password: x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
