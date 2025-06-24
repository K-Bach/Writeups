# Bandit Writeup

# Bandit 0

> The goal of this level is for you to log into the game using SSH. The host to which you need to connect is `bandit.labs.overthewire.org`, on port 2220. The username is `bandit0` and the password is `bandit0`. Once logged in, go to the Level 1 page to find out how to beat Level 1.

Command to login: 
```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```
Use password `bandit0` to login.

# Bandit 1
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

# Bandit 2
> The password for the next level is stored in a file called `-` located in the home directory.

I tried to use `cat -` but it didn't work. Instead, I used:
```bash
cat ./-
```

![password](pics/image-1.png)

Password: 263JGJPfgU6LtdEvgfWU1XP5yac29mFx

# Bandit 3

> The password for the next level is stored in a file called `spaces in this filename` located in the home directory.

To read the file with spaces in its name, you can use quotes or escape the spaces. Here, I used quotes:

```bash
cat "spaces in this filename"
```

![password](pics/image-2.png)

Password: MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx

# Bandit 4

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

