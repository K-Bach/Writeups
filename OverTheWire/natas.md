# Natas

https://overthewire.org/wargames/natas/

## Natas 0

> Username: natas0  
Password: natas0  
URL:      http://natas0.natas.labs.overthewire.org

In this level we just need to log in using the given credentials.

## Natas 1

> The page says: "You can find the password for the next level on this page."

By checking the source code of the page, we find a comment with the password for the next level:

![password](pics/natas/2025-06-29-13-40-53.png)

Password: 0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq

## Natas 2

> The page says: "You can find the password for the next level on this page, but rightclicking has been blocked!"

even if the right-click is blocked, we can still view the source code of the page by opening the browser's developer tools with F12. The password is in a comment:

![password](pics/natas/2025-06-29-13-43-35.png)

Password: TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI

## Natas 3

> The page says: "There is nothing on this page".

These time there are no comments in the source code, but we can see an img element:

![img element](pics/natas/2025-06-29-13-46-23.png)

Let's check if we have access to the files/:

![files](pics/natas/2025-06-29-13-49-21.png)

We can see that there is a file called "files/users.txt" which contains the password for the next level:

Password: 3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH

## Natas 4

> The page says "There is nothing on this page" and in the source code there is a comment that says "No more information leaks!! Not even Google will find it this time...".

The hint is is the word "Google". Trying opening the page with chrome doesn't help. So let's try with one of the first things to try in web CTFs: robots.txt. Let's got to the URL http://natas3.natas.labs.overthewire.org/robots.txt:

![robots.txt](pics/natas/2025-06-29-14-02-25.png)

In the s3cr3t folder there is a file called "users.txt" which contains the password for the next level: QryZXc2e0zahULdHrtHxzyYkj59kUxLQ

## Natas 5

> The page says: "Access disallowed. You are visiting from "" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/"

The hint suggests to send the request for the page with the "Referer" header set to "http://natas5.natas.labs.overthewire.org/". We can do this in the developer tools of the browser:

![edit request](pics/natas/2025-06-29-14-08-59.png)

![password](pics/natas/2025-06-29-14-20-46.png)

Password: 0n35PkggAPm2zbEpOU802c0x0Msn1ToK 

## Natas 6

> The page says: "Access disallowed. You are not logged in"

Since we are not log in let's check the cookies of the page:

![cookies](pics/natas/2025-06-30-19-00-36.png)

There is a cookie called "loggedin" with the value "0". Let's try to change it to "1" and refresh the page (spoiler: it works):

![success](pics/natas/2025-06-30-19-02-10.png)

Password: 0RoJwHdSKWFTYR5WuiAewauSuNaBXned

## Natas 7

> The page shows a form with a text input (Input secret) and a submit button. We can also check the source code.

The code behind the form is:

```php
<?
include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
        } else {
            print "Wrong secret";
        }
    }
?>
```

The secret is stored in the "includes/secret.inc" file, which we can access by going to the URL http://natas6.natas.labs.overthewire.org/includes/secret.inc:

![password in secret.inc](pics/natas/2025-06-30-19-06-00.png)

secret: FOEIUWGHFEEUHOFUOIU

We submit this secret in the form and we get the password for the next level:

![password](pics/natas/2025-06-30-19-06-58.png)

Password: bmg8SvU1LizuWjx3y7xkNERkHxGre0GS

## Natas 8

> The page shows a `Home` and an `About` buttons.

First we check the body for hints. We find a comment that says `password for webuser natas8 is in /etc/natas_webpass/natas8`.
If we click the buttons, we are taken to a new page that says `This is the X page`. Nothing crazy here.  
Let's check the url of the page: `http://natas7.natas.labs.overthewire.org/index.php?page=home`. We can see that the page is loaded with a `page` parameter, so let's try to change it to `huh` and see what happens:

![error](pics/natas/2025-06-30-19-19-53.png)

Since the code looks for a file called `huh` in the `/var/www/natas/natas7` directory. Path traversal?  
The hint in the comment says that the password is in `/etc/natas_webpass/natas8`, so let's try to access it with a path traversal attack by putting the following in the `page` parameter:  
`../../../../etc/natas_webpass/natas8`:

![password](pics/natas/2025-06-30-19-28-13.png)

Password: xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q 

## Natas 9

> The page shows a form identical to the one in natas7, but with different source code.

The code behind the form is:

```php
<?
$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```

The secret is encoded with a function that first encodes the secret in base64, then reverses the string and finally encodes it in hex.
To get the secret we can use the following code:

```python
import base64

encoded = "3d3d516343746d4d6d6c315669563362"
# Hex decode
bytesFromHex = bytes.fromhex(encoded)
# Reverse string
reversedBytes = bytesFromHex[::-1]
# Base64 decode
secret = base64.b64decode(reversedBytes).decode()
print(secret)
```

And we get the secret: oubWYf2kBq

We submit this secret in the form and we get the password for the next level: ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t

![password](pics/natas/2025-06-30-19-42-07.png)

## Natas 10

> The page shows this form:
![form](pics/natas/2025-06-30-19-52-14.png)

Let's check the source code:

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```

The code uses puts our input ($key) into the `grep` command without any sanitization. This allows command injection attacks, which in this case means execute arbitrary commands on the server.  
To exploit this vulnerability, we just have to put a command between two `;` and send it as input in the form. This works because if the semicolon is not escaped, it will be interpreted as a command separator by the shell.
For example, we can try `; ls -la;`:

![output](pics/natas/2025-06-30-20-00-10.png)

Now let's think, where is the password for the next level?
Natas 8 said that the password for the next level is in `/etc/natas_webpass/natas8`, so let's try to look for `/etc/natas_webpass/natas10` using `;cat /etc/natas_webpass/natas10;`:

![password](pics/natas/2025-06-30-20-12-58.png)

Password: t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu

## Natas 11

> The page shows this form:
![form](pics/natas/2025-06-30-20-16-00.png)

The code behind the form is:

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```

The code uses `preg_match` to check if the input contains any of the characters `;`, `|` or `&`. If it does, it prints an error message.
This means that we can't use these characters to inject commands.  
One way to go around this is to pass an empty string to the `grep` command, to make it return all the lines in the output files. Then we can add the file we want to look in by just adding a space and the file name.  
For example, we can try `"" /etc/natas_webpass/natas11` as input:

![password](pics/natas/2025-06-30-21-00-30.png)

Password: UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk