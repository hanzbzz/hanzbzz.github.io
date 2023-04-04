# HTB: BroScience
BroScience is a medium difficulty Linux machine. Let's start off with nmap scan as per usual.
## Recon
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
SSH is open, the webserver on port 80 redirects to https://broscience.htb, which is confirmed by open port 443. There is a strange port 31337 open. When connecting to it via nc i notice a `SSH-2.0-Go` banner:
```bash
❯ nc 10.10.11.195 31337
SSH-2.0-Go
```
I assume this a SSH server written in Go, but i didn't find any details about this so let's leave it alone for now. Let's add the domain information to `/etc/hosts` and check out the website.
## Website
The website seems to be focused on providing information about various exercies.
<img src=../screenshots/htb-broscience/web.png>
There is a login page, and when i try to login with the admin:password credentials, i get a wrong credentials error message:
<img src= ../screenshots/htb-broscience/incorrect_creds.png height=300px width=600px>

However, when trying admin:admin credentials, i get a different error message, saying the account is not activated:
<img src =../screenshots/htb-broscience/not_activated.png height=300px width=600px>

Perhaps this means that admin:admin are the correct credentials, but admin hasn't activated their account yet.

There is not much else to do on the website, so i move on to enumerating URLs with gobuster, using the `raft-small-words` wordlist from seclists and adding php extension:
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
 - `/includes` directory has directory listing enabled and bunch of php files in it
 - `/user.php` gives details about user such as username and email when provided with an id parameter
 - `/activate.php` seems to provde the account activation functionality, i need a valid activation code

Since we have no way to guess the activation code, let's focus on the `includes` directory.
<img src =../screenshots/htb-broscience/includes.png height=300px width=500px>

Most of these files only display a blank page, as they are PHP and get executed when i try to view them. The only exception being the `img.php` file, that complains about missing parameter.
```
Error: Missing 'path' parameter.
```
If i leave the path parameter empty, i get an empty 200 response, and when i give it an image name from the `images` directory, it displays the image. This seems like potentionally a Local File Inclustion(LFI) vulnerability. Trying out a basic LFI payload returns an error:
```
❯ curl 'https://broscience.htb/includes/img.php?path=../../../../etc/passwd' -k
<b>Error:</b> Attack detected.
```