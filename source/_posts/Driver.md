---
title: Driver
date: 2022-01-01 16:42:50
tags: Hack The box
categories: Windows Print Spooler
---

## 信息收集
发现目标主机开放了web服务和SMB服务

```
┌──(root💀kali)-[~/Desktop]
└─# bash nmap.sh 10.10.11.106                                                                                                                 1 ⚙
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-01 02:43 EST
Nmap scan report for 10.10.11.106
Host is up (0.25s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-01-01T14:43:35
|_  start_date: 2022-01-01T14:37:37
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.61 seconds
```
我们访问web服务时，提示我们要输入账号和密码，我们使用admin/admin登录成功

<!--more-->

![在这里插入图片描述](https://img-blog.csdnimg.cn/c4d2b8fafacf4a7e83de610beea75a59.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
登录页面时发现是台打印机，我们点击`Fireware Updates`页面，发现类似文件上传的页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/2e214c05a4a54abcba4a54c4b911d11f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 漏洞利用
<!--more-->

我尝试了很久的文件上产webshell都没有成功，切换思路，既然目标主机开放了445端口和共享SMB服务，那么我们可以利用SCF文件攻击(虽然这种攻击方式很不常见)。我们首先先手动创建一个scf文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/5d503addbbcf4fd683f0a1c02274294e.png)
然后启动responder程序进行监听
![在这里插入图片描述](https://img-blog.csdnimg.cn/c906af81139e4e569a4ca96169bb3d3f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们上传我们写的shell.scf文件，上传成功后会出现一个tony用户的哈希值，加密的方式是`NTLMv2`
![在这里插入图片描述](https://img-blog.csdnimg.cn/4b75787e99934dc8986ba6a5d124e686.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们使用hashcat对这个哈希值进行破解，破解得到的密码是`liltony`
![在这里插入图片描述](https://img-blog.csdnimg.cn/b4ae03ebc9e441cb81c41063bde7d8f7.png)
我们使用这个账号密码进行登录，得到了普通用户的权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/ac151987bd374eeb9178da89785bfe70.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们查看到存在`spoolsv`这个进程，这是一个`Windows Print Spooler`服务，存在一个CVE漏洞编号，对应的CVE编号是`CVE-2021-1675`
![在这里插入图片描述](https://img-blog.csdnimg.cn/235805f980cf43c68a8fc68310f5bcf3.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们在目标主机上远程加载我们的powershell脚本，并且使用脚本创建一个匿属管理员组的用户
![在这里插入图片描述](https://img-blog.csdnimg.cn/1b8333a9b0734baabe95425606940b95.png)
添加成功后，我们可以使用这个账户密码进行登录了，权限是管理员权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/a778b21f88954011b0a534250f909205.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
