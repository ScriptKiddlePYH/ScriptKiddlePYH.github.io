---
title: Powershell收集域内信息
tags: 红队对抗
categories: 内网渗透
top: 1
---

## 前言
Powershell作为微软官方推出的脚本语言，在Windows操作系统中的强大功能总所周知：系统管理员可以利用它提高Windows管理工作的自动化程度；渗透测试人员可以利用它更好地进行系统安全测试。因为powershell命令比较安全，减少了触发IDS或IPS的风险，因此大多数的作用是用于绕过策略。

> **Powershell的常用执行权限共有四种**

|参数|描述 |
|--|--|
| Restricted |默认设置，不允许执行任何脚本  |
|Allsigned|只能运行经过证书验证的脚本|
|Unrestricted|权限最高，可以执行任意脚本|
|RemoteSigned|对本地脚本不进行限制；对来自网络的脚本必须验证其签名|
<!--more-->
## 各脚本命令展示
这里我们将策略设置为Unrestricted，能运行所有的脚本权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306133134774.png)
然后我们进入PowerSploit的Recon文件夹将PowerView.ps1这个脚本导入进去(只有导入这个脚本才能执行以下命令)，这个是PowerSploit的下载地址

[https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306133704948.png)

> **Get-NetDomain：获取当前用户所在域的名称**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306133824783.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-NetUser：获取所有用户的详细信息**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306134143467.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-NetDomainController：获取所有域控制器的信息**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306134253861.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-NetComputer：获取域内所有机器的详细信息**

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021030613443370.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-NetOU：获取域中的OU信息**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306134535643.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021030613454718.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-NetGroup：获取所有域内组和组成员的信息**

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021030613464591.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-NetShare：获取当前域内所有的网络共享信息**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306134857127.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-NetSession：获取指定服务器的对话**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306135028467.png)

> **Get-NetRDPSession：获取指定服务器的远程连接**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306135144213.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-NetProcess：获取远程主机的进程**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306135251953.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-UserEvent：获取指定用户的日志**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306135349272.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-ADObject：获取活动目录的对象**

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021030613552975.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-NetGPO：获取域内所有的组策略对象**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306135710375.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Get-DomainPolicy：获取域默认策略或域控制器策略**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306135819950.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

> **Invoke-UserHunter：获取域用户登录的计算机信息及该用户是否有本地管理员权限**

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306140014762.png)

> **Invoke-ProcessHunter：通过查询域内所有的机器进程找到特定用户**

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021030614015675.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
## Powershell脚本绕过策略实例
首先我们先将策略更改为Restricted，默认不能执行任何脚本
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306140851647.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
执行绕过后，命令成功执行，`powershell -exec bypass "import-module" 脚本路径；执行的命令`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210306140929449.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

