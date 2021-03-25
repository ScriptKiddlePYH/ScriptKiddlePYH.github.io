---
title: proxychains代理扫描并获取内网服务器权限
tags: 红蓝对抗
categories: 内网渗透
top: 13
---
## Proxychains
Proxychains是为了GNU\Linux操作系统而开发的工具，任何TCP连接都可以通过TOR或者SOCKS4，SOCKS5，HTTP/HTTPS路由到目的地。在这个通道技术中可以使用多个代理服务器。除此之外提供匿名方式，诸如用于中转跳板的应用程序也可以用于对发现的新网络进行直接通信。

## 利用思路
还是这个拓扑图，我们穿越了层层障碍，终于拿到了`192.168.103.101`这台服务器的权限，接下来，我们以这台服务器为跳板机，去访问内网中的更多机器。而proxychains则是隐藏我们本机kali对目标服务器之间的流量，从而加大被溯源的成本。在真实的渗透中可能不止一台数据库机器，横向的时候可能会出现多台域主机。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325101439326.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
## 攻击过程
首先我们先拿下win7这台主机的权限，我们使用上次生成的木马进行连接shell
<!--more-->
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325102402822.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325102521265.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
然后我们先打印一下路由表信息，发现啥也没有
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325102734146.png)
运行脚本文件，自动将搜集到的网段加入到自动路由表中，这步很重要，将直接影响到后期proxychains执行的效果
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325102915321.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
接下来我们将使用大名鼎鼎的`socks4a`模块，在后台开启一个代理服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325103248514.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
<!--more-->
在上述工作全部顺利完成后，我们就要去配置我们的proxychains配置文件了，路径为`/etc/proxychains.conf`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325103548413.png)
保存退出后，我们将使用proxychains加nmap进行主机的漏洞扫描，这里因为我查过文章知道，windows server2003存在缓冲区溢出这个漏洞，因此我直接针对这个漏洞展开扫描，执行的扫描命令为`proxychains nmap -sT -sV -Pn -n -p22,135,139,445 --script=smb-vuln-ms08-067.nse 192.168.104.128`，最后的IP地址为横向后的主机IP

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325104557700.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325104629217.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
当我们判断出系统确实存在这个漏洞之后，我们就返回msf对这个漏洞进行进一步的利用，这里强调一点就是，我们不能再使用反弹shell的payload了，因为我们的主机能访问目标机，但是目标机不能访问我们的本机，所以这里要设置一个直连shell的payload
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325105533753.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
至此，我们又拿下了内网中的另一台机器(假如是数据库)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325110028851.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
## 验证
为了验证我们的流量还有真实IP是否得到真实的隐藏，我们中间再插入一台新的主机，里面使用wireshark对流量数据包进行监听，网段设置一定要和内网数据库主机(`104`网段)的主机一致。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325110645479.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
然后我们在win7的那个meterpreter上执行arp扫描，在上面一台主机上观察数据包的流量变化
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325111454791.png)
可以看到，都是win7和win2003主机之间的通信，我们真实的主机IP得到了很好的隐藏
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210325111539446.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)

