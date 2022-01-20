---
title: Backdoor
date: 2022-01-04 21:46:28
tags: Hack the Box
categories: LFI
---

## 信息收集
发现目标主机开放了ssh和web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/91c55463b8894dfc8281797fa545de3c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们将`backdoor.htb`添加到hosts文件中后，访问web服务，发现是一个WordPress页面，并且版本是`5.8.1`
![在这里插入图片描述](https://img-blog.csdnimg.cn/fc20025359b542d092eda73dfd36dc39.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

既然是wordpress，那么我们可以直接使用wpscan来扫描存在哪些漏洞

```bash
wpscan --url http://backdoor.htb/ --api-token X4CFiaLdgwD6FwDMhkrZMpNjFDZ7Ex6DWqlcPM9DVic --enumerate p,u --plugins-detection aggressive
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/c7c8fb81233a4b49b06e3d757078c9dd.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现存在一个组件漏洞，路径是`http://backdoor.htb/wp-content/plugins/akismet/`，我们访问其上一级目录发现是ebook的插件
![在这里插入图片描述](https://img-blog.csdnimg.cn/59ce377ff44443e0ae407e8028b768a1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

我们在EDB上发现了这个组件存在目录穿越漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/c15aaa1c2f99402aa234d95d4ba7d7ff.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们访问其路径，并将wp-config.php文件下载保存下来，发现了mysql的用户名和密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/9276f5329d5444d1a4e7f701f2b2b3e5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
但是我们到后台进行登录时发现无论是`admin`和`wordpressuser`都是登陆失败的
![在这里插入图片描述](https://img-blog.csdnimg.cn/d7d52ae101994365b067e0463284ecec.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们只能切换另一个思路了，上面我们说到时存在一个LFI漏洞的。我们可以使用LFISuite进行路径的检测
![在这里插入图片描述](https://img-blog.csdnimg.cn/12af5d4372a042a783fd87b77f83506d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们虽然可以找到passwd文件，但是并没有任何的作用
![在这里插入图片描述](https://img-blog.csdnimg.cn/be7eb457f68b4b6799558545455b690c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们可以查看目标主机都在运行那些进程，通过传入`/proc/pid/cmdline`这个路径参数，其中pid的值我们可以进行模糊，并用burpsuite进行抓包分析。其中为什么要这么做，这是Linux 文件系统层次结构的文章解析链接[https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/proc.html](https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/proc.html)
![在这里插入图片描述](https://img-blog.csdnimg.cn/bffa7223627d4dfe8db4b137b4984909.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2a11eb47eaea430685df1782909d56fc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们发现进程号为793的进程，在本机的1337端口上运行这一个`gdbserver`这样一个程序
![在这里插入图片描述](https://img-blog.csdnimg.cn/f4483a61544247d282456891a4d1f1dc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 漏洞利用
### 第一种方法
我们在EDB中发现了gdbserver这个程序是存在漏洞的
![在这里插入图片描述](https://img-blog.csdnimg.cn/abd8f238cf054450a79a3a3d13e79783.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们将其内容保存为exp.py文件，然后按照提示先生成一个rev.bin文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/54d8c0fbe2bc4a9590f41b6770b2bee0.png)
然后开启监听，运行我们的exp并获取目标主机的shell
![在这里插入图片描述](https://img-blog.csdnimg.cn/1da19bb296474d1fa28f040adfacede6.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/6b571bba98c44cfe92c049f327069088.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
### 第二种方法
我们可以直接通过MSF程序获取目标主机的shell，并设置对应的参数项
![在这里插入图片描述](https://img-blog.csdnimg.cn/a0817ecc48414e04ba28a8126f1f05a8.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后提示这个payload运行错误，原因是主机并不是32位的，是64位的
![在这里插入图片描述](https://img-blog.csdnimg.cn/c9995cd3ea9b4b509c347aa0508635b0.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们把参数设置为64位再运行即可
![在这里插入图片描述](https://img-blog.csdnimg.cn/5ab52ced97f449338a1cd14d20707741.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/0950beedec5c4b9894654396d09fd96c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 提权
我们将`linpeas.sh`这个文件上传到目标主机上并运行它
![在这里插入图片描述](https://img-blog.csdnimg.cn/ace832b109ac4ca391a07343bc66a62b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现存在这么一个可疑的进程是可能存在漏洞利用的
![在这里插入图片描述](https://img-blog.csdnimg.cn/9219d9c4acde429db32f97840917256e.png)
我们使用pspy程序监听一下主机的进程
![在这里插入图片描述](https://img-blog.csdnimg.cn/a2824fa9dada431e948761bc432f95f6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现这个进程是每休眠一段时间就会再次运行，并且都是以root身份来运行的
![在这里插入图片描述](https://img-blog.csdnimg.cn/597c98a3121744a98ac64e76c51564aa.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们可以看到我们现在使用的终端是dumb
![在这里插入图片描述](https://img-blog.csdnimg.cn/9e65175ae79346ecb3631d670afba0e1.png)
我们要将其设置为xterm终端
![在这里插入图片描述](https://img-blog.csdnimg.cn/eab51c482a6c47ef9827e3de470b933f.png)
然后查看screen的帮助命令发现，-x参数可以帮我们直接进入另一个终端界面，因为screen程序是以root身份运行的，所以我们能直接进入root终端

```bash
screen -x root/root
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/c8e276d5bacf4eeba50d6692a9160185.png)
