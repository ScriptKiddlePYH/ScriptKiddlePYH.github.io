---
title: RouterSpace
date: 2022-03-20 13:09:54
tags: Hack The box
categories: App渗透
---

## 信息收集
我们发现目标主机开放了ssh和web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/5048fe7b19bb4f599fb152f151933e22.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
但是我们访问web页面时，并没有发现存在新的突破口，也没有发现存在域名。可是我们发现了一个apk文件可下载，初步猜测这是一个有关app的测试了
![在这里插入图片描述](https://img-blog.csdnimg.cn/6ed55fe40b034cc78f3bc0c8ce19c716.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

因为我这边已经尝试过使用linux安装anbox，感觉不太成功，所以我这边直接使用了夜神模拟器配合burpsuite进行抓包分析，这个是参考文章[https://www.cnblogs.com/wjrblogs/p/13683812.html](https://www.cnblogs.com/wjrblogs/p/13683812.html)
![在这里插入图片描述](https://img-blog.csdnimg.cn/d165e27c0e2b4d74b2377be88ae16afd.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

我们在那里发现了一个域名`routerspace.htb`，我们使用管理员权限将其写进到hosts文件中(这里建议使用cmd命令行打开后，再使用notepad程序对其进行修改)
![在这里插入图片描述](https://img-blog.csdnimg.cn/bd2d89a09f124018beb3c009659fa3c2.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

我们尝试放一个包看看，返回的信息正常
![在这里插入图片描述](https://img-blog.csdnimg.cn/fb97d042c99a4c2cbd5d137662724125.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
这种路由器式的，直觉告诉我可能存在RCE漏洞，我们尝试构造payload看看返回的结果。发现直接返回用户名称，那证明RCE漏洞是存在的。
![在这里插入图片描述](https://img-blog.csdnimg.cn/70f7be924704490baff42b1df46f08ec.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 漏洞利用
既然我们可以执行命令，那么我们可以尝试构造POC进行漏洞利用。首先我们先尝试是否可以写入文件，发现并没有数据包返回，那证明这个不行
![在这里插入图片描述](https://img-blog.csdnimg.cn/529e423d54c14aca97c5a2da26972a9c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们再试试能不能执行`/bin/bash`的命令，发现好像也不行
![在这里插入图片描述](https://img-blog.csdnimg.cn/40a5269c9148407dbd145fb7f943cdda.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们试试`ls`命令，发现可以成功执行命令，并且返回内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/45313dfdafa64ca5938a5aaf5ebe37f1.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们尝试`.ssh`目录是否可以写入文件，答案是可以的
![在这里插入图片描述](https://img-blog.csdnimg.cn/2262039e5fa24afe9d495f629d560c91.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那我们就有一个思路了，就是我们可以自己生成一个ssh的key，然后写入到这个目录上，那么我们就可以登录到这台主机上了。首先我们在kali上生成一个id_rsa.pub文件，然后发送到.ssh目录上，并赋予700权限

```bash
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDA4G+qgL/420+qY3ylhOQOGU9/0AqjC1aodWwl+Gb3KoQGzkqMTsZ6ju64LkT2nguCeMB1NIQrUPoifSlPC/HjKD277s076eGSfuBkjTWy2EL3V6I71kXkblmeyHNFo7Vbpmbkk+NTC3Yn2gwi8uGAX10GsEzliu+dG8ldKXMNzrz9Vk2KUKJPIEuMVHlG6lMCY5s6zO1CXG5MZLoFO2S2j5MOUAhV6h1ziC6zGBwXbs1m+hJvVzPfRUFTxmbsGtQAqueWMsBBHOhss4FgNNJe4pgeNQfdkwNlrq65V7g/gyQODG/mhsd81HimqyZY90vSipxysEV/aNd39RaBSSm3o4mOuoIRsZnU1DlBOdPMLOQaw6ERc2mwQFAyZTMa6vVDi/seoltYHUDaojfuTdIkqSN65a2IZAOhm9QpXXBqBHkWRrx/B3htrQA/Pxfy4Gnvpy3wqli/BvlrzI/a9m3FaZNGilSo36lB2hOeS+dzUcilkXJqkCvOJa5r94M4+RM= root@kali
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/ff6804d51e9d4c69ad60f5bbba670bf6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/35e772f089064ac29dc72e9e7d9dac5e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
可以在kali上登录成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/7197de9bfd0642eea38a56b856055a36.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权到ROOT
首先我们先上传个linpeas.sh文件，看看有什么提权的点。我们从这里看到了sudo的版本是旧版的，而且提示说可能存在漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/a36a9401dcbc4010bb23df3661956258.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/f5c95d3627f04de3aef68e72d5a6bb85.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/21b844b3a03248268e09ed0b2359072d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们在github上找到了对应的提权漏洞，编号为`CVE-2021-3156`。因为不能wget，所以我把里面的内容都一一复制了出来，这是github的地址[https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit](https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit)
![在这里插入图片描述](https://img-blog.csdnimg.cn/b59453abc5bc417aa4ac9b04aaa6f3b4.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
