---
title: Active
date: 2021-12-24 11:20:45
tags: Hack the Box
categories: 内网
---

## 靶机信息

![在这里插入图片描述](https://img-blog.csdnimg.cn/eda8a039099d4943bbdadeca0b30a10a.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 信息收集

可以看到主机开放了135,445,88这些常见的端口
![在这里插入图片描述](https://img-blog.csdnimg.cn/5cf14b42521c4a969e73a389b2407517.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

可以匿名登录smb服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/e3d0be21298842868f97f94a04e6481e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

我们看到存在一个`Replication`的目录，我们尝试登录进这个目录看看。发现存在`active.htb`目录，并且该目录下有几个有价值的目录信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/5539c4e4a9ad4b5da24575f1cae90b36.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我经过细心查看后，只有在`\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\`目录下找到一个`Groups.xml`文件，经过查看这是一个组策略文件，用于帐户管理的组策略存储在域控制器上的“Groups.xml”文件中，该文件隐藏在 SYSVOL 文件夹中。
![在这里插入图片描述](https://img-blog.csdnimg.cn/3dfeaf7a43274b6db80c1986b56c764c.png?x-oss-process=image/watermark,typeZHJvaWRzYW5zZmFsbGJhY2s,shadow50,textQ1NETiBA5bmz5Yeh55qE5a2m6ICF,size20,colorFFFFFF,t70,gse,x16)
因为这个文件使用了特殊的算法进行加密的，所以我们可以使用`gpp-decrypt.py`这个脚本进行解密，解密出来的结果如下图所示
![在这里插入图片描述](https://img-blog.csdnimg.cn/3b1d134c71474bf78e60b56c7094f613.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

有了账户和密码后，我们登录SMB服务可以查看更多的共享
![在这里插入图片描述](https://img-blog.csdnimg.cn/a0cabca528234f819d7f3fac04fd95c5.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

我们使用账户密码访问Users共享
![在这里插入图片描述](https://img-blog.csdnimg.cn/3d172d64bc1c426399eefb0f548f5fff.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
在桌面上找到第一个答案值
![在这里插入图片描述](https://img-blog.csdnimg.cn/9465fa15bea246989886ef686a471ddc.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 提权

我们使用`rpcclient`枚举用户名和用户组
![在这里插入图片描述](https://img-blog.csdnimg.cn/fe3c3ce5801a4fca8ff2eae28e6cc801.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们使用`GetUserSPNs.py`脚本获取与普通用户帐户关联的服务主体名称。

```bash
GetUserSPNs.py -dc-ip 10.10.10.100 active.htb/SVC_TGS -request
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/18a215bbad5044eea14f81afb92ed4a6.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们获取到哈希值后，使用john来破解得到明文密码。
![在这里插入图片描述](https://img-blog.csdnimg.cn/fefaa6cda3e74dbf93337c78a2fededc.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
现在我们有了管理员的凭据后，可以先看看管理员可以访问哪些共享。可以看到，我们可以访问C盘的共享
![在这里插入图片描述](https://img-blog.csdnimg.cn/ddc1a806b114476996349f7104571698.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们使用账号密码登录进入C盘目录
![在这里插入图片描述](https://img-blog.csdnimg.cn/44b03ce98746402491959058ebfaa443.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
并在桌面上查找到root.txt文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/cdd2ab04ba094a5b9ec52a984a7b800f.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

