---
title: Atom
date: 2021-12-24 11:26:50
tags: Hack the Box
categories: SMB
---

## 靶机信息

![在这里插入图片描述](https://img-blog.csdnimg.cn/d7ff3a26ad1b4b0680f0d4283d757a77.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 信息收集

可以看到靶机开放了80端口，那证明就存在web服务。
![在这里插入图片描述](https://img-blog.csdnimg.cn/71d80ba7cc3748c4a4f0402a9793083a.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/458004df73e046d6ac29665f942ae2a1.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

往下看的时候，发现guest用户可以登录smb服务，那我们就先看看smb服务里边都有哪些有价值的信息。
![在这里插入图片描述](https://img-blog.csdnimg.cn/35ce3f11c2ea4febac8767c3761d9f0f.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
使用匿名登录看看可以访问到哪些信息，可以看到具有读写权限的目录只有`Software_Updates`这个目录
![在这里插入图片描述](https://img-blog.csdnimg.cn/901c2bdb6d4d4e7da7675e1c24ee1e36.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们登录进这个目录中，有一个pdf文件可以下载，我们下载查看了下里面的内容。
![在这里插入图片描述](https://img-blog.csdnimg.cn/2ecb65835531481289d535ee549568a4.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/1edacfc8f7844517bae4f0e7dbd97af0.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

查看完这些信息后，我们继续访问web服务。在服务的底端存在一个邮箱账号和域名，我们先添加到hosts文件中，便于后面进行目录爆破和子域名的搜集。
![在这里插入图片描述](https://img-blog.csdnimg.cn/35cf8a81609b4187930f03c62fcf602d.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那么我们就使用`gobuster`进行域名和目录的爆破吧
![在这里插入图片描述](https://img-blog.csdnimg.cn/916619d4e1dc4bfba3e44627be4f0f36.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/b59b2cb6beb94f13bd94e36d031e5dba.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现好像并没有什么有价值的信息，哎！还是老老实实去下载软件吧。。。
![在这里插入图片描述](https://img-blog.csdnimg.cn/cc46996341604dffb098519776c2cfc8.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现是个exe程序，那我们把它丢Windows上运行看看效果是怎么样的
![在这里插入图片描述](https://img-blog.csdnimg.cn/aea7a78db0594a95b20e01811fc600ae.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们在yml文件中发现了这是一个电子应用程序
![在这里插入图片描述](https://img-blog.csdnimg.cn/1447b123093e4cf79c5fbdf992c90238.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们根据搜索到的信息，上谷歌进行搜索，可以看到有一位大佬发现了这个漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/d4b8f3b4ba784683918c21291c351027.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/3576872644644aef95d67125deffcd4f.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
大佬已经给出了漏洞利用的方法，首先先使用包含单引号的文件名，然后重新计算文件哈希以匹配攻击者提供的二进制文件。
![在这里插入图片描述](https://img-blog.csdnimg.cn/2ce2ad37d7314f4781ca47e3372b791c.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 漏洞利用

首先我们先生成一个带有单引号的有效载荷
![在这里插入图片描述](https://img-blog.csdnimg.cn/841300482268465f928a7a1c6029c243.png)
然后我们按照上面的方法，生成一个 sha512 sum hash 并将其转换为十六进制，然后进一步转换为base64
![在这里插入图片描述](https://img-blog.csdnimg.cn/5222e5c555ae452499acff13d2f7999a.png)
然后我们新建latest.yml这个文件，将上面生成的值进行复制粘贴
![在这里插入图片描述](https://img-blog.csdnimg.cn/d5c11c4ee72b45f09ef3842b265aec6b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

紧接着我们使用python开启一个服务器
![在这里插入图片描述](https://img-blog.csdnimg.cn/6a8bfdbfe08e4dbaad426ef2204b19f0.png)
三个文件夹都要替换掉yml文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/51201bef231a46a9a2b2221c45ffeb40.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/99de167220ab45808c982e771e32f731.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们在msf上对漏洞进行利用，设置好基本参数后，我们可以看到反弹的shell
![在这里插入图片描述](https://img-blog.csdnimg.cn/8cd39b8f18d34046a6a3a1abd41d1bd4.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2ffa34dc528d4bffbf22bbff28573e83.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 权限提升

我们先查看一下当前用户的权限

![在这里插入图片描述](https://img-blog.csdnimg.cn/46fc63e01a074f8780b9977a64491034.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
进入cmd终端进行操作
![在这里插入图片描述](https://img-blog.csdnimg.cn/572df466d9dd4791a92d255ca60aa7a7.png)
进入`Program Files`这个目录查看主机都安装了哪些应用程序。可以看到安装了Redis数据库，是不是想试试未授权访问？这是直觉哈哈
![在这里插入图片描述](https://img-blog.csdnimg.cn/9a3ff33f781548e7be38f9fbb77d972b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们先进入这个目录，看看配置文件是否需要密码进行登录的。我们查找`redis.windows-service.conf`这个文件，使用命令`type redis.windows-service.conf | findstr requirepass`快速查找到登录数据库的密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/bb3958f354d14907842c4a54f90141be.png)
既然发现了密码，那我们直接尝试可不可以登录成功吧
![在这里插入图片描述](https://img-blog.csdnimg.cn/73ef19ef23b04f979996089529a2ec3b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们列出所有的hash看看，发现了一个比较有价值的信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/21d54e0c5d914c8ea4288315af18521b.png)
那我们查看一下user对应的信息，发现是一个管理员，并且还挖掘到了他对应的hash值`Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi`
![在这里插入图片描述](https://img-blog.csdnimg.cn/3bf1bf2cbfb6417c9058a3d05d874987.png)
既然涉及到用户信息，那我们就去Users目录下看看有没有什么有价值的信息吧。然而在jason的桌面上，我们看到了user.txt文件，拿到第一个flag值![t](https://img-blog.csdnimg.cn/806ca1c22ee14f7fa5bb5688113ff486.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
在jason的主机中，我们发现了他安装了两个应用程序，一个是`node_modules`和`PortableKanban`
![在这里插入图片描述](https://img-blog.csdnimg.cn/171f022c449c4fdda60d7e6c67bca7a6.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/1bc9495245b24508b8408bee3570a7e6.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们查看一下cfg配置文件，发现了对应的hash值`Odh7N3L9aVSeHQmgK/nj7RQL8MEYCUMb`
![在这里插入图片描述](https://img-blog.csdnimg.cn/96ad43ed232e4c928dfb0b255cf0b550.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们在exploit-db中搜索到对应的漏洞利用代码
![在这里插入图片描述](https://img-blog.csdnimg.cn/c205078ffcc14aff81bba88d60aa34ad.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们对这个利用脚本进行简洁，让它直接输出对应的明文值。得到明文值`kidvscat_yes_kidvscat`

```python
import json
import base64
from des import * #python3 -m pip install des

def decode(hash):
        hash = base64.b64decode(hash.encode('utf-8'))
        key = DesKey(b"7ly6UznJ")
        return key.decrypt(hash,initial=b"XuVUm5fR",padding=True).decode('utf-8')

print(decode('Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi'))
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/938feaacbc2d46888b987f570b3a166f.png)

登录成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/020f2b5f8b624d2b9420511bc70c6941.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

