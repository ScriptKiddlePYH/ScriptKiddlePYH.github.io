---
title: Redis未授权访问漏洞
tags: 漏洞检测与防御
categories: python安全攻防
top: true
---

## 攻击思路
Redis是一种使用ANSIC语言编写的开源Key-Value型数据库。Redis为了保证效率，将数据缓存在内存中，周期性地把更新的数据写入磁盘或者把修改操作写入追加的记录文件中，在此基础上实现了master-slave(主从)同步。

对Redis配置不当将会导致未授权访问漏洞，从而被攻击者恶意利用。如果Redis以root身份运行，攻击者可以用root权限写入SSH公钥文件，通过SSH登录目标服务器，进而导致服务器权限被获取、泄露或发生加密勒索事件，为正常服务带来严重危害。
<!--more-->
## 漏洞利用
**漏洞利用的方式有很多，这里我们介绍其中的一种——`利用公私钥认证获取ROOT权限`**
首先我们先在靶机上以root身份启动redis服务，命令为`redis-server /etc/redis.conf`，安装redis请读者上网查阅资料，这里只讲述攻击方法
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210214204941377.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)<!--more-->
然后我们在kali上生成一个ssh空密钥
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021021420510262.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
进入/root/.ssh目录下查看生成结果，并将公钥导入到txt文件中
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210214205318550.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
将txt文件中的公钥导入Redis缓存中
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210214205411588.png)
连接目标主机，更改配置文件路径为/root/.ssh，设定文件名称为authorized-keys
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021021420553631.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
通过SSH协议连接到远程目标主机
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210214205628977.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
## 检测方法

先编写程序的起始部分

```python
#程序起始部分
if __name__ == '__main__':
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print("interrupted by user, killing all threads...")
```
然后编写命令行参数处理功能，`opts`为一个两元组列表，如果没有附加参数则为空串

```python
#编写命令行参数处理功能
def start(argv):
    dict = {}
    url = ""
    type = ""
    if len(sys.argv) < 2:
        print("-h 帮助信息; \n")
        sys.exit()
    #定义异常处理
    try:
        banner()
        opts,args = getopt.getopt(argv, "-u:-p:-s:-h")
    except getopt.GetoptError:
        print('Error an argument!')
        sys.exit()
    for opt,arg in opts:
        if opt == "-u":
            url = arg
        elif opt == "-s":
            type = arg
        elif opt == "-p":
            port = arg
        elif opt == "-h":
            print(usage())
    launcher(url,type,port)
```
编写帮助信息

```python
#banner信息
def banner():
    print('\033[1;34m########################################################################################\033[0m\n'
          '\033[1;34m######################################\033[1;32mRedis未授权访问漏洞\033[1;34m####################################\033[0m\n'
          '\033[1;34m########################################################################################\033[0m\n')
```
接下来是Redis漏洞检测的核心代码，此处通过`socket函数`尝试连接远程主机的IP及端口号，发送payload字符串。利用`recvdata函数`接收目标主机返回的数据

```python
#未授权函数检测
def redis_unauthored(url,port):
    result = []
    s = socket.socket()
    payload = "\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a"
    socket.setdefaulttimeout(10)
    for ip in url:
        try:
            s.connect((ip, int(port)))
            s.sendall(payload.encode())
            recvdata = s.recv(1024).decode()
            if recvdata and 'redis_version' in recvdata:
                result.append(str(ip)+':'+str(port)+':'+'\033[1;32;34msuccess\033[0m')
        except:
            pass
            result.append(str(ip) + ':' + str(port) + ':' + '\033[1:31;34mfailed \033[0m')
        s.close()
    return(result)
```
然后针对该IP段进行网络主机检测。该部分代码主要以特殊字符"-"为目标进行分隔，将分隔后的字符进行for循环存入列表中，以便被`函数redis_unauthored`调用

```python
#执行URL
def url_exec(url):
    i = 0
    zi = []
    group = []
    group1 = []
    group2 = []
    li = url.split(".")
    if(url.find('-')==-1):
        group.append(url)
        zi = group
    else:
        for s in li:
            a = s.find('-')
            if a != -1:
                i = i+1
        zi = url_list(li)
        if i > 1:
            for li in zi:
                zz = url_list(li.split("."))
                for ki in zz:
                    group.append(ki)
            zi = group
            i = i-1
        if i > 1:
            for li in zi:
                zzz = url_list(li.split("."))
                for ki in zzz:
                    group1.append(ki)
            zi = group1
            i = i-1
        if i > 1:
            for li in zi:
                zzzz = url_list(li.split("."))
                for ki in zzzz:
                    group2.append(ki)
            zi = group2
    return zi

def url_list(li):
    ss = []
    i = 0
    j = 0
    zi = []
    for s in li:
        a = s.find('-')
        i = i + 1
        if a != -1:
            ss = s.rsplit("-")
            j = i
            break
    for s in range(int(ss[0]), int(ss[1]) + 1):
        li[j - 1] = str(s)
        aa = ".".join(li)
        zi.append(aa)
    return zi
```
最后是添加一些帮助信息和结果格式

```python
#使用规则
def usage():
    print('-h: --help 帮助;')
    print('-p: --port 端口;')
    print('-u: --url 域名;')
    print('-s: --type Redis')
    
#输出结果格式设计
def output_exec(output,type):
    print("\033[1;32;40m"+type+"......\033[0m")
    print("++++++++++++++++++++++++++++++++++++++++++++++++")
    print("|         ip         |    port   |     status  |")
    for li in output:
        print("+-----------------+-----------+--------------+")
        print("|   "+li.replace(":","   |    ")+"  | ")
    print("+----------------+------------+---------------+\n")
    print("[*] shutting down....")
```
最后设置一个漏洞回调函数

```python
#漏洞回调函数
def launcher(url,type,port):
    #未授权访问类型
    if type == "Redis":
        output=redis_unauthored(url_exec(url),port)
        output_exec(output,type)
```
附上完整代码以免疏漏

```python
import sys
import getopt
import socket

#编写命令行参数处理功能
def start(argv):
    dict = {}
    url = ""
    type = ""
    if len(sys.argv) < 2:
        print("-h 帮助信息; \n")
        sys.exit()
    #定义异常处理
    try:
        banner()
        opts,args = getopt.getopt(argv, "-u:-p:-s:-h")
    except getopt.GetoptError:
        print('Error an argument!')
        sys.exit()
    for opt,arg in opts:
        if opt == "-u":
            url = arg
        elif opt == "-s":
            type = arg
        elif opt == "-p":
            port = arg
        elif opt == "-h":
            print(usage())
    launcher(url,type,port)

#banner信息
def banner():
    print('\033[1;34m########################################################################################\033[0m\n'
          '\033[1;34m######################################\033[1;32mRedis未授权访问漏洞\033[1;34m####################################\033[0m\n'
          '\033[1;34m########################################################################################\033[0m\n')

#使用规则
def usage():
    print('-h: --help 帮助;')
    print('-p: --port 端口;')
    print('-u: --url 域名;')
    print('-s: --type Redis')

#未授权函数检测
def redis_unauthored(url,port):
    result = []
    s = socket.socket()
    payload = "\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a"
    socket.setdefaulttimeout(10)
    for ip in url:
        try:
            s.connect((ip, int(port)))
            s.sendall(payload.encode())
            recvdata = s.recv(1024).decode()
            if recvdata and 'redis_version' in recvdata:
                result.append(str(ip)+':'+str(port)+':'+'\033[1;32;34msuccess\033[0m')
        except:
            pass
            result.append(str(ip) + ':' + str(port) + ':' + '\033[1:31;34mfailed \033[0m')
        s.close()
    return(result)

#执行URL
def url_exec(url):
    i = 0
    zi = []
    group = []
    group1 = []
    group2 = []
    li = url.split(".")
    if(url.find('-')==-1):
        group.append(url)
        zi = group
    else:
        for s in li:
            a = s.find('-')
            if a != -1:
                i = i+1
        zi = url_list(li)
        if i > 1:
            for li in zi:
                zz = url_list(li.split("."))
                for ki in zz:
                    group.append(ki)
            zi = group
            i = i-1
        if i > 1:
            for li in zi:
                zzz = url_list(li.split("."))
                for ki in zzz:
                    group1.append(ki)
            zi = group1
            i = i-1
        if i > 1:
            for li in zi:
                zzzz = url_list(li.split("."))
                for ki in zzzz:
                    group2.append(ki)
            zi = group2
    return zi

def url_list(li):
    ss = []
    i = 0
    j = 0
    zi = []
    for s in li:
        a = s.find('-')
        i = i + 1
        if a != -1:
            ss = s.rsplit("-")
            j = i
            break
    for s in range(int(ss[0]), int(ss[1]) + 1):
        li[j - 1] = str(s)
        aa = ".".join(li)
        zi.append(aa)
    return zi

#输出结果格式设计
def output_exec(output,type):
    print("\033[1;32;40m"+type+"......\033[0m")
    print("++++++++++++++++++++++++++++++++++++++++++++++++")
    print("|         ip         |    port   |     status  |")
    for li in output:
        print("+-----------------+-----------+--------------+")
        print("|   "+li.replace(":","   |    ")+"  | ")
    print("+----------------+------------+---------------+\n")
    print("[*] shutting down....")

#漏洞回调函数
def launcher(url,type,port):
    #未授权访问类型
    if type == "Redis":
        output=redis_unauthored(url_exec(url),port)
        output_exec(output,type)


#程序起始部分
if __name__ == '__main__':
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print("interrupted by user, killing all threads...")
```
实现效果如下图所示
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210214220350642.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTAwNzA3Mw==,size_16,color_FFFFFF,t_70)
## 防御策略
- **禁止远程使用高危命令**
- **低权限运行Redis服务**
- **禁止外网访问Redis**
- **阻止其他用户添加新的公钥，将authorized_keys的权限设置为对拥有者只读**
